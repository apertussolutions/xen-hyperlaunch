/*
 * lcm-tool : Launch Control Module tool
 *
 * Tool to generate a Launch Control Module for Xen.
 *
 * Copyright (c) 2020, Star Lab Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <yajl/yajl_tree.h>

#include "launch_control_module.h"

#define MAX_INPUT_FILE_SIZE (1024 * 64) /* in bytes */

#define DEBUG

#ifdef DEBUG
#define debug(format, args...) printf("DEBUG: " format, ## args )
#else
#define debug(format, ... ) ((void)0)
#endif

void show_help(const char *cmdname)
{
    printf("%s <in: launch definition file> <out: launch control module>\n",
           cmdname);
}

int read_file_size(const char *filename, unsigned int max_bytes,
              unsigned int *out_size)
{
    struct stat statbuf;

    if ( stat(filename, &statbuf) )
    {
        fprintf(stderr, "Failed to check file size of: %s\n", filename);
        return 1;
    }

    if ( statbuf.st_size > max_bytes )
    {
        fprintf(stderr, "File: %s exceeds maximum size: %u\n",
                filename, max_bytes);
        return 1;
    }

    *out_size = statbuf.st_size;

    return 0;
}

int read_and_parse_input_file(const char *filename,
                              unsigned char *file_buffer,
                              unsigned int buffer_size,
                              yajl_val *out_node)
{
#define ERR_BUFFER_SIZE 1024
    char errbuf[ERR_BUFFER_SIZE];
    size_t bytes_read;
    yajl_val node;
    FILE *file_stream;

	errbuf[0] = 0; /* Init with the empty string */
	errbuf[sizeof(errbuf) - 1] = 0; /* Enforce null-termination */

    debug("Reading and parsing: %s\n", filename);

    file_stream = fopen(filename, "r");
    if ( !file_stream )
    {
        fprintf(stderr, "Failed to open: %s\n", filename);
        return 1;
    }

    /*
     * Read the entire config file.
	 * Note: reserving the last character of the buffer for the 0 terminator.
     */
    bytes_read = fread(file_buffer, 1, buffer_size - 1, file_stream);

    if ( (bytes_read == 0) || (feof(stdin)) )
	{
        fprintf(stderr, "Read length error (read %zu bytes)\n", bytes_read);
        return 1;
    }
	else if ( bytes_read > (buffer_size - 1) )
	{
        /* This should never happen */
        fprintf(stderr, "Read exceeded buffer size - aborting\n");
        return 1;
    }

    if ( fclose(file_stream) )
    {
        fprintf(stderr, "Error closing the input file stream: %d\n",
                errno);
        return 1;
    }

    debug("Entering parser\n");

    /* Reserving the last character of errbuf for the null terminator */
    node = yajl_tree_parse((const char *) file_buffer, errbuf,
                           sizeof(errbuf) - 1);
    debug("Parsing done\n");
    if ( !node  )
    {
        fprintf(stderr, "parse_error: %s\n", (strlen(errbuf) ? errbuf : ""));
        return 1;
    }

    /* Success */
    *out_node = node;

	return 0;
}

/* Used to calculate the buffer space needed to add a module to the output */
int module_strlen(uint16_t type, unsigned int subtype_data,
                  unsigned int *out_len)
{
    switch (type)
    {
        case LCM_MODULE_IGNORE:
        case LCM_MODULE_LAUNCH_CONTROL_MODULE:
            /* This tool doesn't generate these */
            return -1;

        case LCM_MODULE_DOMAIN_BASIC_CONFIG:
        {
            *out_len = sizeof(struct lcm_module) +
                       sizeof(struct lcm_domain_basic_config);
            break;
        }

        case LCM_MODULE_DOMAIN_HIGH_PRIV_CONFIG:
        {
            *out_len = sizeof(struct lcm_module) +
                       sizeof(struct lcm_domain_high_priv_config);
            break;
        }

        case LCM_MODULE_DOMAIN_EXTENDED_CONFIG:
        {
            *out_len = sizeof(struct lcm_module) +
                       sizeof(struct lcm_domain_extended_config) +
                       subtype_data; /* config string */
            break;
        }

        case LCM_MODULE_DOMAIN_RAMDISK:
        case LCM_MODULE_CPU_MICROCODE:
        case LCM_MODULE_XSM_FLASK_POLICY:
            /* TODO: implement these */
            return -2;

        default:
            return -1;
    }

    return 0;
}

int generate_launch_control_module(yajl_val config_node, FILE *file_stream)
{
/******* TODO: START WORK IN PROGRESS SECTION ************/
    struct lcm_header_info *header_info;
    struct lcm_module *module;
    unsigned int out_size;
    unsigned int written;
    unsigned int mod_idx;
    unsigned int buf_len;
    unsigned char *out_buffer;

    const char *modules_path[] = {"modules", NULL};
    yajl_val modules_v;

    debug("generate_launch_control_module\n");

    buf_len = 4096; /* FIXME */

    out_buffer = malloc(buf_len);
    if ( !out_buffer )
        return -ENOMEM;

    memset(out_buffer, 0, buf_len);
    debug("buffer cleared\n");

    header_info = (struct lcm_header_info *)out_buffer;
    header_info->magic_number = LCM_HEADER_MAGIC_NUMBER;
    out_size = sizeof(struct lcm_header_info);

    modules_v = yajl_tree_get(config_node, modules_path,
                                       yajl_t_array);

    if ( !modules_v || !YAJL_IS_ARRAY(modules_v) )
        return -EINVAL;

    debug("got modules\n");

    for ( mod_idx = 0; mod_idx < YAJL_GET_ARRAY(modules_v)->len; mod_idx++)
    {
        module = &header_info->modules[mod_idx];

        module->type = LCM_MODULE_DOMAIN_BASIC_CONFIG;
        module->len = sizeof(struct lcm_module) +
                      sizeof(struct lcm_domain_basic_config);

        yajl_val is_priv = yajl_tree_get(
                        YAJL_GET_ARRAY(modules_v)->values[mod_idx],
                        (const char *[]){ "permissions", "privileged", NULL },
                        yajl_t_any);
        if ( is_priv )
        {
            if ( YAJL_IS_TRUE(is_priv) )
            {
                debug("is priv: true\n");
                module->basic_config.permissions |=
                    LCM_DOMAIN_PERMISSION_PRIVILEGED;
            }
            else
                debug("is priv: false\n");
        }
        else
            debug("is priv: not set\n");

        out_size += module->len; // TODO: overflow protection
        break;
    }


/******* TODO: END WORK IN PROGRESS SECTION ************/
    written = fwrite(out_buffer, 1, out_size, file_stream);
    if ( written < out_size )
    {
        fprintf(stderr, "Error writing out the launch control module\n");
        return 1;
    }
    debug("Wrote: %u bytes\n", written);

    free(out_buffer);

    return 0;
}

int generate_output(yajl_val config_node, const char *filename)
{
    FILE *file_stream;
    struct stat statbuf;
    int ret = 0;

    /* Safety catch: don't overwrite files */
    if ( !stat(filename, &statbuf) )
    {
        fprintf(stderr, "Error: file %s exists\n", filename);
        return 1;
    }

    file_stream = fopen(filename, "w");
    if ( !file_stream )
    {
        fprintf(stderr, "Error: could not open file %s for writing\n",
                filename);
        return 1;
    }
    /* Errors after this point need to clean up the output file */

    ret = generate_launch_control_module(config_node, file_stream);

    debug("Result of gen lcm: %d\n", ret);

    if ( fclose(file_stream) )
    {
        fprintf(stderr, "Error closing the output file stream: %d\n",
                errno);
        if ( !ret )
            ret = 1;
    }

    if ( ret && unlink(filename) )
        fprintf(stderr, "Error %d removing the incomplete output file: %s\n",
                errno, filename);

    return ret;
}

int main(int argc, char **argv)
{
    const char *input_filename, *output_filename;
    unsigned char *file_buffer;
    unsigned int file_size, buffer_size;
    yajl_val config_node;

    if ( argc != 3 )
    {
        show_help(argv[0]);
        return 1;
    }
    input_filename = argv[1];
    output_filename = argv[2];

    if ( read_file_size(input_filename, MAX_INPUT_FILE_SIZE, &file_size) )
        return 2;

    buffer_size = file_size + 1; /* Add one for a null terminator */

    file_buffer = malloc(buffer_size);
    if ( !file_buffer )
    {
        fprintf(stderr, "Couldn't allocate memory to read entire file: %s\n",
                input_filename);
        return 2;
    }
    memset(file_buffer, 0, buffer_size);

    if ( read_and_parse_input_file(input_filename, file_buffer, buffer_size,
                                   &config_node) )
    {
        fprintf(stderr, "Couldn't parse file: %s\n", input_filename);
        return 2;
    }

    debug("Generating output\n");

    if ( generate_output(config_node, output_filename) )
    {
        fprintf(stderr, "Couldn't generate launch control module output\n");
        return 3;
    }

    yajl_tree_free(config_node);
    free(file_buffer);

    return 0;
}
