/*
 * lcm-tool : Launch Control Module tool
 *
 * Tool to generate a Launch Control Module for Xen.
 *
 * Copyright (c) 2020, Star Lab Corporation
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <yajl/yajl_tree.h>

#include "launch_control_module.h"

/* FIXME: include these from source */
#define SECINITSID_DOM0     1
#define SECINITSID_DOMU    10
#define SECINITSID_DOMDM   11
#define SECINITSID_DOMBOOT 12

#define MAX_INPUT_FILE_SIZE (1024 * 64) /* in bytes */
#define MAX_NUMBER_OF_LCM_MODULES 32

#define error(format, args...) fprintf(stderr, "Error: " format, ## args )

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

    if ( (bytes_read == 0) || (feof(file_stream)) )
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

int get_config_bool(yajl_val j_mod, const char *key[], uint32_t val,
                    uint32_t *var)
{
    int i;

    yajl_val j_val = yajl_tree_get(j_mod, key, yajl_t_any);
    if ( !j_val )
    {
        error("missing:");
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "\n");

        return -1;
    }

    if ( YAJL_IS_TRUE(j_val) )
        *var |= val;

    return 0;
}

int get_config_string(yajl_val j_mod, const char *key[],
                      unsigned int max_len, unsigned int *out_len,
                      uint8_t *out_string)
{
    int i;
    unsigned int len;
    const char *in_string;

    yajl_val j_val = yajl_tree_get(j_mod, key, yajl_t_string);
    if ( !j_val )
    {
        error("missing:");
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "\n");

        return -1;
    }

    in_string = YAJL_GET_STRING(j_val);
    len = strnlen(in_string, max_len + 1);
    if ( len > max_len )
    {
        error("domain string:");
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "exceeds maximum length (%d)\n", max_len);
        return -1;
    }
    debug("in: config string: %s\n", in_string);

    strncpy((char *)out_string, in_string, len);
    *out_len = len;

    return 0;
}

/* Perform string translation for domain sid values */
int get_config_domain_sid(yajl_val j_mod, const char *key[],
                          uint32_t *out_sid)
{
    int i;
    char sidbuf[8];
    unsigned int cfg_len;
    const char **labels = (const char *[]){ "dom0", "domDM", "domU", "domBoot",
                                            NULL };
    unsigned int *sid_vals = (unsigned int []){ SECINITSID_DOM0,
                                                SECINITSID_DOMDM,
                                                SECINITSID_DOMU,
                                                SECINITSID_DOMBOOT };

    for ( i = 0; labels[i] != NULL; i++ )
        assert(sizeof(sidbuf) >= strlen(labels[i]));

    memset(sidbuf, 0, sizeof(sidbuf));

    if ( get_config_string(j_mod, key, sizeof(sidbuf)-1, &cfg_len,
                           (uint8_t *)sidbuf) )
        return -1;

    for ( i = 0; labels[i] != NULL; i++ )
    {
        if ( !strncmp(labels[i], sidbuf, sizeof(sidbuf)) )
        {
            *out_sid = sid_vals[i];
            return 0;
        }
    }

    error("domain sid value unrecognized: %s\nacceptable values:\n", sidbuf);
    for ( i = 0; labels[i] != NULL; i++ )
        fprintf(stderr, " - %s\n", labels[i]);

    return -1;
}

int get_config_uint(yajl_val j_mod, const char *key[],
                    unsigned int min, unsigned int max,
                    unsigned int *out_int)
{
    int i;
    unsigned int in_val;

    yajl_val j_val = yajl_tree_get(j_mod, key, yajl_t_number);
    if ( !j_val || !YAJL_IS_INTEGER(j_val) )
    {
        error("missing or invalid value:");
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "\n");

        return -1;
    }

    in_val = YAJL_GET_INTEGER(j_val);
    if ( (in_val < min) || (in_val > max) )
    {
        error("value outside range [%u, %u]:", min, max);
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "\n");
        return -1;
    }

    *out_int = in_val;

    return 0;
}

int get_config_memory_size(yajl_val j_mod, const char *key[],
                             uint64_t *out_mem_size)
{
    int i;
    unsigned long long in_val;

    yajl_val j_val = yajl_tree_get(j_mod, key, yajl_t_number);
    if ( !j_val || !YAJL_IS_INTEGER(j_val) )
    {
        error("missing or invalid value:");
        for ( i = 0; key[i] != NULL; i++ )
            fprintf(stderr, " %s", key[i]);
        fprintf(stderr, "\n");

        return -1;
    }

    in_val = YAJL_GET_INTEGER(j_val);
#define MAX_MEMORY_SIZE ( 1024UL * 1024UL * 1024UL * 1024UL )
    if ( (in_val == 0) || (in_val > MAX_MEMORY_SIZE) )
        return -1;

    *out_mem_size = in_val;

    return 0;
}

int get_module_basic_config(yajl_val j_cfg, struct lcm_module *module)
{
    unsigned int cfg_len;

    if ( get_config_bool(j_cfg, (const char *[]){ "permissions", "privileged",
                                                  NULL },
                         LCM_DOMAIN_PERMISSION_PRIVILEGED,
                         &module->basic_config.permissions) )
        return -EINVAL;

    if ( get_config_bool(j_cfg, (const char *[]){ "permissions", "hardware",
                                                  NULL },
                         LCM_DOMAIN_PERMISSION_HARDWARE,
                         &module->basic_config.permissions) )
        return -EINVAL;


    if ( get_config_bool(j_cfg, (const char *[]){ "functions", "boot", NULL },
                         LCM_DOMAIN_FUNCTION_BOOT,
                         &module->basic_config.functions) )
        return -EINVAL;

    if ( get_config_bool(j_cfg, (const char *[]){ "functions", "console",
                                                  NULL },
                         LCM_DOMAIN_FUNCTION_CONSOLE,
                         &module->basic_config.functions) )
        return -EINVAL;

    if ( get_config_bool(j_cfg, (const char *[]){ "mode", "pv", NULL },
                         LCM_DOMAIN_MODE_PARAVIRTUALIZED,
                         &module->basic_config.mode) )
        return -EINVAL;

    if ( get_config_bool(j_cfg, (const char *[]){ "mode",
                                                  "device_model", NULL },
                         LCM_DOMAIN_MODE_ENABLE_DEVICE_MODEL,
                         &module->basic_config.mode) )
        return -EINVAL;

    if ( get_config_string(j_cfg, (const char *[]){ "domain_handle", NULL },
                           sizeof(module->basic_config.domain_handle),
                           &cfg_len,
                           (uint8_t *)&module->basic_config.domain_handle) )
        return -EINVAL;

    if ( get_config_memory_size(j_cfg, (const char *[]){ "memory_size",
                                                         NULL  },
                                &module->basic_config.mem_size) )
        return -EINVAL;

    if ( get_config_domain_sid(j_cfg, (const char *[]){ "domain_sid", NULL  },
                               &module->basic_config.domain_sid) )
        return -EINVAL;

    return 0;
}

int get_module_high_priv_config(yajl_val j_cfg, struct lcm_module *module)
{
    if ( get_config_bool(j_cfg, (const char *[]){ "mode", "pv", NULL },
                         LCM_DOMAIN_HIGH_PRIV_MODE_PARAVIRTUALIZED,
                         &module->high_priv_config.mode) )
        return -EINVAL;

    return 0;
}

int get_module_extended_config(yajl_val j_cfg, struct lcm_module *module,
                               unsigned int max_config_len,
                               unsigned int *out_config_len)
{
    if ( get_config_string(j_cfg, (const char *[]){ "config", NULL },
                           max_config_len, out_config_len,
                           &module->extended_config.config_string[0]) )
        return -1;

    return 0;
}

/*
 * TODO: enforce/validate constraints on the LCM:
 *       - is there a description for each multiboot module, or are there
 *         gaps below the highest-numbered mb_index from the input?
 */
int generate_launch_control_module(yajl_val config_node, FILE *file_stream)
{
    struct lcm_header_info *header_info;
    struct lcm_module *module;
    int ret;
    unsigned int out_size;
    unsigned int written;
    unsigned int mod_idx;
    unsigned int buf_len;
    unsigned int multiboot_mod_index;
    unsigned char *out_buffer;
    yajl_val j_modules, j_mod;

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

    j_modules = yajl_tree_get(config_node, (const char *[]){ "modules", NULL },
                              yajl_t_array);

    if ( !j_modules || !YAJL_IS_ARRAY(j_modules) ||
         YAJL_GET_ARRAY(j_modules)->len > MAX_NUMBER_OF_LCM_MODULES )
        return -EINVAL;

    debug("got modules\n");

    module = &header_info->modules[0]; /* Indexing only valid for 0th module */

    for ( mod_idx = 0; mod_idx < YAJL_GET_ARRAY(j_modules)->len; mod_idx++ )
    {
        bool basic_config_found = false;
        yajl_val j_cfg;

        j_mod = YAJL_GET_ARRAY(j_modules)->values[mod_idx];

        debug("reading mb_index for mod_idx: %u\n", mod_idx);

        if ( get_config_uint(j_mod, (const char *[]){ "mb_index", NULL },
                             0, 255, &multiboot_mod_index) )
            return -EINVAL;

        /* ---- basic config ---- */
        j_cfg = yajl_tree_get(j_mod, (const char *[]){"basic_config", NULL},
                              yajl_t_object);
        if ( j_cfg )
        {
            debug("basic config\n");

            ret = get_module_basic_config(j_cfg, module);
            if ( ret )
                return ret;

            basic_config_found = true;

            module->type = LCM_MODULE_DOMAIN_BASIC_CONFIG;
            module->mb_index = multiboot_mod_index;
            module->pad[0] = 0;
            module->len = sizeof(struct lcm_module) +
                          sizeof(struct lcm_domain_basic_config);

            out_size += module->len;
            module = (struct lcm_module *)(((uint8_t *)module) + module->len);
        }

        /* ---- high priv config ---- */
        j_cfg = yajl_tree_get(j_mod,
                              (const char *[]){"high_priv_config", NULL},
                              yajl_t_object);
        if ( j_cfg )
        {
            debug("high priv config\n");

            if ( basic_config_found )
            {
                error("module #%u has both basic and high priv configs\n",
                       multiboot_mod_index);
                return -EINVAL;
            }

            ret = get_module_high_priv_config(j_cfg, module);
            if ( ret )
                return ret;

            module->type = LCM_MODULE_DOMAIN_HIGH_PRIV_CONFIG;
            module->mb_index = multiboot_mod_index;
            module->pad[0] = 0;
            module->len = sizeof(struct lcm_module) +
                          sizeof(struct lcm_domain_high_priv_config);

            out_size += module->len;
            module = (struct lcm_module *)(((uint8_t *)module) + module->len);
        }

        /* ---- extended config ---- */
        j_cfg = yajl_tree_get(j_mod,
                              (const char *[]){"extended_config", NULL},
                              yajl_t_object);
        if ( j_cfg )
        {
            /* FIXME: a better max_len_config_string here */
            unsigned int max_len_config_string = buf_len
                - out_size
                - sizeof(struct lcm_module)
                - sizeof(struct lcm_domain_extended_config);
            unsigned int len_config_string;

            debug("extended config\n");

            ret = get_module_extended_config(j_cfg, module,
                                             max_len_config_string,
                                             &len_config_string);
            if ( ret )
                return ret;

            debug("extended config string length: %u\n", len_config_string);

            module->type = LCM_MODULE_DOMAIN_EXTENDED_CONFIG;
            module->mb_index = multiboot_mod_index;
            module->pad[0] = 0;
            module->len = sizeof(struct lcm_module) +
                          sizeof(struct lcm_domain_extended_config) +
                          len_config_string;

            out_size += module->len;
            module = (struct lcm_module *)(((uint8_t *)module) + module->len);
        }


        /* TODO: ramdisk */
        /* TODO: microcode */
        /* TODO: xsm_flask_policy */
    }

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
