/*
 * lcm-tool : Launch Control Module tool
 *
 * Tool to generate a Launch Control Module for Xen.
 *
 * Copyright (c) 2020, Star Lab Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <yajl/yajl_tree.h>

#include "launch-control-module.h"

#define MAX_INPUT_FILE_SIZE (1024 * 64) /* in bytes */

#define DEBUG

#ifdef DEBUG
#define debug(format, args...) printf("DEBUG: " format, ## args )
#else
#define debug(format, ... ) ((void)0)
#endif

void show_help(const char *cmdname)
{
    printf("%s <launch definition file>\n", cmdname);
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

int main(int argc, char **argv)
{
    const char *filename;
    unsigned char *file_buffer;
    unsigned int file_size, buffer_size;
    yajl_val config_node;

    if ( argc != 2 )
    {
        show_help(argv[0]);
        return 1;
    }
    filename = argv[1];

    if ( read_file_size(filename, MAX_INPUT_FILE_SIZE, &file_size) )
        return 2;

    buffer_size = file_size + 1; /* Add one for a null terminator */

    file_buffer = malloc(buffer_size);
    if ( !file_buffer )
    {
        fprintf(stderr, "Couldn't allocate memory to read entire file: %s\n",
                filename);
        return 2;
    }
    memset(file_buffer, 0, buffer_size);

    if ( read_and_parse_input_file(filename, file_buffer, buffer_size,
                                   &config_node) )
    {
        fprintf(stderr, "Couldn't parse file: %s\n", filename);
        return 2;
    }

    /* TODO: read the nodes and generate the LCM */

    yajl_tree_free(config_node);
    free(file_buffer);

    return 0;
}
