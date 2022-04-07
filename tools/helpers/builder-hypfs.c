
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <xenhypfs.h>

#include "late-init-pv.h"

/* general size for static path array */
#define HYPFS_MAX_PATH 100

bool has_builder_hypfs(xenhypfs_handle *hdl, uint32_t domid)
{
    struct xenhypfs_dirent *ent;
    char path[HYPFS_MAX_PATH];
    unsigned int n;

    snprintf(path, HYPFS_MAX_PATH, "/builder/%d", domid);

    ent = xenhypfs_readdir(hdl, path, &n);
    if ( ent )
    {
        free(ent);
        return true;
    }

    return false;
}

static int read_hypfs_bool(xenhypfs_handle *fshdl, const char *path, bool *val)
{
    struct xenhypfs_dirent *dirent;
    void *raw_value;

    errno = 0;

    raw_value = xenhypfs_read_raw(fshdl, path, &dirent);
    if ( raw_value == NULL )
    {
        errno = EIO;
        return false;
    }

    if ( dirent->type != xenhypfs_type_bool )
    {
        errno = EINVAL;
        return false;
    }

    *val = *(bool *)raw_value;

    free(raw_value); free(dirent);
    return true;
}

static bool read_hypfs_uint(
    xenhypfs_handle *fshdl, const char *path, size_t sz, void *val)
{
    struct xenhypfs_dirent *dirent;
    void *raw_value;

    errno = 0;

    raw_value = xenhypfs_read_raw(fshdl, path, &dirent);
    if ( raw_value == NULL )
    {
        errno = EIO;
        return false;
    }

    if ( (dirent->type != xenhypfs_type_uint) ||
         (dirent->size != sz) )
    {
        errno = EINVAL;
        return false;
    }

    switch ( sz )
    {
    case sizeof(uint8_t):
        *(uint8_t *)val = *(uint8_t *)raw_value;
        break;
    case sizeof(uint16_t):
        *(uint16_t *)val = *(uint16_t *)raw_value;
        break;
    case sizeof(uint32_t):
        *(uint32_t *)val = *(uint32_t *)raw_value;
        break;
    case sizeof(uint64_t):
        *(uint64_t *)val = *(uint64_t *)raw_value;
        break;
    default:
        free(raw_value); free(dirent);
        errno = EINVAL;
        return false;
    }

    free(raw_value); free(dirent);
    return true;
}

static uint8_t read_hypfs_uint8(xenhypfs_handle *fshdl, const char *path)
{
    uint8_t value;

    if ( !read_hypfs_uint(fshdl, path, sizeof(value), &value) )
    {
        fprintf(stderr, "error: unable to read uint8_t from %s \n", path);
        return 0;
    }

    return value;
}

static uint16_t read_hypfs_uint16(xenhypfs_handle *fshdl, const char *path)
{
    uint16_t value;

    if ( !read_hypfs_uint(fshdl, path, sizeof(value), &value) )
    {
        fprintf(stderr, "error: unable to read uint16_t from %s \n", path);
        return 0;
    }

    return value;
}

static uint32_t read_hypfs_uint32(xenhypfs_handle *fshdl, const char *path)
{
    uint32_t value;

    if ( !read_hypfs_uint(fshdl, path, sizeof(value), &value) )
    {
        fprintf(stderr, "error: unable to read uint32_t from %s \n", path);
        return 0;
    }

    return value;
}

static uint64_t read_hypfs_uint64(xenhypfs_handle *fshdl, const char *path)
{
    uint64_t value;

    if ( !read_hypfs_uint(fshdl, path, sizeof(value), &value) )
    {
        fprintf(stderr, "error: unable to read uint64_t from %s \n", path);
        return 0;
    }

    return value;
}

static bool is_constructed(xenhypfs_handle *fshdl, uint32_t domid)
{
    char path[HYPFS_MAX_PATH];
    bool constructed;

    snprintf(path, HYPFS_MAX_PATH, "/builder/%d/constructed", domid);

    if ( !read_hypfs_bool(fshdl, path, &constructed) )
    {
        fprintf(stderr, "error: unable to read constructed field\n");
        return false;
    }

    return constructed;
}

#define XS_PATH   "/builder/%d/xenstore"
#define CONS_PATH "/builder/%d/devices/console"

int read_hypfs_tree(xenhypfs_handle *hdl, struct domain_info *di)
{
    char path[HYPFS_MAX_PATH];

    if ( !is_constructed(hdl, di->domid) )
    {
        fprintf(stderr, "error: domain %d did not get constructed\n",
                di->domid);
        return -EEXIST;
    }

    if ( !di->override_uuid )
    {
        snprintf(path, HYPFS_MAX_PATH, "/builder/%d/uuid", di->domid);
        di->uuid = xenhypfs_read(hdl, path);
    }

    snprintf(path, HYPFS_MAX_PATH, "/builder/%d/ncpus", di->domid);
    di->num_cpu = read_hypfs_uint32(hdl, path);
    if ( errno != 0 )
    {
        fprintf(stderr, "error: unable to read number of cpus\n");
        return -errno;
    }

    snprintf(path, HYPFS_MAX_PATH, "/builder/%d/mem_size", di->domid);
    di->mem_info.target = read_hypfs_uint32(hdl, path);
    if ( errno != 0 )
    {
        fprintf(stderr, "error: unable to read memory size\n");
        return -errno;
    }

    snprintf(path, HYPFS_MAX_PATH, "/builder/%d/mem_max", di->domid);
    di->mem_info.max = read_hypfs_uint32(hdl, path);
    if ( errno != 0 )
    {
        fprintf(stderr, "error: unable to read max memory\n");
        return -errno;
    }

    /* Xenstore */
    snprintf(path, HYPFS_MAX_PATH, XS_PATH "/evtchn", di->domid);
    di->xs_info.evtchn_port = read_hypfs_uint32(hdl, path);
    if ( errno != 0 )
    {
        fprintf(stderr, "error: unable to read xenstore event channel port\n");
        return -errno;
    }

    snprintf(path, HYPFS_MAX_PATH, XS_PATH "/mfn", di->domid);
    di->xs_info.mfn = read_hypfs_uint64(hdl, path);
    if ( errno != 0 )
    {
        fprintf(stderr, "error: unable to read xenstore page mfn\n");
        return -errno;
    }

    /* Console */
    if ( di->cons_info.enable )
    {
        snprintf(path, HYPFS_MAX_PATH, CONS_PATH "/evtchn", di->domid);
        di->cons_info.evtchn_port = read_hypfs_uint32(hdl, path);
        if ( errno != 0 )
        {
            fprintf(stderr, "error: unable to read xenstore event channel port\n");
            return -errno;
        }

        snprintf(path, HYPFS_MAX_PATH, CONS_PATH "/mfn", di->domid);
        di->cons_info.mfn = read_hypfs_uint64(hdl, path);
        if ( errno != 0 )
        {
            fprintf(stderr, "error: unable to read xenstore page mfn\n");
            return -errno;
        }
    }

    return 0;
}

