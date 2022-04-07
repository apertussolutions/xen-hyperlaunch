
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <xenstore.h>

#define MAX_XS_PAATH 100

static xs_transaction_t t_id = XBT_NULL;

int do_xs_start_transaction(struct xs_handle *xsh)
{
    t_id = xs_transaction_start(xsh);
    if (t_id == XBT_NULL)
        return -errno;

    return 0;
}

int do_xs_end_transaction(struct xs_handle *xsh)
{
    if ( t_id == XBT_NULL )
        return -EINVAL;

    if (!xs_transaction_end(xsh, t_id, false))
        return -errno;

    return 0;
}

int do_xs_write(struct xs_handle *xsh, char *path, char *val)
{
    if ( !xs_write(xsh, t_id, path, val, strlen(val)) )
    {
        fprintf(stderr, "failed write: %s\n", path);
        return -errno;
    }

    return 0;
}

int do_xs_perms(
    struct xs_handle *xsh, char *path, struct xs_permissions *perms,
    uint32_t num_perms)
{
    if ( !xs_set_permissions(xsh, t_id, path, perms, num_perms) )
    {
        fprintf(stderr, "failed set perm: %s\n", path);
        return -errno;
    }

    return 0;
}

int do_xs_write_dir_node_with_perm(
    struct xs_handle *xsh, char *dir, char *node, char *val,
    struct xs_permissions *perms, uint32_t num_perms)
{
    char full_path[MAX_XS_PAATH];
    int ret = 0;

    /*
     * mainly for creating a value holding node, but
     * also support creating directory nodes.
     */
    if ( strlen(node) != 0 )
        snprintf(full_path, MAX_XS_PAATH, "%s/%s", dir, node);
    else
        snprintf(full_path, MAX_XS_PAATH, "%s", dir);

    ret = do_xs_write(xsh, full_path, val);
    if ( ret < 0 )
        return ret;

    if ( perms != NULL && num_perms > 0 )
        ret = do_xs_perms(xsh, full_path, perms, num_perms);

    return ret;
}

int do_xs_write_dir_node(
    struct xs_handle *xsh, char *dir, char *node, char *val)
{
    return do_xs_write_dir_node_with_perm(xsh, dir, node, val, NULL, 0);
}

int do_xs_write_dom_with_perm(
    struct xs_handle *xsh, uint32_t domid, char *path, char *val,
    struct xs_permissions *perms, uint32_t num_perms)
{
    char full_path[MAX_XS_PAATH];
    int ret = 0;

    /*
     * mainly for creating a value holding node, but
     * also support creating directory nodes.
     */
    if ( strlen(path) != 0 )
        snprintf(full_path, MAX_XS_PAATH, "/local/domain/%d/%s", domid, path);
    else
        snprintf(full_path, MAX_XS_PAATH, "/local/domain/%d", domid);

    ret = do_xs_write(xsh, full_path, val);
    if ( ret < 0 )
        return ret;

    if ( perms != NULL && num_perms > 0 )
        ret = do_xs_perms(xsh, full_path, perms, num_perms);

    return ret;
}

int do_xs_write_dom(
    struct xs_handle *xsh, uint32_t domid, char *path, char *val)
{
    return do_xs_write_dom_with_perm(xsh, domid, path, val, NULL, 0);
}
