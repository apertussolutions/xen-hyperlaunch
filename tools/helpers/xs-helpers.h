#ifndef __XS_HELPERS_H
#define __XS_HELPERS_H

#include <xenstore.h>

int do_xs_start_transaction(struct xs_handle *xsh);
int do_xs_end_transaction(struct xs_handle *xsh);

int do_xs_write(struct xs_handle *xsh, char *path, char *val);
int do_xs_perms(
    struct xs_handle *xsh, char *path, struct xs_permissions *perms,
    uint32_t num_perms);

int do_xs_write_dir_node_with_perm(
    struct xs_handle *xsh, char *dir, char *node, char *val,
    struct xs_permissions *perms, uint32_t num_perms);
int do_xs_write_dir_node(
    struct xs_handle *xsh, char *dir, char *node, char *val);

int do_xs_write_dom_with_perm(
    struct xs_handle *xsh, uint32_t domid, char *path, char *val,
    struct xs_permissions *perms, uint32_t num_perms);
int do_xs_write_dom(
    struct xs_handle *xsh, uint32_t domid, char *path, char *val);

#endif

