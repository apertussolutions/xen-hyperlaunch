#ifndef __HYPFS_HELPERS_H
#define __HYPFS_HELPERS_H

#include "late-init-pv.h"

bool has_builder_hypfs(xenhypfs_handle *hdl, uint32_t domid);
int read_hypfs_tree(xenhypfs_handle *hdl, struct domain_info *di);

#endif
