/*
 * Flattened Device Tree
 *
 * Copyright (C) 2012 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __XEN_FDT_H__
#define __XEN_FDT_H__

#include <xen/init.h>
#include <xen/libfdt/libfdt.h>
#include <xen/types.h>

#define DEVICE_TREE_MAX_DEPTH 16

/* Default #address and #size cells */
#define DT_ROOT_NODE_ADDR_CELLS_DEFAULT 2
#define DT_ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define dt_prop_cmp(s1, s2) strcmp((s1), (s2))
#define dt_node_cmp(s1, s2) strcasecmp((s1), (s2))
#define dt_compat_cmp(s1, s2) strcasecmp((s1), (s2))

/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 dt_read_number(const __be32 *cell, int size)
{
    u64 r = 0;

    while ( size-- )
        r = (r << 32) | be32_to_cpu(*(cell++));
    return r;
}

/* Helper to convert a number of cells to bytes */
static inline int dt_cells_to_size(int size)
{
    return (size * sizeof (u32));
}

/* Helper to convert a number of bytes to cells, rounds down */
static inline int dt_size_to_cells(int bytes)
{
    return (bytes / sizeof(u32));
}

static inline u64 dt_next_cell(int s, const __be32 **cellp)
{
    const __be32 *p = *cellp;

    *cellp = p + s;
    return dt_read_number(p, s);
}


bool __init device_tree_node_matches(
    const void *fdt, int node, const char *match);

bool __init device_tree_node_compatible(
    const void *fdt, int node, const char *match);

void __init device_tree_get_reg(
    const __be32 **cell, u32 address_cells, u32 size_cells, u64 *start,
    u64 *size);

u32 __init device_tree_get_u32(
    const void *fdt, int node, const char *prop_name, u32 dflt);

typedef int (*device_tree_node_func)(
    const void *fdt, int node, const char *name, int depth, u32 address_cells,
    u32 size_cells, void *data);

int device_tree_for_each_node(
    const void *fdt, int node, device_tree_node_func func, void *data);


#endif /* __XEN_FDT_H__ */
