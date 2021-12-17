/*
 * Flattened Device Tree
 *
 * Copyright (C) 2012-2014 Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <xen/fdt.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/types.h>

bool __init device_tree_node_matches(
    const void *fdt, int node, const char *match)
{
    const char *name;
    size_t match_len;

    name = fdt_get_name(fdt, node, NULL);
    match_len = strlen(match);

    /* Match both "match" and "match@..." patterns but not
       "match-foo". */
    return strncmp(name, match, match_len) == 0
        && (name[match_len] == '@' || name[match_len] == '\0');
}

bool __init device_tree_node_compatible(
    const void *fdt, int node, const char *match)
{
    int len, l;
    int mlen;
    const void *prop;

    mlen = strlen(match);

    prop = fdt_getprop(fdt, node, "compatible", &len);
    if ( prop == NULL )
        return false;

    while ( len > 0 ) {
        if ( !dt_compat_cmp(prop, match) )
            return true;
        l = strlen(prop) + 1;
        prop += l;
        len -= l;
    }

    return false;
}

void __init device_tree_get_reg(
    const __be32 **cell, u32 address_cells, u32 size_cells, u64 *start,
    u64 *size)
{
    *start = dt_next_cell(address_cells, cell);
    *size = dt_next_cell(size_cells, cell);
}

u32 __init device_tree_get_u32(
    const void *fdt, int node, const char *prop_name, u32 dflt)
{
    const struct fdt_property *prop;

    prop = fdt_get_property(fdt, node, prop_name, NULL);
    if ( !prop || prop->len < sizeof(u32) )
        return dflt;

    return fdt32_to_cpu(*(uint32_t*)prop->data);
}

/**
 * device_tree_for_each_node - iterate over all device tree sub-nodes
 * @fdt: flat device tree.
 * @node: parent node to start the search from
 * @func: function to call for each sub-node.
 * @data: data to pass to @func.
 *
 * Any nodes nested at DEVICE_TREE_MAX_DEPTH or deeper are ignored.
 *
 * Returns 0 if all nodes were iterated over successfully.  If @func
 * returns a value different from 0, that value is returned immediately.
 */
int __init device_tree_for_each_node(
    const void *fdt, int node, device_tree_node_func func, void *data)
{
    /*
     * We only care about relative depth increments, assume depth of
     * node is 0 for simplicity.
     */
    int depth = 0;
    const int first_node = node;
    u32 address_cells[DEVICE_TREE_MAX_DEPTH];
    u32 size_cells[DEVICE_TREE_MAX_DEPTH];
    int ret;

    do {
        const char *name = fdt_get_name(fdt, node, NULL);
        u32 as, ss;

        if ( depth >= DEVICE_TREE_MAX_DEPTH )
        {
            printk("Warning: device tree node `%s' is nested too deep\n",
                   name);
            continue;
        }

        as = depth > 0 ? address_cells[depth-1] : DT_ROOT_NODE_ADDR_CELLS_DEFAULT;
        ss = depth > 0 ? size_cells[depth-1] : DT_ROOT_NODE_SIZE_CELLS_DEFAULT;

        address_cells[depth] = device_tree_get_u32(fdt, node,
                                                   "#address-cells", as);
        size_cells[depth] = device_tree_get_u32(fdt, node,
                                                "#size-cells", ss);

        /* skip the first node */
        if ( node != first_node )
        {
            ret = func(fdt, node, name, depth, as, ss, data);
            if ( ret != 0 )
                return ret;
        }

        node = fdt_next_node(fdt, node, &depth);
    } while ( node >= 0 && depth > 0 );

    return 0;
}
