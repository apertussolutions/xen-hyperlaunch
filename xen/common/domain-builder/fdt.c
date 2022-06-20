#include <xen/bootdomain.h>
#include <xen/bootinfo.h>
#include <xen/domain_builder.h>
#include <xen/fdt.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/page-size.h>
#include <xen/pfn.h>
#include <xen/types.h>

#include <asm/bzimage.h>
#include <asm/setup.h>

#include "fdt.h"

#define BUILDER_FDT_TARGET_UNK 0
#define BUILDER_FDT_TARGET_X86 1
#define BUILDER_FDT_TARGET_ARM 2
static int __initdata target_arch = BUILDER_FDT_TARGET_UNK;

static struct boot_module *read_module(
    const void *fdt, int node, uint32_t address_cells, uint32_t size_cells,
    struct boot_info *info)
{
    const struct fdt_property *prop;
    const __be32 *cell;
    struct boot_module *bm;
    bootmodule_kind kind = BOOTMOD_UNKNOWN;
    int len;

    if ( device_tree_node_compatible(fdt, node, "module,kernel") )
        kind = BOOTMOD_KERNEL;

    if ( device_tree_node_compatible(fdt, node, "module,ramdisk") )
        kind = BOOTMOD_RAMDISK;

    if ( device_tree_node_compatible(fdt, node, "module,microcode") )
        kind = BOOTMOD_UCODE;

    if ( device_tree_node_compatible(fdt, node, "module,xsm-policy") )
        kind = BOOTMOD_XSM;

    if ( device_tree_node_compatible(fdt, node, "module,config") )
        kind = BOOTMOD_GUEST_CONF;

    if ( device_tree_node_compatible(fdt, node, "module,index") )
    {
        uint32_t idx;

        idx = (uint32_t)device_tree_get_u32(fdt, node, "module-index", 0);
        if ( idx == 0 )
            return NULL;

        bm = &info->mods[idx];

        bm->kind = kind;

        return bm;
    }

    if ( device_tree_node_compatible(fdt, node, "module,addr") )
    {
        uint64_t addr, size;

        prop = fdt_get_property(fdt, node, "module-addr", &len);
        if ( !prop )
            return NULL;

        if ( len < dt_cells_to_size(address_cells + size_cells) )
            return NULL;

        cell = (const __be32 *)prop->data;
        device_tree_get_reg(
            &cell, address_cells, size_cells, &addr, &size);

        bm = bootmodule_next_by_addr(info, addr, NULL);

        bm->kind = kind;

        return bm;
    }

    printk(XENLOG_WARNING
           "builder fdt: module node %d, no index or addr provided\n",
           node);

    return NULL;
}

static int process_config_node(
    const void *fdt, int node, const char *name, int depth,
    uint32_t address_cells, uint32_t size_cells, void *data)
{
    struct boot_info *info = (struct boot_info *)data;
    int node_next;

    if ( !info )
        return -1;

    for ( node_next = fdt_first_subnode(fdt, node);
          node_next > 0;
          node_next = fdt_next_subnode(fdt, node_next))
        read_module(fdt, node_next, address_cells, size_cells, info);

    return 0;
}

static int process_domain_node(
    const void *fdt, int node, const char *name, int depth,
    uint32_t address_cells, uint32_t size_cells, void *data)
{
    struct boot_info *info = (struct boot_info *)data;
    const struct fdt_property *prop;
    struct boot_domain *domain;
    int node_next, i, plen;

    if ( !info )
        return -1;

    if ( info->builder->nr_doms >= BUILD_MAX_BOOT_DOMAINS )
        return -1;

    domain = &info->builder->domains[info->builder->nr_doms];

    domain->domid = (domid_t)device_tree_get_u32(fdt, node, "domid", 0);
    domain->permissions = device_tree_get_u32(fdt, node, "permissions", 0);
    domain->functions = device_tree_get_u32(fdt, node, "functions", 0);
    domain->mode = device_tree_get_u32(fdt, node, "mode", 0);

    prop = fdt_get_property(fdt, node, "domain-uuid", &plen);
    if ( prop )
        for ( i=0; i < sizeof(domain->uuid) % sizeof(uint32_t); i++ )
            *(domain->uuid + i) = fdt32_to_cpu((uint32_t)prop->data[i]);

    domain->ncpus = device_tree_get_u32(fdt, node, "cpus", 1);

    if ( target_arch == BUILDER_FDT_TARGET_X86 )
    {
        prop = fdt_get_property(fdt, node, "memory", &plen);
        if ( prop )
        {
            int sz = fdt32_to_cpu(prop->len);
            char s[64];
            unsigned long val;

            if ( sz >= 64 )
                panic("node %s invalid `memory' property\n", name);

            memcpy(s, prop->data, sz);
            s[sz] = '\0';
            val = parse_size_and_unit(s, NULL);

            domain->meminfo.mem_size.nr_pages = PFN_UP(val);
            domain->meminfo.mem_max.nr_pages = PFN_UP(val);
        }
        else
            panic("node %s missing `memory' property\n", name);
    }
    else
            panic("%s: only x86 memory parsing supported\n", __func__);

    prop = fdt_get_property(fdt, node, "security-id",
                                &plen);
    if ( prop )
    {
        int sz = fdt32_to_cpu(prop->len);
        sz = sz > BUILD_MAX_SECID_LEN ?  BUILD_MAX_SECID_LEN : sz;
        memcpy(domain->secid, prop->data, sz);
    }

    for ( node_next = fdt_first_subnode(fdt, node);
          node_next > 0;
          node_next = fdt_next_subnode(fdt, node_next))
    {
        struct boot_module *bm = read_module(fdt, node_next, address_cells,
                                             size_cells, info);

        switch ( bm->kind )
        {
        case BOOTMOD_KERNEL:
            /* kernel was already found */
            if ( domain->kernel != NULL )
                continue;

            bm->arch->headroom = bzimage_headroom(bootstrap_map(bm), bm->size);
            bootstrap_map(NULL);

            if ( bm->string.len )
                bm->string.kind = BOOTSTR_CMDLINE;
            else
            {
                prop = fdt_get_property(fdt, node_next, "bootargs", &plen);
                if ( prop )
                {
                    int size = fdt32_to_cpu(prop->len);
                    size = size > BOOTMOD_MAX_STRING ?
                           BOOTMOD_MAX_STRING : size;
                    memcpy(bm->string.bytes, prop->data, size);
                    bm->string.kind = BOOTSTR_CMDLINE;
                }
            }

            domain->kernel = bm;

            break;
        case BOOTMOD_RAMDISK:
            /* ramdisk was already found */
            if ( domain->ramdisk != NULL )
                continue;

            domain->ramdisk = bm;

            break;
        case BOOTMOD_GUEST_CONF:
            /* guest config was already found */
            if ( domain->configs[BUILD_DOM_CONF_IDX] != NULL )
                continue;

            domain->configs[BUILD_DOM_CONF_IDX] = bm;

            break;
        default:
            continue;
        }
    }

    info->builder->nr_doms++;

    return 0;
}

static int __init scan_node(
    const void *fdt, int node, const char *name, int depth, u32 address_cells,
    u32 size_cells, void *data)
{
    int rc = -1;

    /* skip nodes that are not direct children of the hyperlaunch node */
    if ( depth > 1 )
        return 0;

    if ( device_tree_node_compatible(fdt, node, "xen,config") )
        rc = process_config_node(fdt, node, name, depth,
                                 address_cells, size_cells, data);
    else if ( device_tree_node_compatible(fdt, node, "xen,domain") )
        rc = process_domain_node(fdt, node, name, depth,
                                 address_cells, size_cells, data);

    if ( rc < 0 )
        printk("hyperlaunch fdt: node `%s'failed to parse\n", name);

    return rc;
}

/* check_fdt
 *   Attempts to initialize hyperlaunch config
 *
 * Returns:
 *    -EINVAL: Not a valid DTB
 *   -ENODATA: Valid DTB but not a valid hyperlaunch device tree
 *          0: Valid hyperlaunch device tree
 */
int __init check_fdt(struct boot_info *info, void *fdt)
{
    int hv_node, ret;

    ret = fdt_check_header(fdt);
    if ( ret < 0 )
        return -EINVAL;

    hv_node = fdt_path_offset(fdt, "/chosen/hypervisor");
    if ( hv_node < 0 )
        return -ENODATA;

    if ( !device_tree_node_compatible(fdt, hv_node, "hypervisor,xen") )
        return -EINVAL;

    if ( IS_ENABLED(CONFIG_X86) &&
         device_tree_node_compatible(fdt, hv_node, "xen,x86") )
        target_arch = BUILDER_FDT_TARGET_X86;
    else if ( IS_ENABLED(CONFIG_ARM) &&
              device_tree_node_compatible(fdt, hv_node, "xen,arm") )
        target_arch = BUILDER_FDT_TARGET_ARM;

    if ( target_arch != BUILDER_FDT_TARGET_X86 &&
         target_arch != BUILDER_FDT_TARGET_ARM )
        return -EINVAL;

    ret = device_tree_for_each_node(fdt, hv_node, scan_node, boot_info);
    if ( ret > 0 )
        return -ENODATA;

    return 0;
}
