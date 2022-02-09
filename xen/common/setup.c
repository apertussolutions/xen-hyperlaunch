#include <xen/fdt.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/multiboot.h>
#include <xen/page-size.h>
#include <xen/setup.h>
#include <xen/types.h>

#include <asm/bzimage.h> /* for bzimage_headroom */
#include <asm/setup.h>

/*
 * reference to the configuration for the current boot domain under
 * construction
 */
struct bootdomain __initdata *current_bootdomain;

#ifdef CONFIG_HYPERLAUNCH

bool __initdata hyperlaunch_enabled;
static struct hyperlaunch_config __initdata hl_config;

static bool read_module(
    const void *fdt, int node, uint32_t address_cells, uint32_t size_cells,
    struct hyperlaunch_config *config, struct bootmodule *bm)
{
    const struct fdt_property *prop;
    const __be32 *cell;
    bootmodule_kind kind = BOOTMOD_UNKNOWN;
    int len;

    if ( device_tree_node_compatible(fdt, node, "module,kernel") )
        kind = BOOTMOD_KERNEL;

    if ( device_tree_node_compatible(fdt, node, "module,ramdisk") )
        kind = BOOTMOD_RAMDISK;

    if ( device_tree_node_compatible(fdt, node, "module,microcode") )
        kind = BOOTMOD_MICROCODE;

    if ( device_tree_node_compatible(fdt, node, "module,xsm-policy") )
        kind = BOOTMOD_XSM;

    if ( device_tree_node_compatible(fdt, node, "module,config") )
        kind = BOOTMOD_GUEST_CONF;

    if ( device_tree_node_compatible(fdt, node, "multiboot,module") )
    {
#ifdef CONFIG_MULTIBOOT
        uint32_t idx;

        idx = (uint32_t)device_tree_get_u32(fdt, node, "mb-index", 0);
        if ( idx == 0 )
            return false;

        bm->kind = kind;
        /* under multiboot, start will just hold pointer to module entry */
        bm->start = (paddr_t)(&config->mods[idx]);

        return true;
#else
        return false;
#endif
    }

    prop = fdt_get_property(fdt, node, "module-addr", &len);
    if ( !prop )
        return false;

    if ( len < dt_cells_to_size(address_cells + size_cells) )
        return false;

    cell = (const __be32 *)prop->data;
    device_tree_get_reg(
        &cell, address_cells, size_cells, &(bm->start), &(bm->size));
    bm->kind = kind;

    return true;
}

static int process_config_node(
    const void *fdt, int node, const char *name, int depth,
    uint32_t address_cells, uint32_t size_cells, void *data)
{
    struct hyperlaunch_config *config = (struct hyperlaunch_config *)data;
    uint16_t *count;
    int node_next;

    if ( !config )
        return -1;

    for ( node_next = fdt_first_subnode(fdt, node),
          count = &(config->config.nr_mods);
          node_next > 0;
          node_next = fdt_next_subnode(fdt, node_next),
          (*count)++ )
    {
        struct bootmodule *next_bm;

        if ( *count >= HL_MAX_CONFIG_MODULES )
        {
            printk("Warning: truncating to %d hyperlaunch config modules\n",
                   HL_MAX_CONFIG_MODULES);
            return 0;
        }

        next_bm = &config->config.mods[*count];
        read_module(fdt, node_next, address_cells, size_cells, config, next_bm);
    }

    return 0;
}

static int process_domain_node(
    const void *fdt, int node, const char *name, int depth,
    uint32_t address_cells, uint32_t size_cells, void *data)
{
    struct hyperlaunch_config *config = (struct hyperlaunch_config *)data;
    const struct fdt_property *prop;
    struct bootdomain *domain;
    uint16_t *count;
    int node_next, i, plen;

    if ( !config )
        return -1;

    domain = &config->domains[config->nr_doms];

    domain->domid = (domid_t)device_tree_get_u32(fdt, node, "domid", 0);
    domain->permissions = device_tree_get_u32(fdt, node, "permissions", 0);
    domain->functions = device_tree_get_u32(fdt, node, "functions", 0);
    domain->mode = device_tree_get_u32(fdt, node, "mode", 0);

    prop = fdt_get_property(fdt, node, "domain-uuid", &plen);
    if ( prop )
        for ( i=0; i < sizeof(domain->uuid) % sizeof(uint32_t); i++ )
            *(domain->uuid + i) = fdt32_to_cpu((uint32_t)prop->data[i]);

    domain->ncpus = device_tree_get_u32(fdt, node, "cpus", 1);

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

        domain->mem_size.nr_pages = val >> PAGE_SHIFT;
    }
    else
        panic("node %s missing `memory' property\n", name);

    prop = fdt_get_property(fdt, node, "security-id",
                                &plen);
    if ( prop )
    {
        int sz = fdt32_to_cpu(prop->len);
        sz = sz > HL_MAX_SECID_LEN ?  HL_MAX_SECID_LEN : sz;
        memcpy(domain->secid, prop->data, sz);
    }

    for ( node_next = fdt_first_subnode(fdt, node),
          count = &(domain->nr_mods);
          node_next > 0;
          node_next = fdt_next_subnode(fdt, node_next),
          (*count)++ )
    {
        struct bootmodule *next_bm;

        if ( name == NULL )
            continue;

        if ( *count >= HL_MAX_DOMAIN_MODULES )
        {
            printk("Warning: truncating to %d hyperlaunch domain modules"
                   " for %dth domain\n", HL_MAX_DOMAIN_MODULES,
                   config->nr_doms);
            break;
        }

        if ( device_tree_node_compatible(fdt, node_next, "module,kernel") )
        {
            prop = fdt_get_property(fdt, node_next, "bootargs", &plen);
            if ( prop )
            {
                int size = fdt32_to_cpu(prop->len);
                size = size > HL_MAX_CMDLINE_LEN ? HL_MAX_CMDLINE_LEN : size;
                memcpy(domain->cmdline, prop->data, size);
            }
        }

        next_bm = &domain->modules[*count];
        read_module(fdt, node_next, address_cells, size_cells, config, next_bm);
    }

    config->nr_doms++;

    return 0;
}

static int __init hl_scan_node(
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
        printk("hyperlaunch fdt: node `%s': parsing failed\n", name);

    return rc;
}

/* hyperlaunch_init:
 *   Attempts to initialize hyperlaunch config
 *
 * Returns:
 *   -1: Not a valid DTB
 *    0: Valid DTB but not a valid hyperlaunch device tree
 *    1: Valid hyperlaunch device tree
 */
int __init hyperlaunch_init(const void *fdt)
{
    int hl_node, ret;

    ret = fdt_check_header(fdt);
    if ( ret < 0 )
        return -1;

    hl_node = fdt_path_offset(fdt, "/chosen/hypervisor");
    if ( hl_node < 0 )
        return 0;

    ret = device_tree_for_each_node(fdt, hl_node, hl_scan_node, &hl_config);
    if ( ret > 0 )
        return 0;

    hyperlaunch_enabled = true;

    return 1;
}

#ifdef CONFIG_MULTIBOOT
bool __init hyperlaunch_mb_init(module_t *mods)
{
    bool ret = false;
    /* fdt is required to be module 0 */
    void *fdt = _p(mods->mod_start);

    hl_config.mods = mods;

    switch ( hyperlaunch_init(fdt) )
    {
    case 1:
        ret = true;
    case -1:
        break;
    case 0:
    default:
        panic("HYPERLAUNCH: nonrecoverable error occured processing DTB\n");
    }

    return ret;
}

void __init hyperlaunch_mb_headroom(void)
{
    int i,j;

    for( i = 0; i < hl_config.nr_doms; i++ )
    {
        for ( j = 0; j < hl_config.domains[i].nr_mods; j++ )
        {
            if ( hl_config.domains[i].modules[j].kind == BOOTMOD_KERNEL )
            {
                module_t *kern =
                    (module_t *)_p(hl_config.domains[i].modules[j].start);

                kern->headroom = bzimage_headroom(bootstrap_map(kern),
                                                  kern->mod_end);
                bootstrap_map(NULL);
            }
        }
    }
}
#endif

uint32_t __init hyperlaunch_create_domains(
    struct domain **hwdom, const char *kextra, const char *loader)
{
    uint32_t dom_count = 0, functions_used = 0;
    int i;

    *hwdom = NULL;

    for ( i = 0; i < hl_config.nr_doms; i++ )
    {
        struct bootdomain *d = &(hl_config.domains[i]);

        /* build a legacy dom0 and set it as the hwdom */
        if ( (d->functions & HL_FUNCTION_LEGACY_DOM0) &&
             !(functions_used & HL_FUNCTION_LEGACY_DOM0) )
        {
            module_t *image = NULL, *initrd = NULL;
            int j;

            for ( j = 0; j < d->nr_mods; j++ )
            {
                if ( d->modules[j].kind == BOOTMOD_KERNEL )
                    image = (module_t *)_p(d->modules[j].start);

                if ( d->modules[j].kind == BOOTMOD_RAMDISK )
                    initrd = (module_t *)_p(d->modules[j].start);

                if ( image && initrd )
                    break;
            }

            if ( image == NULL )
                return 0;

#ifdef CONFIG_MULTIBOOT
            *hwdom = create_dom0(image, initrd, kextra, loader);
#endif
            if ( *hwdom )
            {
                functions_used |= HL_FUNCTION_LEGACY_DOM0;
                dom_count++;
            }
            else
                panic("HYPERLAUNCH: "
                      "Dom0 config present but dom0 construction failed\n");
        }
        else
            printk(XENLOG_WARNING "hyperlaunch: "
                   "currently only supports classic dom0 construction");
    }

    return dom_count;
}

#endif
