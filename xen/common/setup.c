#include <xen/err.h>
#include <xen/fdt.h>
#include <xen/grant_table.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/multiboot.h>
#include <xen/page-size.h>
#include <xen/setup.h>
#include <xen/types.h>
#include <public/domctl.h>

#include <asm/bzimage.h> /* for bzimage_headroom */
#include <asm/pv/shim.h>
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

static bool __init handle_mb_kernel(struct bootdomain *bd, const char *loader)
{
    struct bootmodule *bm;
    module_t *image = NULL;

    if ( (bm = bootmodule_by_type(bd, BOOTMOD_KERNEL)) == NULL )
        return false; /* TODO: add printk statement */

    if ( (image = (module_t *)_p(bm->start)) == NULL )
        return false; /* TODO: add printk statement */

    if ( image->string )
    {
        char *cmdline = image->string ? __va(image->string) : NULL;
        cmdline = cmdline_cook(cmdline, loader);
        safe_strcat(bd->cmdline, cmdline);
    }

    return true;
}
#endif

static domid_t __init get_next_domid(void)
{
    static domid_t last_domid = 0;
    domid_t next;

    for ( next = last_domid + 1; next < DOMID_FIRST_RESERVED; next++ )
    {
        struct domain *d;

        if ( (d = rcu_lock_domain_by_id(next)) == NULL )
        {
            last_domid = next;
            return next;
        }

        rcu_unlock_domain(d);
    }

    return 0;
}

static struct domain *__init create_domain(
    struct bootdomain *bd, const char *kextra, const char *loader)
{
    /* start off with some standard/common defaults */
    struct xen_domctl_createdomain dom_cfg = {
        .max_evtchn_port = -1,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
    };
    struct domain *d;
    bool is_privileged;

#ifdef CONFIG_MULTIBOOT
    if ( !handle_mb_kernel(bd, loader) )
        return NULL;
#endif

    /* mask out PV and device model bits, if 0 then the domain is PVH */
    if ( !(bd->mode & (HL_MODE_PARAVIRTUALIZED|HL_MODE_ENABLE_DEVICE_MODEL)) )
    {
        dom_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                         (hvm_hap_supported() ? XEN_DOMCTL_CDF_hap : 0));

        /* TODO: review which flags should be present */
        dom_cfg.arch.emulation_flags |=
            XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
    }

    if ( iommu_enabled && (bd->permissions & HL_PERMISSION_HARDWARE) )
        dom_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    if ( kextra )
        /* kextra always includes exactly one leading space. */
        safe_strcat(bd->cmdline, kextra);

    arch_dom_acpi(bd);

    /* configure a legacy dom0 */
    if ( (bd->functions & HL_FUNCTION_LEGACY_DOM0) )
    {
        domid_t dom0id = get_initial_domain_id();

        dom_cfg.flags |= IS_ENABLED(CONFIG_TBOOT) ? XEN_DOMCTL_CDF_s3_integrity : 0;
        dom_cfg.max_vcpus = dom0_max_vcpus();
        dom_cfg.arch.misc_flags = opt_dom0_msr_relaxed ? XEN_X86_MSR_RELAXED : 0;

        /* Force dom0 to be PVH regardless of hyperlaunch config */
        if ( opt_dom0_pvh )
        {
            dom_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                             ((hvm_hap_supported() && !opt_dom0_shadow) ?
                              XEN_DOMCTL_CDF_hap : 0));

            dom_cfg.arch.emulation_flags |=
                XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
        }

        if ( iommu_enabled )
            dom_cfg.flags |= XEN_DOMCTL_CDF_iommu;

        bd->domid = bd->domid == 0 ? dom0id : bd->domid;
        is_privileged = true;
    } else {
        unsigned int limit;

        /*
         * doing under else as to not burn a domid when legacy dom0 is
         * being constructed
         */
        if ( bd->domid == 0 && (bd->domid = get_next_domid()) == 0 )
                panic("hyperlaunch: unable to allocate domain ids\n");

        limit = bd-> mode & HL_MODE_PARAVIRTUALIZED ?
                    MAX_VIRT_CPUS : HVM_MAX_VCPUS;
        if ( bd->ncpus > limit )
            dom_cfg.max_vcpus = limit;
        else
            dom_cfg.max_vcpus = bd->ncpus;

        is_privileged = !!(bd->permissions & HL_PERMISSION_CONTROL);
    }

    is_privileged = pv_shim ? false : is_privileged;

    /* Create domain reference */
    d = domain_create(bd->domid, &dom_cfg, is_privileged);
    if ( IS_ERR(d) )
        return NULL;
    else
    {
        unsigned long cr4_pv32_mask;

        if ( (bd->functions & HL_FUNCTION_LEGACY_DOM0) ||
             (bd->permissions & HL_PERMISSION_HARDWARE) )
            hardware_domain = d;

        if ( (bd->functions & HL_FUNCTION_LEGACY_DOM0) )
        {
            if ( alloc_dom0_vcpu0(d) == NULL )
                panic("Error allocating VCPU for a Domain0\n");
        }
        else
        {
            if ( alloc_dom_vcpu0(d) == NULL )
                panic("Error allocating VCPU for a Domain0\n");
        }

        /*
         * Temporarily clear SMAP in CR4 to allow user-accesses in
         * construct_domain(). This saves a large number of corner cases
         * interactions with copy_from_user().
         */
        if ( cpu_has_smap )
        {
            cr4_pv32_mask &= ~X86_CR4_SMAP;
            write_cr4(read_cr4() & ~X86_CR4_SMAP);
        }

        if ( construct_domain(d, bd) != 0 )
            panic("Could not construct domain 0\n");

        if ( cpu_has_smap )
        {
            write_cr4(read_cr4() | X86_CR4_SMAP);
            cr4_pv32_mask |= X86_CR4_SMAP;
        }
    }

    return d;
}

uint32_t __init hyperlaunch_create_domains(
    struct domain **hwdom, const char *kextra, const char *loader)
{
    uint32_t dom_count = 0, functions_used = 0;
    int i;

    *hwdom = NULL;

    for ( i = 0; i < hl_config.nr_doms; i++ )
    {
        struct bootdomain *bd = &(hl_config.domains[i]);
        struct domain *d;

        d = create_domain(bd, kextra, loader);
        if ( !d )
            panic("HYPERLAUNCH: "
                  "Domain config present but construction failed\n");

        /* build a legacy dom0 and set it as the hwdom */
        if ( (bd->functions & HL_FUNCTION_LEGACY_DOM0) &&
             !(functions_used & HL_FUNCTION_LEGACY_DOM0) )
        {
            *hwdom = d;

            functions_used |= HL_FUNCTION_LEGACY_DOM0;
        }

        dom_count++;
    }

    return dom_count;
}

#endif
