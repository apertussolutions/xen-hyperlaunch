#include <xen/bootdomain.h>
#include <xen/bootinfo.h>
#include <xen/domain.h>
#include <xen/domain_builder.h>
#include <xen/err.h>
#include <xen/grant_table.h>
#include <xen/iommu.h>
#include <xen/sched.h>

#include <asm/pv/shim.h>
#include <asm/setup.h>

extern unsigned long cr4_pv32_mask;

static unsigned int __init dom_max_vcpus(struct boot_domain *bd)
{
    unsigned int limit;

    if ( builder_is_initdom(bd) )
        return dom0_max_vcpus();

    limit = bd->mode & BUILD_MODE_PARAVIRTUALIZED ?
                MAX_VIRT_CPUS : HVM_MAX_VCPUS;

    if ( bd->ncpus > limit )
        return limit;
    else
        return bd->ncpus;
}

struct vcpu *__init alloc_dom_vcpu0(struct boot_domain *bd)
{
    if ( bd->functions & BUILD_FUNCTION_INITIAL_DOM )
        return alloc_dom0_vcpu0(bd->domain);

    bd->domain->node_affinity = node_online_map;
    bd->domain->auto_node_affinity = true;

    return vcpu_create(bd->domain, 0);
}


void __init arch_create_dom(
    const struct boot_info *bi, struct boot_domain *bd)
{
    struct xen_domctl_createdomain dom_cfg = {
        .flags = IS_ENABLED(CONFIG_TBOOT) ? XEN_DOMCTL_CDF_s3_integrity : 0,
        .max_evtchn_port = -1,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
        .max_vcpus = dom_max_vcpus(bd),
        .arch = {
            .misc_flags = bd->functions & BUILD_FUNCTION_INITIAL_DOM &&
                           opt_dom0_msr_relaxed ? XEN_X86_MSR_RELAXED : 0,
        },
    };
    unsigned int is_privileged = 0;
    char *cmdline;

    if ( bd->kernel == NULL )
        panic("Error creating d%uv0\n", bd->domid);

    /* mask out PV and device model bits, if 0 then the domain is PVH */
    if ( !(bd->mode &
           (BUILD_MODE_PARAVIRTUALIZED|BUILD_MODE_ENABLE_DEVICE_MODEL)) )
    {
        dom_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                         (hvm_hap_supported() ? XEN_DOMCTL_CDF_hap : 0));

        /*
         * If shadow paging is enabled for the initial domain, mask out
         * HAP if it was just enabled.
         */
        if ( builder_is_initdom(bd) )
            if ( opt_dom0_shadow )
                dom_cfg.flags |= ~XEN_DOMCTL_CDF_hap;

        /* TODO: review which flags should be present */
        dom_cfg.arch.emulation_flags |=
            XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
    }

    if ( iommu_enabled && builder_is_hwdom(bd) )
        dom_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    if ( !pv_shim && builder_is_ctldom(bd) )
        is_privileged = CDF_privileged;

    /* Create initial domain.  Not d0 for pvshim. */
    bd->domid = get_initial_domain_id();
    bd->domain = domain_create(bd->domid, &dom_cfg, is_privileged);
    if ( IS_ERR(bd->domain) )
        panic("Error creating d%u: %ld\n", bd->domid, PTR_ERR(bd->domain));

    init_dom0_cpuid_policy(bd->domain);

    if ( alloc_dom_vcpu0(bd) == NULL )
        panic("Error creating d%uv0\n", bd->domid);

    /* Grab the DOM0 command line. */
    cmdline = (bd->kernel->string.kind == BOOTSTR_CMDLINE) ?
              bd->kernel->string.bytes : NULL;
    if ( cmdline || bi->arch->kextra )
    {
        char dom_cmdline[MAX_GUEST_CMDLINE];

        cmdline = arch_prepare_cmdline(cmdline, bi->arch);
        strlcpy(dom_cmdline, cmdline, MAX_GUEST_CMDLINE);

        if ( bi->arch->kextra )
            /* kextra always includes exactly one leading space. */
            strlcat(dom_cmdline, bi->arch->kextra, MAX_GUEST_CMDLINE);

        apply_xen_cmdline(dom_cmdline);

        strlcpy(bd->kernel->string.bytes, dom_cmdline, MAX_GUEST_CMDLINE);
    }

    /*
     * Temporarily clear SMAP in CR4 to allow user-accesses in construct_dom0().
     * This saves a large number of corner cases interactions with
     * copy_from_user().
     */
    if ( cpu_has_smap )
    {
        cr4_pv32_mask &= ~X86_CR4_SMAP;
        write_cr4(read_cr4() & ~X86_CR4_SMAP);
    }

    if ( construct_domain(bd) != 0 )
        panic("Could not construct domain 0\n");

    if ( cpu_has_smap )
    {
        write_cr4(read_cr4() | X86_CR4_SMAP);
        cr4_pv32_mask |= X86_CR4_SMAP;
    }
}

