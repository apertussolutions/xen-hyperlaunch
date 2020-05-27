/*
 * hvm/dom_build.c
 *
 * Domain builder for PVH guest.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 * Copyright (C) 2020 Star Lab Corp
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/softirq.h>

#include <public/launch_control_module.h>
#include <public/hvm/e820.h>
#include <public/hvm/hvm_vcpu.h>

#include <asm/dom_build.h>
#include <asm/dom0_build.h> /* FIXME: for dom0_paging_pages, pvh_populate_memory_range */
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/setup.h>

static __init const struct lcm_domain_basic_config *map_boot_domain_config(
    const module_t *lcm_image)
{
    void *image_start;
    struct lcm_header_info *hdr;
    const struct lcm_entry *entry;
    unsigned int consumed;

    image_start = bootstrap_map(lcm_image);
    hdr = (struct lcm_header_info *)image_start;

    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);
    for ( ; ; )
    {
        if ( (entry->len + consumed) == hdr->total_len )
            break;

        if ( (entry->type == LCM_DATA_DOMAIN) &&
             (entry->domain.flags | LCM_DOMAIN_HAS_BASIC_CONFIG) &&
             (entry->domain.basic_config.functions | LCM_DOMAIN_FUNCTION_BOOT) )
            return &entry->domain.basic_config;

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }
    panic("Failed to find boot domain config in LCM\n");
}

static void __init boot_domain_setup_e820(struct domain *d,
                                          unsigned long nr_pages)
{
    /*
     * The boot domain does not have hardware access, so a simple fixed
     * e820 map should suffice.
     */
    /*
     * References:
     * - dmesg and look for e820 examples
     * - xen/arch/x86/hvm/dom0_build.c
     * - tools/libxl/libxl_x86.c
     * - firmware/hvmloader/e820.c
     */
    /* TODO: revisit all values and calculations here */

    const uint32_t lowmem_reserved_base = 0x9e000; /* TODO: check this */
    const uint32_t bios_image_base = 0xf0000; /* TODO: check this */

    unsigned long low_pages, ext_pages, max_ext_pages, high_pages;
    unsigned long cur_pages = 0;
    unsigned nr = 0, e820_entries = 5;

    /* low pages: below 1MB */
    low_pages = lowmem_reserved_base >> PAGE_SHIFT;
    if ( low_pages > nr_pages )
        panic("Insufficient memory assigned to the boot domain\n");

    /* max_ext_pages: maximum size of extended memory range */
    max_ext_pages = (HVM_BELOW_4G_MMIO_START - MB(1)) >> PAGE_SHIFT;

    /* ext pages: from 1MB to mmio hole */
    ext_pages = nr_pages - low_pages;
    if ( ext_pages > max_ext_pages )
        ext_pages = max_ext_pages;

    /* high pages: above 4GB */
    high_pages = 0;
    if ( nr_pages > (low_pages + ext_pages) )
        high_pages = nr_pages - (low_pages + ext_pages);

    /* If we should have a highmem range, add one more e820 entry */
    if ( high_pages )
        e820_entries++;

    ASSERT(e820_entries < E820MAX);

    d->arch.e820 = xzalloc_array(struct e820entry, e820_entries);
    if ( !d->arch.e820 )
        panic("Unable to allocate memory for boot domain e820 map\n");

    /* usable: Low memory */
    d->arch.e820[nr].addr = 0x000000;
    d->arch.e820[nr].size = lowmem_reserved_base;
    d->arch.e820[nr].type = E820_RAM;
    cur_pages += (d->arch.e820[nr].size) >> PAGE_SHIFT;
    nr++;

    /* reserved: lowmem_reserved_base-0xA0000: BIOS implementation */
    d->arch.e820[nr].addr = lowmem_reserved_base;
    d->arch.e820[nr].size = 0xA0000 - lowmem_reserved_base;
    d->arch.e820[nr].type = E820_RESERVED;
    nr++;

    /* gap from 0xA0000 to bios_image_base */

    /* reserved: BIOS region */
    d->arch.e820[nr].addr = bios_image_base;
    d->arch.e820[nr].size = 0x100000 - bios_image_base;
    d->arch.e820[nr].type = E820_RESERVED;
    nr++;

    /* usable: extended memory from 1MB */
    d->arch.e820[nr].addr = 0x100000;
    d->arch.e820[nr].size = ext_pages << PAGE_SHIFT;
    d->arch.e820[nr].type = E820_RAM;
    cur_pages += (d->arch.e820[nr].size) >> PAGE_SHIFT;
    nr++;

    /* reserved: mmio range, up to 4G */
    /* TODO: check: is one large entry right here? examples seem to have two */
    /* TODO: check: is blocking this entire range correct, or are gaps needed? */
    d->arch.e820[nr].addr = HVM_BELOW_4G_MMIO_START;
    d->arch.e820[nr].size = HVM_BELOW_4G_MMIO_LENGTH;
    d->arch.e820[nr].type = E820_RESERVED;
    nr++;

    /* usable: highmem */
    if ( high_pages )
    {
        d->arch.e820[nr].addr = 0x100000000;
        d->arch.e820[nr].size = high_pages << PAGE_SHIFT;
        d->arch.e820[nr].type = E820_RAM;
        cur_pages += (d->arch.e820[nr].size) >> PAGE_SHIFT;
        nr++;
    }

    d->arch.nr_e820 = nr;

    ASSERT(nr == e820_entries);
    ASSERT(cur_pages == nr_pages);
}

static void __init boot_domain_init_p2m(struct domain *d,
    const struct lcm_domain_basic_config *cfg)
{
    /* TODO: validate cfg.mem_size; add some round up */
    /*unsigned long nr_pages = cfg->mem_size / PAGE_SIZE;*/
    unsigned long nr_pages = dom0_compute_nr_pages(d, NULL, 0);
    bool preempted;

    boot_domain_setup_e820(d, nr_pages);
    do {
        preempted = false;
        paging_set_allocation(d, dom0_paging_pages(d, nr_pages),
                              &preempted);
        process_pending_softirqs();
    } while ( preempted );
}

static int __init boot_domain_populate_p2m(struct domain *d)
{
    unsigned int i;
    int rc;

    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        unsigned long addr, size;

        if ( d->arch.e820[i].type != E820_RAM )
            continue;

        addr = PFN_DOWN(d->arch.e820[i].addr);
        size = PFN_DOWN(d->arch.e820[i].size);

        rc = pvh_populate_memory_range(d, addr, size);
        if ( rc )
            return rc;
    }

    return 0;
}

static int __init boot_domain_setup_cpus(struct domain *d, paddr_t entry,
                                         paddr_t start_info)
{
    struct vcpu *v = d->vcpu[0];
    int rc;
    /*
     * This sets the vCPU state according to the state described in
     * docs/misc/pvh.pandoc.
     */
    vcpu_hvm_context_t cpu_ctx = {
        .mode = VCPU_HVM_MODE_32B,
        .cpu_regs.x86_32.ebx = start_info,
        .cpu_regs.x86_32.eip = entry,
        .cpu_regs.x86_32.cr0 = X86_CR0_PE | X86_CR0_ET,
        .cpu_regs.x86_32.cs_limit = ~0u,
        .cpu_regs.x86_32.ds_limit = ~0u,
        .cpu_regs.x86_32.es_limit = ~0u,
        .cpu_regs.x86_32.ss_limit = ~0u,
        .cpu_regs.x86_32.tr_limit = 0x67,
        .cpu_regs.x86_32.cs_ar = 0xc9b,
        .cpu_regs.x86_32.ds_ar = 0xc93,
        .cpu_regs.x86_32.es_ar = 0xc93,
        .cpu_regs.x86_32.ss_ar = 0xc93,
        .cpu_regs.x86_32.tr_ar = 0x8b,
    };

    sched_setup_boot_domain_vcpu(d);

    rc = arch_set_info_hvm_guest(v, &cpu_ctx);
    if ( rc )
    {
        printk("Unable to setup boot domain BSP context: %d\n", rc);
        return rc;
    }

    /* TODO: any permission initialization needed here? */

    update_domain_wallclock_time(d);

    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

    return 0;
}

int __init construct_pvh_boot_domain(struct domain *d,
                                     const module_t *lcm_image,
                                     const module_t *kernel_image,
                                     unsigned long image_headroom,
                                     const module_t *initrd,
                                     char *cmdline)
{
    int rc;
    struct lcm_domain_basic_config boot_domain_cfg;
    paddr_t entry, start_info;

    printk(XENLOG_INFO "*** Building PVH Boot Domain ***\n");

    /* boot domain is not a hardware domain so not setting up mmcfg here */

    boot_domain_cfg = *map_boot_domain_config(lcm_image);
    bootstrap_map(NULL);

    boot_domain_init_p2m(d, &boot_domain_cfg);

    /* boot domain has no iommu access, so no init for that here */

    rc = boot_domain_populate_p2m(d);
    if ( rc )
    {
        printk("Failed to setup boot domain physical memory map\n");
        return rc;
    }

    rc = pvh_load_kernel(d, kernel_image, image_headroom, initrd,
                         bootstrap_map(kernel_image),
                         cmdline, &entry, &start_info);
    bootstrap_map(NULL);
    if ( rc )
    {
        printk("Failed to load boot domain kernel\n");
        return rc;
    }

    rc = boot_domain_setup_cpus(d, entry, start_info);
    if ( rc )
    {
        printk("Failed to setup boot domain CPUs: %d\n", rc);
        return rc;
    }

    /* TODO: setup ACPI */

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
