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

#include <xen/acpi.h>
#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/softirq.h>

#include <acpi/actables.h>

#include <public/launch_control_module.h>
#include <public/hvm/e820.h>
#include <public/hvm/hvm_vcpu.h>
#include <public/arch-x86/hvm/start_info.h>

#include <asm/dom_build.h>
#include <asm/dom0_build.h> /* FIXME: for dom0_paging_pages */
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/setup.h>
#include <asm/hvm/support.h>

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

static __init const struct lcm_domain_basic_config *map_basic_domain_config(
    const module_t *lcm_image, unsigned int dom_idx)
{
    void *image_start;
    struct lcm_header_info *hdr;
    const struct lcm_entry *entry;
    unsigned int consumed, cur_idx;

    image_start = bootstrap_map(lcm_image);
    hdr = (struct lcm_header_info *)image_start;

    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);
    for ( cur_idx = 0; ; cur_idx++ )
    {
        if ( (entry->len + consumed) == hdr->total_len )
            break;

        if ( (entry->type == LCM_DATA_DOMAIN) &&
             (entry->domain.flags | LCM_DOMAIN_HAS_BASIC_CONFIG) &&
             (cur_idx == dom_idx) )
            return &entry->domain.basic_config;

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }
    panic("Failed to find domain config %u in LCM\n", dom_idx);
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

/* Steal RAM from the end of a memory region. */
static int __init pvh_steal_ram(struct domain *d, unsigned long size,
                                unsigned long align, paddr_t limit,
                                paddr_t *addr)
{
    unsigned int i = d->arch.nr_e820;

    /*
     * Alignment 0 should be set to 1, so it doesn't wrap around in the
     * calculations below.
     */
    align = align ? : 1;
    while ( i-- )
    {
        struct e820entry *entry = &d->arch.e820[i];

        if ( entry->type != E820_RAM || entry->addr + entry->size > limit )
            continue;

        *addr = (entry->addr + entry->size - size) & ~(align - 1);
        if ( *addr < entry->addr ||
             /* Don't steal from the low 1MB due to the copying done there. */
             *addr < MB(1) )
            continue;

        entry->size = *addr - entry->addr;
        return 0;
    }

    return -ENOMEM;
}

/* NB: memory map must be sorted at all times for this to work correctly. */
static int __init pvh_add_mem_range(struct domain *d, uint64_t s, uint64_t e,
                                    unsigned int type)
{
    struct e820entry *map;
    unsigned int i;

    for ( i = 0; i < d->arch.nr_e820; i++ )
    {
        uint64_t rs = d->arch.e820[i].addr;
        uint64_t re = rs + d->arch.e820[i].size;

        if ( rs == e && d->arch.e820[i].type == type )
        {
            d->arch.e820[i].addr = s;
            return 0;
        }

        if ( re == s && d->arch.e820[i].type == type &&
             (i + 1 == d->arch.nr_e820 || d->arch.e820[i + 1].addr >= e) )
        {
            d->arch.e820[i].size += e - s;
            return 0;
        }

        if ( rs >= e )
            break;

        if ( re > s )
            return -EEXIST;
    }

    map = xzalloc_array(struct e820entry, d->arch.nr_e820 + 1);
    if ( !map )
    {
        printk(XENLOG_WARNING "E820: out of memory to add region\n");
        return -ENOMEM;
    }

    memcpy(map, d->arch.e820, i * sizeof(*d->arch.e820));
    memcpy(map + i + 1, d->arch.e820 + i,
           (d->arch.nr_e820 - i) * sizeof(*d->arch.e820));
    map[i].addr = s;
    map[i].size = e - s;
    map[i].type = type;
    xfree(d->arch.e820);
    d->arch.e820 = map;
    d->arch.nr_e820++;

    return 0;
}

static int __init boot_domain_setup_acpi_madt(struct domain *d, paddr_t *addr)
{
    struct acpi_table_madt *madt;
    struct acpi_table_header *table;
    struct acpi_madt_local_x2apic *x2apic;
    acpi_status status;
    unsigned long size;
    int rc;

    /* Calculate the size of the crafted MADT. */
    size = sizeof(*madt);
    size += sizeof(*x2apic); /* Only one vCPU */

    madt = xzalloc_bytes(size);
    if ( !madt )
    {
        printk("Unable to allocate memory for MADT table\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Copy the native MADT table header. */
    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);
    if ( !ACPI_SUCCESS(status) )
    {
        printk("Failed to get MADT ACPI table, aborting.\n");
        rc = -EINVAL;
        goto out;
    }
    madt->header = *table;
    madt->address = APIC_DEFAULT_PHYS_BASE;
    /*
     * NB: this is currently set to 4, which is the revision in the ACPI
     * spec 6.1. Sadly ACPICA doesn't provide revision numbers for the
     * tables described in the headers.
     */
    madt->header.revision = min_t(unsigned char, table->revision, 4);

    x2apic = (void *)(madt + 1);

    x2apic->header.type = ACPI_MADT_TYPE_LOCAL_X2APIC;
    x2apic->header.length = sizeof(*x2apic);
    x2apic->uid = 0;
    x2apic->local_apic_id = 0;
    x2apic->lapic_flags = ACPI_MADT_ENABLED;

    /* TODO: should maintain the ASSERT pointer diff with size */
    madt->header.length = size;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    madt->header.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, madt), size);

    /* Place the new MADT in guest memory space. */
    if ( pvh_steal_ram(d, size, 0, GB(4), addr) )
    {
        printk("Unable to steal guest RAM for MADT\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, *addr, *addr + size, E820_ACPI) )
        printk("Unable to add MADT region to memory map\n");

    rc = hvm_copy_to_guest_phys(*addr, madt, size, d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy MADT into guest memory\n");
        goto out;
    }

    rc = 0;

 out:
    xfree(madt);

    return rc;
}

static int __init boot_domain_setup_acpi_xsdt(struct domain *d, paddr_t madt_addr,
                                      paddr_t *addr)
{
    struct acpi_table_xsdt *xsdt;
    struct acpi_table_header *table;
    struct acpi_table_rsdp *rsdp;
    unsigned long size = sizeof(*xsdt);
    unsigned int num_tables = 0;
    paddr_t xsdt_paddr;
    int rc;

    /*
     * Restore original DMAR table signature, we are going to filter it from
     * the new XSDT that is presented to the guest, so it is no longer
     * necessary to have it's signature zapped.
     */
    acpi_dmar_reinstate();

    /* Only adding the MADT table to the XSDT. */
    num_tables = 1;

    /*
     * No need to add or subtract anything because struct acpi_table_xsdt
     * includes one array slot already, and we have filtered out the original
     * MADT and we are going to add a custom built MADT.
     */
    size += num_tables * sizeof(xsdt->table_offset_entry[0]);

    xsdt = xzalloc_bytes(size);
    if ( !xsdt )
    {
        printk("Unable to allocate memory for XSDT table\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Copy the native XSDT table header. */
    rsdp = acpi_os_map_memory(acpi_os_get_root_pointer(), sizeof(*rsdp));
    if ( !rsdp )
    {
        printk("Unable to map RSDP\n");
        rc = -EINVAL;
        goto out;
    }
    xsdt_paddr = rsdp->xsdt_physical_address;
    acpi_os_unmap_memory(rsdp, sizeof(*rsdp));
    table = acpi_os_map_memory(xsdt_paddr, sizeof(*table));
    if ( !table )
    {
        printk("Unable to map XSDT\n");
        rc = -EINVAL;
        goto out;
    }
    xsdt->header = *table;
    acpi_os_unmap_memory(table, sizeof(*table));

    /* Add the custom MADT. */
    xsdt->table_offset_entry[0] = madt_addr;

    xsdt->header.revision = 1;
    xsdt->header.length = size;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    xsdt->header.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, xsdt), size);

    /* Place the new XSDT in guest memory space. */
    if ( pvh_steal_ram(d, size, 0, GB(4), addr) )
    {
        printk("Unable to find guest RAM for XSDT\n");
        rc = -ENOMEM;
        goto out;
    }

    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, *addr, *addr + size, E820_ACPI) )
        printk("Unable to add XSDT region to memory map\n");

    rc = hvm_copy_to_guest_phys(*addr, xsdt, size, d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy XSDT into guest memory\n");
        goto out;
    }

    rc = 0;

 out:
    xfree(xsdt);

    return rc;
}
static int __init boot_domain_setup_acpi(struct domain *d, paddr_t start_info)
{
    paddr_t madt_paddr, xsdt_paddr, rsdp_paddr;
    int rc;
    struct acpi_table_rsdp *native_rsdp, rsdp = {
        .signature = ACPI_SIG_RSDP,
        .revision = 2,
        .length = sizeof(rsdp),
    };

    rc = boot_domain_setup_acpi_madt(d, &madt_paddr);
    if ( rc )
        return rc;

    rc = boot_domain_setup_acpi_xsdt(d, madt_paddr, &xsdt_paddr);
    if ( rc )
        return rc;

    /* Craft a custom RSDP. */
    native_rsdp = acpi_os_map_memory(acpi_os_get_root_pointer(), sizeof(rsdp));
    if ( !native_rsdp )
    {
        printk("Failed to map native RSDP\n");
        return -ENOMEM;
    }
    memcpy(rsdp.oem_id, native_rsdp->oem_id, sizeof(rsdp.oem_id));
    acpi_os_unmap_memory(native_rsdp, sizeof(rsdp));
    rsdp.xsdt_physical_address = xsdt_paddr;
    /*
     * Calling acpi_tb_checksum here is a layering violation, but
     * introducing a wrapper for such simple usage seems overkill.
     */
    rsdp.checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, &rsdp),
                                      ACPI_RSDP_REV0_SIZE);
    rsdp.extended_checksum -= acpi_tb_checksum(ACPI_CAST_PTR(u8, &rsdp),
                                               sizeof(rsdp));

    /*
     * Place the new RSDP in guest memory space.
     *
     * NB: this RSDP is not going to replace the original RSDP, which should
     * still be accessible to the guest. However that RSDP is going to point to
     * the native RSDT, and should not be used for the Dom0 kernel's boot
     * purposes (we keep it visible for post boot access).
     */
    if ( pvh_steal_ram(d, sizeof(rsdp), 0, GB(4), &rsdp_paddr) )
    {
        printk("Unable to allocate guest RAM for RSDP\n");
        return -ENOMEM;
    }
    /* Mark this region as E820_ACPI. */
    if ( pvh_add_mem_range(d, rsdp_paddr, rsdp_paddr + sizeof(rsdp),
                           E820_ACPI) )
        printk("Unable to add RSDP region to memory map\n");

    /* Copy RSDP into guest memory. */
    rc = hvm_copy_to_guest_phys(rsdp_paddr, &rsdp, sizeof(rsdp), d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy RSDP into guest memory\n");
        return rc;
    }

    /* Copy RSDP address to start_info. */
    rc = hvm_copy_to_guest_phys(start_info +
                                offsetof(struct hvm_start_info, rsdp_paddr),
                                &rsdp_paddr,
                                sizeof(((struct hvm_start_info *)
                                        0)->rsdp_paddr),
                                d->vcpu[0]);
    if ( rc )
    {
        printk("Unable to copy RSDP address to start info\n");
        return rc;
    }

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

    memcpy(d->handle, boot_domain_cfg.domain_handle,
           sizeof(xen_domain_handle_t));

    boot_domain_init_p2m(d, &boot_domain_cfg);

    /* boot domain has no iommu access, so no init for that here */

    rc = boot_domain_populate_p2m(d);
    if ( rc )
    {
        printk("Failed to setup boot domain physical memory map\n");
        bootstrap_map(NULL);
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
    boot_domain_setup_acpi(d, start_info);
    return 0;
}

int __init construct_pvh_initial_domain(struct domain *d,
                                        const module_t *lcm_image,
                                        unsigned int lcm_dom_idx,
                                        const module_t *kernel_image,
                                        unsigned long image_headroom,
                                        const module_t *initrd,
                                        char *cmdline)
{
    int rc;
    struct lcm_domain_basic_config basic_cfg;
    paddr_t entry, start_info;

    printk(XENLOG_INFO "--- Building a PVH Initial Domain, domid: %d ---\n",
           d->domain_id);
           /* TODO: display a better identifier here: add a 'name' string
            * to basic_config? */

    /*
     * TODO: initial domains are not currently supposed as hardware domains
     *        so not setting up mmcfg here
     */

    basic_cfg = *map_basic_domain_config(lcm_image, lcm_dom_idx);
    bootstrap_map(NULL);

    memcpy(d->handle, basic_cfg.domain_handle,
           sizeof(xen_domain_handle_t));

    /*
     * TODO: memory calc for boot dom is likely different (simpler)
     *       than for other domains; so a separate function makes sense
     */
    boot_domain_init_p2m(d, &basic_cfg);

    /* boot domain has no iommu access, so no init for that here */

    /*
     * TODO: for domains with hardware, will need more complex p2m;
     *       for now, reuse the simple boot domain logic
     */
    rc = boot_domain_populate_p2m(d);
    if ( rc )
    {
        printk("Failed to setup initial domain (%d) physical memory map\n",
               d->domain_id); /* FIXME: name identifier instead of domid */
        return rc;
    }

    rc = pvh_load_kernel(d, kernel_image, image_headroom, initrd,
                         bootstrap_map(kernel_image),
                         cmdline, &entry, &start_info);
    bootstrap_map(NULL);
    if ( rc )
    {
        printk("Failed to load initial domain kernel\n");
        return rc;
    }

    /*
     * FIXME: boot domain only has a single VCPU; more setup appropriate
     *        for the other initial domains (unless the boot domain does it)
     */
    rc = boot_domain_setup_cpus(d, entry, start_info);
    if ( rc )
    {
        printk("Failed to setup initial domain CPUs, rc: %d\n", rc);
        return rc;
    }

    /* TODO: setup ACPI */
    boot_domain_setup_acpi(d, start_info);
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
