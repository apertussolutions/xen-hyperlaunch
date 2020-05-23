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

#include <xen/init.h>
#include <xen/softirq.h>

#include <public/launch_control_module.h>

#include <asm/dom_build.h>
#include <asm/dom0_build.h> /* FIXME: for dom0_paging_pages */
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
     * The boot domain does not have hardware access, so a simple e820 map
     * should suffice.
     */
    /* FIXME: implement this */
}

static void __init boot_domain_init_p2m(struct domain *d,
    const struct lcm_domain_basic_config *cfg)
{
    /* TODO: validate cfg.mem_size; add some round up */
    unsigned long nr_pages = cfg->mem_size / PAGE_SIZE;
    bool preempted;

    boot_domain_setup_e820(d, nr_pages);
    do {
        preempted = false;
        paging_set_allocation(d, dom0_paging_pages(d, nr_pages),
                              &preempted);
        process_pending_softirqs();
    } while ( preempted );
}

int __init construct_pvh_boot_domain(struct domain *d,
                                     const module_t *lcm_image,
                                     const module_t *kernel_image,
                                     unsigned long image_headroom,
                                     const module_t *initrd,
                                     const char *cmdline)
{
    /*int rc;*/
    const struct lcm_domain_basic_config *boot_domain_cfg;

    printk(XENLOG_INFO "*** Building PVH Boot Domain ***\n");

    /* boot domain is not a hardware domain so not setting up mmcfg here */

    boot_domain_cfg = map_boot_domain_config(lcm_image);

    boot_domain_init_p2m(d, boot_domain_cfg);

    /* boot domain has no iommu access, so no init for that here */

    /* TODO: rc = pvh_populate_p2m(d);
    if ( rc )
    {
        printk("Failed to setup boot domain physical memory map\n");
        bootstrap_map(NULL);
        return rc;
    }*/

    /* TODO: load kernel */
    /* TODO: setup CPUs */
    /* TODO: setup ACPI */

    bootstrap_map(NULL);

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
