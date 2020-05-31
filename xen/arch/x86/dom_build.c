/******************************************************************************
 * dom_build.c
 *
 * Copyright (c) 2020, Star Lab Corp
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/softirq.h>

#include <asm/dom_build.h>
#include <asm/setup.h>

int __init construct_boot_domain(struct domain *d,
                                 const module_t *lcm,
                                 const module_t *kernel,
                                 unsigned long image_headroom,
                                 const module_t *initrd, char *cmdline)
{
#ifdef CONFIG_BOOT_DOMAIN
    int rc;

    /* Sanity! */
    BUG_ON(d->domain_id != DOMID_BOOT_DOMAIN);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(d->vcpu[0]->is_initialised);

    process_pending_softirqs();

    if ( is_hvm_domain(d) )
        rc = construct_pvh_boot_domain(d, lcm, kernel, image_headroom, initrd,
                                       cmdline);
    else if ( is_pv_domain(d) )
        panic("Cannot construct a PV boot domain\n");
    else
        panic("Cannot construct boot domain. No guest interface available\n");

    if ( rc )
        return rc;

    /* Sanity! */
    BUG_ON(!d->vcpu[0]->is_initialised);
#else
    ASSERT_UNREACHABLE();
#endif
    return 0;
}

int __init construct_initial_domain(struct domain *d,
                                    const module_t *lcm,
                                    unsigned int lcm_dom_idx,
                                    const module_t *kernel,
                                    unsigned long image_headroom,
                                    const module_t *initrd, char *cmdline)
{
#ifdef CONFIG_BOOT_DOMAIN
    int rc;

    /* Sanity! */
    BUG_ON(d->domain_id == DOMID_BOOT_DOMAIN);
    BUG_ON(d->domain_id == 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(d->vcpu[0]->is_initialised);

    process_pending_softirqs();

    if ( is_hvm_domain(d) )
        rc = construct_pvh_initial_domain(d, lcm, lcm_dom_idx, kernel,
                                          image_headroom, initrd, cmdline);
    else if ( is_pv_domain(d) )
        panic("Cannot construct a PV initial domain\n");
    else
        panic("Cannot construct initial domain with unknown guest interface.\n");

    if ( rc )
        return rc;

    /* Sanity! */
    BUG_ON(!d->vcpu[0]->is_initialised);
#else
    ASSERT_UNREACHABLE();
#endif
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
