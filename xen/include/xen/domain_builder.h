/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XEN_DOMAIN_BUILDER_H
#define XEN_DOMAIN_BUILDER_H

#include <xen/bootdomain.h>
#include <xen/bootinfo.h>

#include <asm/setup.h>

struct domain_builder {
    bool fdt_enabled;
#define BUILD_MAX_BOOT_DOMAINS 64
    uint16_t nr_doms;
    struct boot_domain domains[BUILD_MAX_BOOT_DOMAINS];

    struct arch_domain_builder *arch;
};

static inline bool builder_is_initdom(struct boot_domain *bd)
{
    return bd->functions & BUILD_FUNCTION_INITIAL_DOM;
}

static inline bool builder_is_ctldom(struct boot_domain *bd)
{
    return (bd->functions & BUILD_FUNCTION_INITIAL_DOM ||
            bd->permissions & BUILD_PERMISSION_CONTROL );
}

static inline bool builder_is_hwdom(struct boot_domain *bd)
{
    return (bd->functions & BUILD_FUNCTION_INITIAL_DOM ||
            bd->permissions & BUILD_PERMISSION_HARDWARE );
}

static inline struct domain *builder_get_hwdom(struct boot_info *info)
{
    int i;

    for ( i = 0; i < info->builder->nr_doms; i++ )
    {
        struct boot_domain *d = &info->builder->domains[i];

        if ( builder_is_hwdom(d) )
            return d->domain;
    }

    return NULL;
}

void builder_init(struct boot_info *info);
uint32_t builder_create_domains(struct boot_info *info);

#endif /* XEN_DOMAIN_BUILDER_H */
