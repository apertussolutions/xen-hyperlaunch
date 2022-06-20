#include <xen/bootdomain.h>
#include <xen/bootinfo.h>
#include <xen/domain_builder.h>
#include <xen/init.h>
#include <xen/types.h>

#include <asm/bzimage.h>
#include <asm/setup.h>

#include "fdt.h"

static struct domain_builder __initdata builder;

void __init builder_init(struct boot_info *info)
{
    struct boot_domain *d = NULL;

    info->builder = &builder;

    if ( IS_ENABLED(CONFIG_BUILDER_FDT) )
    {
        /* fdt is required to be module 0 */
        switch ( check_fdt(info, __va(info->mods[0].start)) )
        {
        case 0:
            printk("Domain Builder: initialized from config\n");
            info->builder->fdt_enabled = true;
            return;
        case -EINVAL:
            info->builder->fdt_enabled = false;
            break;
        case -ENODATA:
        default:
            panic("%s: error occured processing DTB\n", __func__);
        }
    }

    /*
     * No FDT config support or an FDT wasn't present, do an initial
     * domain construction
     */
    printk("Domain Builder: falling back to initial domain build\n");
    info->builder->nr_doms = 1;
    d = &info->builder->domains[0];

    d->mode = opt_dom0_pvh ? 0 : BUILD_MODE_PARAVIRTUALIZED;

    d->kernel = &info->mods[0];
    d->kernel->kind = BOOTMOD_KERNEL;

    d->permissions = BUILD_PERMISSION_CONTROL | BUILD_PERMISSION_HARDWARE;
    d->functions = BUILD_FUNCTION_CONSOLE | BUILD_FUNCTION_XENSTORE |
                     BUILD_FUNCTION_INITIAL_DOM;

    d->kernel->arch->headroom = bzimage_headroom(bootstrap_map(d->kernel),
                                                   d->kernel->size);
    bootstrap_map(NULL);

    if ( d->kernel->string.len )
        d->kernel->string.kind = BOOTSTR_CMDLINE;
}

uint32_t __init builder_create_domains(struct boot_info *info)
{
    uint32_t build_count = 0, functions_built = 0;
    int i;

    for ( i = 0; i < info->builder->nr_doms; i++ )
    {
        struct boot_domain *d = &info->builder->domains[i];

        if ( ! IS_ENABLED(CONFIG_MULTIDOM_BUILDER) &&
             ! builder_is_initdom(d) &&
             functions_built & BUILD_FUNCTION_INITIAL_DOM )
            continue;

        if ( d->kernel == NULL )
        {
            if ( builder_is_initdom(d) )
                panic("%s: intial domain missing kernel\n", __func__);

            printk(XENLOG_ERR "%s:Dom%d definiton has no kernel\n", __func__,
                    d->domid);
            continue;
        }

        arch_create_dom(info, d);
        if ( d->domain )
        {
            functions_built |= d->functions;
            build_count++;
        }
    }

    return build_count;
}
