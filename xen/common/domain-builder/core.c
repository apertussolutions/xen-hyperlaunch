#include <xen/bootdomain.h>
#include <xen/bootinfo.h>
#include <xen/domain_builder.h>
#include <xen/event.h>
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

static bool __init build_domain(struct boot_info *info, struct boot_domain *bd)
{
    if ( bd->constructed == true )
        return true;

    if ( bd->kernel == NULL )
        return false;

    printk(XENLOG_INFO "*** Building Dom%d ***\n", bd->domid);

    arch_create_dom(info, bd);
    if ( bd->domain )
    {
        bd->constructed = true;
        return true;
    }

    return false;
}

uint32_t __init builder_create_domains(struct boot_info *info)
{
    uint32_t build_count = 0, functions_built = 0;
    struct boot_domain *bd;
    int i;

    if ( IS_ENABLED(CONFIG_MULTIDOM_BUILDER) )
    {
        bd = builder_dom_by_function(info, BUILD_FUNCTION_XENSTORE);
        if ( build_domain(info, bd) )
        {
            functions_built |= bd->functions;
            build_count++;
        }
        else
            printk(XENLOG_WARNING "Xenstore build failed, system may be unusable\n");

        bd = builder_dom_by_function(info, BUILD_FUNCTION_CONSOLE);
        if ( build_domain(info, bd) )
        {
            functions_built |= bd->functions;
            build_count++;
        }
        else
            printk(XENLOG_WARNING "Console build failed, system may be unusable\n");
    }

    for ( i = 0; i < info->builder->nr_doms; i++ )
    {
        bd = &info->builder->domains[i];

        if ( ! IS_ENABLED(CONFIG_MULTIDOM_BUILDER) &&
             ! builder_is_initdom(bd) &&
             functions_built & BUILD_FUNCTION_INITIAL_DOM )
            continue;

        if ( !build_domain(info, bd) )
        {
            if ( builder_is_initdom(bd) )
                panic("%s: intial domain missing kernel\n", __func__);

            printk(XENLOG_WARNING "Dom%d build failed, skipping\n", bd->domid);
            continue;
        }

        functions_built |= bd->functions;
        build_count++;
    }

    if ( IS_ENABLED(CONFIG_X86) )
        /* Free temporary buffers. */
        discard_initial_images();

    if ( IS_ENABLED(CONFIG_BUILDER_HYPFS) )
        builder_hypfs(info);

    return build_count;
}

domid_t __init get_next_domid(void)
{
    static domid_t __initdata last_domid = 0;
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

int __init alloc_system_evtchn(
    const struct boot_info *info, struct boot_domain *bd)
{
    evtchn_alloc_unbound_t evtchn_req;
    struct boot_domain *c = builder_dom_by_function(info,
                                                    BUILD_FUNCTION_CONSOLE);
    struct boot_domain *s = builder_dom_by_function(info,
                                                    BUILD_FUNCTION_XENSTORE);
    int rc;

    evtchn_req.dom = bd->domid;

    if ( c != NULL && c != bd && c->constructed )
    {
        evtchn_req.remote_dom = c->domid;

        rc = evtchn_alloc_unbound(&evtchn_req);
        if ( rc )
        {
            printk("Failed allocating console event channel for domain %d\n",
                   bd->domid);
            return rc;
        }

        bd->console.evtchn = evtchn_req.port;
    }

    if ( s != NULL && s != bd && s->constructed )
    {
        evtchn_req.remote_dom = s->domid;

        rc = evtchn_alloc_unbound(&evtchn_req);
        if ( rc )
        {
            printk("Failed allocating xenstore event channel for domain %d\n",
                   bd->domid);
            return rc;
        }

        bd->store.evtchn = evtchn_req.port;
    }

    return 0;
}
