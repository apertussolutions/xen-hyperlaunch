
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xenhypfs.h>
#include <xenstore.h>
#include <xentoollog.h>
#include <xen/io/xenbus.h>

#include "hypfs-helpers.h"
#include "late-init-pv.h"
#include "xs-helpers.h"

static struct option options[] = {
    { "uuid", 1, NULL, 'u' },
    { "console", 0, NULL, 'c' },
    { "force", 0, NULL, 'f' },
    { "domain", 1, NULL, 'd' },
    { "verbose", 0, NULL, 'v' },
    { NULL, 0, NULL, 0 }
};

static void usage(void)
{
    fprintf(stderr,
"Usage:\n"
"\n"
"late-init-pv <options>\n"
"\n"
"where options may include:\n"
"\n"
"  --uuid <UUID string>     override the UUID to use for the domain\n"
"  --console                configure the console\n"
"  --force                  for @introduceDomain even if xenstore entries exist\n"
"  --domain <domain id>     domain id of the domain to be initialized\n"
"  -v[v[v]]                 verbosity constructing xenstore tree\n");
}

#define XS_DOM_PERM(x, d, k, v)                                             \
    ret = do_xs_write_dom_with_perm(x, d, k, v, perms, num_perms);          \
    if ( ret != 0 ) return ret                                              \

#define XS_DIR_PERM(x, p, k, v)                                             \
    ret = do_xs_write_dir_node_with_perm(x, p, k, v, perms, num_perms);     \
    if ( ret != 0 ) return ret                                              \

static int create_xs_entries(
    struct xs_handle *xsh, uint16_t curr_domid, struct domain_info *di)
{
    char value[16];
    struct xs_permissions perms[2] = {
        {.id = curr_domid, .perms = XS_PERM_NONE},
        {.id = di->domid, .perms = XS_PERM_READ},
    };
    uint32_t num_perms = (sizeof(perms) / sizeof((perms)[0]));
    int ret = 0;

    while ( do_xs_start_transaction(xsh) == 0 )
    {
        XS_DOM_PERM(xsh, di->domid, "", "");

        snprintf(value, 16, "%d", di->domid);
        XS_DOM_PERM(xsh, di->domid, "domid", value);

        XS_DOM_PERM(xsh, di->domid, "memory", "");
        snprintf(value, 16, "%d", di->mem_info.target);
        XS_DOM_PERM(xsh, di->domid, "memory/target", value);

        if ( di->mem_info.max )
            snprintf(value, 16, "%d", di->mem_info.max);
        else
            snprintf(value, 16, "%d", di->mem_info.target);
        XS_DOM_PERM(xsh, di->domid, "memory/static-max", value);

        XS_DOM_PERM(xsh, di->domid, "store", "");
        snprintf(value, 16, "%d", di->xs_info.evtchn_port);
        XS_DOM_PERM(xsh, di->domid, "store/port", value);

        snprintf(value, 16, "%ld", di->xs_info.mfn);
        XS_DOM_PERM(xsh, di->domid, "store/ring-ref", value);

        if ( di->cons_info.enable )
        {
            char be_path[64], fe_path[64];

            snprintf(fe_path, 64, "/local/domain/%d/console", di->domid);
            snprintf(be_path, 64, "/local/domain/%d/backend/console/%d/0",
                     di->cons_info.be_domid, di->domid);

            /* Backend entries */
            XS_DIR_PERM(xsh, be_path, "", "");
            snprintf(value, 16, "%d", di->domid);
            XS_DIR_PERM(xsh, be_path, "frontend-id", value);
            XS_DIR_PERM(xsh, be_path, "frontend", fe_path);
            XS_DIR_PERM(xsh, be_path, "online", "1");
            XS_DIR_PERM(xsh, be_path, "protocol", "vt100");

            snprintf(value, 16, "%d", XenbusStateInitialising);
            XS_DIR_PERM(xsh, be_path, "state", value);

            /* Frontend entries */
            XS_DOM_PERM(xsh, di->domid, "console", "");
            snprintf(value, 16, "%d", di->cons_info.be_domid);
            XS_DIR_PERM(xsh, fe_path, "backend", be_path);
            XS_DIR_PERM(xsh, fe_path, "backend-id", value);
            XS_DIR_PERM(xsh, fe_path, "limit", "1048576");
            XS_DIR_PERM(xsh, fe_path, "type", "xenconsoled");
            XS_DIR_PERM(xsh, fe_path, "output", "pty");
            XS_DIR_PERM(xsh, fe_path, "tty", "");

            snprintf(value, 16, "%d", di->cons_info.evtchn_port);
            XS_DIR_PERM(xsh, fe_path, "port", value);

            snprintf(value, 16, "%ld", di->cons_info.mfn);
            XS_DIR_PERM(xsh, fe_path, "ring-ref", value);

        }

        ret = do_xs_end_transaction(xsh);
        switch ( ret )
        {
        case 0:
            break; /* proceed to loop break */
        case -EAGAIN:
            continue; /* try again */
        default:
            return ret; /* failed */
        }

        break;
    }

    return ret;
}

static bool init_domain(struct xs_handle *xsh, struct domain_info *di)
{
    xc_interface *xch = xc_interface_open(0, 0, 0);
    xen_pfn_t con_mfn = 0L;
    /*xc_dom_gnttab_seed will do nothing of front == back */
    uint32_t con_domid = di->domid;
    int ret;

    /* console */
    if ( di->cons_info.enable )
    {
        con_domid = di->cons_info.be_domid;
        con_mfn = di->cons_info.mfn;
    }

    ret = xc_dom_gnttab_seed(xch, di->domid, di->is_hvm, con_mfn,
            di->xs_info.mfn, con_domid, di->xs_info.be_domid);
    if ( ret != 0 )
    {
        fprintf(stderr, "error (%d) setting up grant tables for dom%d\n",
                ret, di->domid);
        xc_interface_close(xch);
        return false;
    }

    xc_interface_close(xch);

    return xs_introduce_domain(xsh, di->domid, di->xs_info.mfn,
                               di->xs_info.evtchn_port);
}

int main(int argc, char** argv)
{
    int opt, rv;
    bool force = false;
    struct xs_handle *xsh = NULL;
    xenhypfs_handle *xhfs = NULL;
    xentoollog_level minmsglevel = XTL_PROGRESS;
    xentoollog_logger *logger = NULL;
    struct domain_info di = { .domid = ~0 };

    while ( (opt = getopt_long(argc, argv, "cfd:v", options, NULL)) != -1 )
    {
        switch ( opt )
        {
        case 'u':
            di.override_uuid = true;
            di.uuid = optarg;
            break;
        case 'c':
            di.cons_info.enable = true;
            break;
        case 'f':
            force = true;
            break;
        case 'd':
            di.domid = strtol(optarg, NULL, 10);
            break;
        case 'v':
            if ( minmsglevel )
                minmsglevel--;
            break;
        default:
            usage();
            return 2;
        }
    }

    if ( optind != argc || di.domid == ~0 )
    {
        usage();
        return 1;
    }

    logger = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr,
                                                               minmsglevel, 0);

    xhfs = xenhypfs_open(logger, 0);
    if ( !xhfs )
    {
        fprintf(stderr, "error: unable to acces xen hypfs\n");
        rv = 2;
        goto out;
    }

    if ( !has_builder_hypfs(xhfs, di.domid) )
    {
        fprintf(stderr, "error: hypfs entry for domain %d not present\n",
                di.domid);
        rv = 3;
        goto out;
    }

    if ( read_hypfs_tree(xhfs, &di) != 0 )
    {
        fprintf(stderr, "error: unable to parse hypfs for domain %d\n",
                di.domid);
        rv = 4;
        goto out;
    }

    xsh = xs_open(0);
    if ( xsh == NULL )
    {
        fprintf(stderr, "error: unable to connect to xenstored\n");
        rv = 5;
        goto out;
    }

    if ( xs_is_domain_introduced(xsh, di.domid) )
    {
        if ( !force )
        {
            fprintf(stderr, "error: domain %d already introduced\n", di.domid);
            rv = 6;
            goto out;
        }
        else
        {
            fprintf(stderr, "warning: re-introducting domain %d\n", di.domid);
        }
    }

    /* TODO: hardcdoding local domain to 0 for testing purposes */
    if ( (rv = create_xs_entries(xsh, 0, &di)) != 0 )
    {
        fprintf(stderr, "error(%d): unable create xenstore entries\n", rv);
        rv = 7;
        goto out;
    }

    init_domain(xsh, &di);
    rv = 0;

out:
    if ( xsh )
        xs_close(xsh);

    if ( xhfs )
        xenhypfs_close(xhfs);

    if ( logger )
        xtl_logger_destroy(logger);

    return rv;
}
