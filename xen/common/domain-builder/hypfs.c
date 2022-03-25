#include <xen/bootinfo.h>
#include <xen/domain_builder.h>
#include <xen/hypfs.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/string.h>
#include <xen/xmalloc.h>

#define INIT_HYPFS_DIR(var, nam)                 \
    var.e.type = XEN_HYPFS_TYPE_DIR;             \
    var.e.encoding = XEN_HYPFS_ENC_PLAIN;        \
    var.e.name = (nam);                          \
    var.e.size = 0;                              \
    var.e.max_size = 0;                          \
    INIT_LIST_HEAD(&var.e.list);                 \
    var.e.funcs = (&hypfs_dir_funcs);            \
    INIT_LIST_HEAD(&var.dirlist)

#define INIT_HYPFS_FIXEDSIZE(var, typ, nam, contvar, fn, wr) \
    var.e.type = (typ);                                      \
    var.e.encoding = XEN_HYPFS_ENC_PLAIN;                    \
    var.e.name = (nam);                                      \
    var.e.size = sizeof(contvar);                            \
    var.e.max_size = (wr) ? sizeof(contvar) : 0;             \
    var.e.funcs = (fn);                                      \
    var.u.content = &(contvar)

#define INIT_HYPFS_UINT(var, nam, contvar)                       \
    INIT_HYPFS_FIXEDSIZE(var, XEN_HYPFS_TYPE_UINT, nam, contvar, \
                         &hypfs_leaf_ro_funcs, 0)

#define INIT_HYPFS_BOOL(var, nam, contvar)                       \
    INIT_HYPFS_FIXEDSIZE(var, XEN_HYPFS_TYPE_BOOL, nam, contvar, \
                         &hypfs_leaf_ro_funcs, 0)

#define INIT_HYPFS_VARSIZE(var, typ, nam, msz, fn) \
    var.e.type = (typ) ;                           \
    var.e.encoding = XEN_HYPFS_ENC_PLAIN;          \
    var.e.name = (nam);                            \
    var.e.max_size = (msz);                        \
    var.e.funcs = (fn)

#define INIT_HYPFS_STRING(var, nam)               \
    INIT_HYPFS_VARSIZE(var, XEN_HYPFS_TYPE_STRING, nam, 0, &hypfs_leaf_ro_funcs)

struct device_node {
    struct hypfs_entry_dir dir;

    uint32_t evtchn;
    struct hypfs_entry_leaf evtchn_leaf;

    xen_pfn_t mfn;
    struct hypfs_entry_leaf mfn_leaf;
};

struct domain_node {
    char dir_name[HYPFS_DYNDIR_ID_NAMELEN];
    struct hypfs_entry_dir dir;

    char uuid[40];
    struct hypfs_entry_leaf uuid_leaf;

    uint16_t functions;
    struct hypfs_entry_leaf func_leaf;

    uint32_t ncpus;
    struct hypfs_entry_leaf ncpus_leaf;

    uint32_t mem_size;
    struct hypfs_entry_leaf mem_sz_leaf;

    uint32_t mem_max;
    struct hypfs_entry_leaf mem_mx_leaf;

    bool constructed;
    struct hypfs_entry_leaf const_leaf;

    struct device_node xs;

    struct hypfs_entry_dir dev_dir;

    struct device_node con_dev;
};

static struct hypfs_entry_dir __read_mostly *builder_dir;
static struct domain_node __read_mostly *entries;

static int __init alloc_hypfs(struct boot_info *info)
{
    if ( !(builder_dir = (struct hypfs_entry_dir *)xmalloc_bytes(
                        sizeof(struct hypfs_entry_dir))) )
    {
        printk(XENLOG_WARNING "%s: unable to allocate hypfs dir\n", __func__);
        return -ENOMEM;
    }

    builder_dir->e.type = XEN_HYPFS_TYPE_DIR;
    builder_dir->e.encoding = XEN_HYPFS_ENC_PLAIN;
    builder_dir->e.name = "builder";
    builder_dir->e.size = 0;
    builder_dir->e.max_size = 0;
    INIT_LIST_HEAD(&builder_dir->e.list);
    builder_dir->e.funcs = &hypfs_dir_funcs;
    INIT_LIST_HEAD(&builder_dir->dirlist);

    if ( !(entries = (struct domain_node *)xmalloc_bytes(
                        sizeof(struct domain_node) * info->builder->nr_doms)) )
    {
        printk(XENLOG_WARNING "%s: unable to allocate hypfs nodes\n", __func__);
        return -ENOMEM;
    }

    return 0;
}

void __init builder_hypfs(struct boot_info *info)
{
    int i;

    printk("Domain Builder: creating hypfs nodes\n");

    if ( alloc_hypfs(info) != 0 )
        return;

    for ( i = 0; i < info->builder->nr_doms; i++ )
    {
        struct domain_node *e = &entries[i];
        struct boot_domain *bd = &info->builder->domains[i];
        uint8_t *uuid = bd->uuid;

        snprintf(e->dir_name, sizeof(e->dir_name), "%d", bd->domid);

        snprintf(e->uuid, sizeof(e->uuid), "%08x-%04x-%04x-%04x-%04x%08x",
                 *(uint32_t *)uuid, *(uint16_t *)(uuid+4),
                 *(uint16_t *)(uuid+6), *(uint16_t *)(uuid+8),
                 *(uint16_t *)(uuid+10), *(uint32_t *)(uuid+12));

        e->functions = bd->functions;
        e->constructed = bd->constructed;

        e->ncpus = bd->ncpus;
        e->mem_size = (bd->meminfo.mem_size.nr_pages * PAGE_SIZE)/1024;
        e->mem_max = (bd->meminfo.mem_max.nr_pages * PAGE_SIZE)/1024;

        e->xs.evtchn = bd->store.evtchn;
        e->xs.mfn = bd->store.mfn;

        e->con_dev.evtchn = bd->console.evtchn;
        e->con_dev.mfn = bd->console.mfn;

        /* Initialize and construct builder hypfs tree */
        INIT_HYPFS_DIR(e->dir, e->dir_name);
        INIT_HYPFS_DIR(e->xs.dir, "xenstore");
        INIT_HYPFS_DIR(e->dev_dir, "devices");
        INIT_HYPFS_DIR(e->con_dev.dir, "console");

        INIT_HYPFS_STRING(e->uuid_leaf, "uuid");
        hypfs_string_set_reference(&e->uuid_leaf, e->uuid);
        INIT_HYPFS_UINT(e->func_leaf, "functions", e->functions);
        INIT_HYPFS_UINT(e->ncpus_leaf, "ncpus", e->ncpus);
        INIT_HYPFS_UINT(e->mem_sz_leaf, "mem_size", e->mem_size);
        INIT_HYPFS_UINT(e->mem_mx_leaf, "mem_max", e->mem_max);
        INIT_HYPFS_BOOL(e->const_leaf, "constructed", e->constructed);

        INIT_HYPFS_UINT(e->xs.evtchn_leaf, "evtchn", e->xs.evtchn);
        INIT_HYPFS_UINT(e->xs.mfn_leaf, "mfn", e->xs.mfn);

        INIT_HYPFS_UINT(e->con_dev.evtchn_leaf, "evtchn", e->con_dev.evtchn);
        INIT_HYPFS_UINT(e->con_dev.mfn_leaf, "mfn", e->con_dev.mfn);

        hypfs_add_leaf(&e->con_dev.dir, &e->con_dev.evtchn_leaf, true);
        hypfs_add_leaf(&e->con_dev.dir, &e->con_dev.mfn_leaf, true);
        hypfs_add_dir(&e->dev_dir, &e->con_dev.dir, true);

        hypfs_add_dir(&e->dir, &e->dev_dir, true);

        hypfs_add_leaf(&e->xs.dir, &e->xs.evtchn_leaf, true);
        hypfs_add_leaf(&e->xs.dir, &e->xs.mfn_leaf, true);
        hypfs_add_dir(&e->dir, &e->xs.dir, true);

        hypfs_add_leaf(&e->dir, &e->uuid_leaf, true);
        hypfs_add_leaf(&e->dir, &e->func_leaf, true);
        hypfs_add_leaf(&e->dir, &e->ncpus_leaf, true);
        hypfs_add_leaf(&e->dir, &e->mem_sz_leaf, true);
        hypfs_add_leaf(&e->dir, &e->mem_mx_leaf, true);
        hypfs_add_leaf(&e->dir, &e->const_leaf, true);

        hypfs_add_dir(builder_dir, &e->dir, true);
    }

    hypfs_add_dir(&hypfs_root, builder_dir, true);
}
