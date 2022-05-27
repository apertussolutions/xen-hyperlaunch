#ifndef __XEN_BOOTINFO_H__
#define __XEN_BOOTINFO_H__

#include <xen/mm.h>
#include <xen/types.h>

#include <asm/bootinfo.h>

typedef enum {
    BOOTMOD_UNKNOWN,
    BOOTMOD_XEN,
    BOOTMOD_FDT,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_XSM,
    BOOTMOD_UCODE,
    BOOTMOD_GUEST_DTB,
}  bootmodule_kind;

typedef enum {
    BOOTSTR_EMPTY,
    BOOTSTR_STRING,
    BOOTSTR_CMDLINE,
} bootstring_kind;

#define BOOTMOD_MAX_STRING 1024
struct __packed boot_string {
    bootstring_kind kind;
    struct arch_bootstring *arch;

    char bytes[BOOTMOD_MAX_STRING];
    size_t len;
};

struct __packed boot_module {
    bootmodule_kind kind;
    paddr_t start;
    mfn_t mfn;
    size_t size;

    struct arch_bootmodule *arch;
    struct boot_string string;
};

struct __packed boot_info {
    char *cmdline;

    uint32_t nr_mods;
    struct boot_module *mods;

    struct arch_boot_info *arch;
};

extern struct boot_info *boot_info;

static inline unsigned long bootmodule_next_idx_by_kind(
    const struct boot_info *bi, bootmodule_kind kind, unsigned long start)
{
    for ( ; start < bi->nr_mods; start++ )
        if ( bi->mods[start].kind == kind )
            return start;

    return bi->nr_mods + 1;
}

static inline unsigned long bootmodule_count_by_kind(
    const struct boot_info *bi, bootmodule_kind kind)
{
    unsigned long count = 0;
    int i;

    for ( i=0; i < bi->nr_mods; i++ )
        if ( bi->mods[i].kind == kind )
            count++;

    return count;
}

static inline struct boot_module *bootmodule_next_by_kind(
    const struct boot_info *bi, bootmodule_kind kind, unsigned long start)
{
    for ( ; start < bi->nr_mods; start++ )
        if ( bi->mods[start].kind == kind )
            return &bi->mods[start];

    return NULL;
}

static inline void bootmodule_update_start(struct boot_module *b, paddr_t new_start)
{
    b->start = new_start;
    b->mfn = maddr_to_mfn(new_start);
}

static inline void bootmodule_update_mfn(struct boot_module *b, mfn_t new_mfn)
{
    b->mfn = new_mfn;
    b->start = mfn_to_maddr(new_mfn);
}

#endif
