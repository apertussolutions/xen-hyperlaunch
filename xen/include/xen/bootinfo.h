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

#endif
