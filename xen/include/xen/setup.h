/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XEN_SETUP_H
#define XEN_SETUP_H

#include <public/xen.h>
#ifdef CONFIG_MULTIBOOT
#include <xen/multiboot.h>
#endif

#include <asm/setup.h>

/* Reusing Dom0less definitions */
typedef enum {
    BOOTMOD_XEN,
    BOOTMOD_FDT,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_MICROCODE,
    BOOTMOD_XSM,
    BOOTMOD_GUEST_DTB,
    BOOTMOD_GUEST_CONF,
    BOOTMOD_UNKNOWN
}  bootmodule_kind;

struct bootmodule {
    bootmodule_kind kind;
    bool domU;
    paddr_t start;
    paddr_t size;
};

/* End reuse */

struct memsize {
    long nr_pages;
    unsigned int percent;
    bool minus;
};

/* Currently only two config modules supported, microcode and xsm policy */
#define HL_MAX_CONFIG_MODULES 2
struct bootconfig {
    uint16_t nr_mods;
    struct bootmodule mods[HL_MAX_CONFIG_MODULES];
};

struct bootdomain {
#define HL_PERMISSION_NONE          (0)
#define HL_PERMISSION_CONTROL       (1 << 0)
#define HL_PERMISSION_HARDWARE      (1 << 1)
    uint32_t permissions;

#define HL_FUNCTION_NONE            (0)
#define HL_FUNCTION_BOOT            (1 << 0)
#define HL_FUNCTION_CRASH           (1 << 1)
#define HL_FUNCTION_CONSOLE         (1 << 2)
#define HL_FUNCTION_XENSTORE        (1 << 30)
#define HL_FUNCTION_LEGACY_DOM0     (1 << 31)
    uint32_t functions;

#define HL_MODE_PARAVIRTUALIZED     (1 << 0) /* PV | PVH/HVM */
#define HL_MODE_ENABLE_DEVICE_MODEL (1 << 1) /* HVM | PVH */
#define HL_MODE_LONG                (1 << 2) /* 64 BIT | 32 BIT */
    uint32_t mode;

    domid_t domid;
    uint8_t uuid[16];

    uint32_t ncpus;
    struct memsize mem_size;
    struct memsize mem_min;
    struct memsize mem_max;

#define HL_MAX_SECID_LEN 64
    unsigned char secid[HL_MAX_SECID_LEN];

#define HL_MAX_DOMAIN_MODULES 3
    uint16_t nr_mods;
    struct bootmodule modules[HL_MAX_DOMAIN_MODULES];
#define HL_MAX_CMDLINE_LEN 1024
    char cmdline[HL_MAX_CMDLINE_LEN];
};

struct hyperlaunch_config {
    const void *fdt;
#ifdef CONFIG_MULTIBOOT
    module_t *mods;
#endif
    struct bootconfig config;
#define HL_MAX_BOOT_DOMAINS 64
    uint16_t nr_doms;
    struct bootdomain domains[HL_MAX_BOOT_DOMAINS];
};

#ifdef CONFIG_HYPERLAUNCH
extern bool hyperlaunch_enabled;

int __init hyperlaunch_init(const void *fdt);

#ifdef CONFIG_MULTIBOOT
bool __init hyperlaunch_mb_init(module_t *mods);
#endif

#else /* CONFIG_HYPERLAUNCH */

#define hyperlaunch_enabled false

static inline int __init hyperlaunch_init(const void *fdt)
{
    return 0;
}

#ifdef CONFIG_MULTIBOOT
static inline bool __init hyperlaunch_mb_init(module_t *mods)
{
    return false;
}
#endif

#endif /* CONFIG_HYPERLAUNCH */
#endif /* XEN_SETUP_H */
