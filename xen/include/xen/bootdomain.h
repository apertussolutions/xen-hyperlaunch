#ifndef __XEN_BOOTDOMAIN_H__
#define __XEN_BOOTDOMAIN_H__

#include <xen/bootinfo.h>
#include <xen/types.h>

#include <public/xen.h>

#include <asm/bootdomain.h>

struct domain;

struct boot_domain {
#define BUILD_PERMISSION_NONE          (0)
#define BUILD_PERMISSION_CONTROL       (1 << 0)
#define BUILD_PERMISSION_HARDWARE      (1 << 1)
    uint32_t permissions;

#define BUILD_FUNCTION_NONE            (0)
#define BUILD_FUNCTION_BOOT            (1 << 0)
#define BUILD_FUNCTION_CRASH           (1 << 1)
#define BUILD_FUNCTION_CONSOLE         (1 << 2)
#define BUILD_FUNCTION_STUBDOM         (1 << 3)
#define BUILD_FUNCTION_XENSTORE        (1 << 30)
#define BUILD_FUNCTION_INITIAL_DOM     (1 << 31)
    uint32_t functions;
                                                /* On     | Off    */
#define BUILD_MODE_PARAVIRTUALIZED     (1 << 0) /* PV     | PVH/HVM */
#define BUILD_MODE_ENABLE_DEVICE_MODEL (1 << 1) /* HVM    | PVH     */
#define BUILD_MODE_LONG                (1 << 2) /* 64 BIT | 32 BIT  */
    uint32_t mode;

    domid_t domid;
    uint8_t uuid[16];

    uint32_t ncpus;
    struct arch_domain_mem meminfo;

#define BUILD_MAX_SECID_LEN 64
    unsigned char secid[BUILD_MAX_SECID_LEN];

    struct boot_module *kernel;
    struct boot_module *ramdisk;
#define BUILD_MAX_CONF_MODS 2
#define BUILD_DTB_CONF_IDX 0
#define BUILD_DOM_CONF_IDX 1
    struct boot_module *configs[BUILD_MAX_CONF_MODS];

    struct domain *domain;
};

#endif
