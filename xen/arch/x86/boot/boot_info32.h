#ifndef __BOOT_INFO32_H__
#define __BOOT_INFO32_H__

#include "defs.h"

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
    u32 kind;
    u64 arch;

    char bytes[BOOTMOD_MAX_STRING];
    u64 len;
};

struct __packed arch_bootmodule {
    bool relocated;
    u32 flags;
#define BOOTMOD_FLAG_X86_RELOCATED      1U << 0
    u32 headroom;
};

struct __packed boot_module {
    u32 kind;
    u64 start;
    u64 mfn;
    u64 size;

    u64 arch;
    struct boot_string string;
};

struct __packed arch_boot_info {
    /* uint32_t */
    u32 flags;
#define BOOTINFO_FLAG_X86_MEMLIMITS  	1U << 0
#define BOOTINFO_FLAG_X86_BOOTDEV    	1U << 1
#define BOOTINFO_FLAG_X86_CMDLINE    	1U << 2
#define BOOTINFO_FLAG_X86_MODULES    	1U << 3
#define BOOTINFO_FLAG_X86_AOUT_SYMS  	1U << 4
#define BOOTINFO_FLAG_X86_ELF_SYMS   	1U << 5
#define BOOTINFO_FLAG_X86_MEMMAP     	1U << 6
#define BOOTINFO_FLAG_X86_DRIVES     	1U << 7
#define BOOTINFO_FLAG_X86_BIOSCONFIG 	1U << 8
#define BOOTINFO_FLAG_X86_LOADERNAME 	1U << 9
#define BOOTINFO_FLAG_X86_APM        	1U << 10

    /* bool */
    u8 xen_guest;

    /* char* */
    u64 boot_loader_name;
    u64 kextra;

    /* uint32_t */
    u32 mem_lower;
    u32 mem_upper;

    /* uint32_t */
    u32 mmap_length;
    /* paddr_t */
    u64 mmap_addr;
};

struct __packed boot_info {
    /* char* */
    u64 cmdline;

    /* uint32_t */
    u32 nr_mods;
    /* struct boot_module* */
    u64 mods;

    /* struct domain_builder* */
    u64 builder;

    /* struct arch_boot_info* */
    u64 arch;
};

#endif
