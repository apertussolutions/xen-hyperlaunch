#ifndef __ARCH_X86_BOOTINFO_H__
#define __ARCH_X86_BOOTINFO_H__

/* unused for x86 */
struct arch_bootstring { };

struct __packed arch_bootmodule {
#define BOOTMOD_FLAG_X86_RELOCATED      1U << 0
    uint32_t flags;
    uint32_t headroom;
};

struct __packed arch_boot_info {
    uint32_t flags;
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

    bool xenguest;

    char *boot_loader_name;
    char *kextra;

    uint32_t mem_lower;
    uint32_t mem_upper;

    uint32_t mmap_length;
    paddr_t mmap_addr;
};

struct __packed mb_memmap {
    uint32_t size;
    uint32_t base_addr_low;
    uint32_t base_addr_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;
};

struct arch_domain_builder { };

static inline bool loader_is_grub2(const char *loader_name)
{
    /* GRUB1="GNU GRUB 0.xx"; GRUB2="GRUB 1.xx" */
    const char *p = strstr(loader_name, "GRUB ");
    return (p != NULL) && (p[5] != '0');
}

static inline char *arch_prepare_cmdline(char *p, struct arch_boot_info *arch)
{
    p = p ? : "";

    /* Strip leading whitespace. */
    while ( *p == ' ' )
        p++;

    /* GRUB2 and PVH don't not include image name as first item on command line. */
    if ( !(arch->xenguest || loader_is_grub2(arch->boot_loader_name)) )
    {
        /* Strip image name plus whitespace. */
        while ( (*p != ' ') && (*p != '\0') )
            p++;
        while ( *p == ' ' )
            p++;
    }

    return p;
}

static inline char *arch_bootinfo_prepare_cmdline(
    char *cmdline, struct arch_boot_info *arch)
{
    if ( !cmdline )
        return "";

    if ( (arch->kextra = strstr(cmdline, " -- ")) != NULL )
    {
        /*
         * Options after ' -- ' separator belong to dom0.
         *  1. Orphan dom0's options from Xen's command line.
         *  2. Skip all but final leading space from dom0's options.
         */
        *arch->kextra = '\0';
        arch->kextra += 3;
        while ( arch->kextra[1] == ' ' ) arch->kextra++;
    }


    return arch_prepare_cmdline(cmdline, arch);
}
#endif
