#include <xen/init.h>
#include <xen/lib.h>
#include <xen/err.h>
#include <xen/grant_table.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/acpi.h>
#include <xen/efi.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <xen/multiboot.h>
#include <xen/domain_page.h>
#include <xen/version.h>
#include <xen/gdbstub.h>
#include <xen/hypercall.h>
#include <xen/keyhandler.h>
#include <xen/numa.h>
#include <xen/rcupdate.h>
#include <xen/vga.h>
#include <xen/dmi.h>
#include <xen/pfn.h>
#include <xen/nodemask.h>
#include <xen/virtual_region.h>
#include <xen/watchdog.h>
#include <public/launch_control_module.h>
#include <public/version.h>
#include <compat/platform.h>
#include <compat/xen.h>
#include <xen/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/msi.h>
#include <asm/desc.h>
#include <asm/paging.h>
#include <asm/e820.h>
#include <xen/kexec.h>
#include <asm/edd.h>
#include <xsm/xsm.h>
#include <asm/tboot.h>
#include <asm/bzimage.h> /* for bzimage_headroom */
#include <asm/dom0_build.h> /* FIXME: temporary for dom0_construct_pv */
#include <asm/mach-generic/mach_apic.h> /* for generic_apic_probe */
#include <asm/setup.h>
#include <xen/cpu.h>
#include <asm/nmi.h>
#include <asm/alternative.h>
#include <asm/mc146818rtc.h>
#include <asm/cpuid.h>
#include <asm/spec_ctrl.h>
#include <asm/guest.h>
#include <asm/microcode.h>

#define MAX_MULTIBOOT_MODS_COUNT 8 /* FIXME: move this; see: pvh_mbi_mods */
#define MAX_NUM_INITIAL_DOMAINS 8 /* FIXME: review this and place correctly */

/* opt_nosmp: If true, secondary processors are ignored. */
static bool __initdata opt_nosmp;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus;
integer_param("maxcpus", max_cpus);

int8_t __read_mostly opt_smt = -1;
boolean_param("smt", opt_smt);

/* opt_invpcid: If false, don't use INVPCID instruction even if available. */
static bool __initdata opt_invpcid = true;
boolean_param("invpcid", opt_invpcid);
bool __read_mostly use_invpcid;

unsigned long __read_mostly cr4_pv32_mask;

/* **** Linux config option: propagated to domain0. */
/* "acpi=off":    Sisables both ACPI table parsing and interpreter. */
/* "acpi=force":  Override the disable blacklist.                   */
/* "acpi=ht":     Limit ACPI just to boot-time to enable HT.        */
/* "acpi=noirq":  Disables ACPI interrupt routing.                  */
static int parse_acpi_param(const char *s);
custom_param("acpi", parse_acpi_param);

/* **** Linux config option: propagated to domain0. */
/* noapic: Disable IOAPIC setup. */
boolean_param("noapic", skip_ioapic_setup);

/* **** Linux config option: propagated to domain0. */
/* xen_cpuidle: xen control cstate. */
s8 __read_mostly xen_cpuidle = -1;
boolean_param("cpuidle", xen_cpuidle);

#ifndef NDEBUG
unsigned long __initdata highmem_start;
size_param("highmem-start", highmem_start);
#endif

cpumask_t __read_mostly cpu_present_map;

unsigned long __read_mostly xen_phys_start;

unsigned long __read_mostly xen_virt_end;

char __section(".bss.stack_aligned") __aligned(STACK_SIZE)
    cpu0_stack[STACK_SIZE];

struct cpuinfo_x86 __read_mostly boot_cpu_data = { 0, 0, 0, 0, -1 };

unsigned long __read_mostly mmu_cr4_features = XEN_MINIMAL_CR4;

/* smep: Enable/disable Supervisor Mode Execution Protection */
#define SMEP_HVM_ONLY (-2)
static s8 __initdata opt_smep = -1;

/*
 * Initial domain place holder. Needs to be global so it can be created in
 * __start_xen and unpaused in init_done.
 */
static struct domain *__initdata initial_domain;

static int __init parse_smep_param(const char *s)
{
    if ( !*s )
    {
        opt_smep = 1;
        return 0;
    }

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_smep = 0;
        return 0;
    case 1:
        opt_smep = 1;
        return 0;
    }

    if ( !strcmp(s, "hvm") )
        opt_smep = SMEP_HVM_ONLY;
    else
        return -EINVAL;

    return 0;
}
custom_param("smep", parse_smep_param);

/* smap: Enable/disable Supervisor Mode Access Prevention */
#define SMAP_HVM_ONLY (-2)
static s8 __initdata opt_smap = -1;

static int __init parse_smap_param(const char *s)
{
    if ( !*s )
    {
        opt_smap = 1;
        return 0;
    }

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_smap = 0;
        return 0;
    case 1:
        opt_smap = 1;
        return 0;
    }

    if ( !strcmp(s, "hvm") )
        opt_smap = SMAP_HVM_ONLY;
    else
        return -EINVAL;

    return 0;
}
custom_param("smap", parse_smap_param);

bool __read_mostly acpi_disabled;
bool __initdata acpi_force;
static char __initdata acpi_param[10] = "";

static int __init parse_acpi_param(const char *s)
{
    /* Save the parameter so it can be propagated to domain0. */
    safe_strcpy(acpi_param, s);

    /* Interpret the parameter for use within Xen. */
    if ( !parse_bool(s, NULL) )
    {
        disable_acpi();
    }
    else if ( !strcmp(s, "force") )
    {
        acpi_force = true;
        acpi_ht = 1;
        acpi_disabled = false;
    }
    else if ( !strcmp(s, "ht") )
    {
        if ( !acpi_force )
            disable_acpi();
        acpi_ht = 1;
    }
    else if ( !strcmp(s, "noirq") )
    {
        acpi_noirq_set();
    }
    else
        return -EINVAL;

    return 0;
}

static const module_t *__initdata initial_images;
static unsigned int __initdata nr_initial_images;

unsigned long __init initial_images_nrpages(nodeid_t node)
{
    unsigned long node_start = node_start_pfn(node);
    unsigned long node_end = node_end_pfn(node);
    unsigned long nr;
    unsigned int i;

    for ( nr = i = 0; i < nr_initial_images; ++i )
    {
        unsigned long start = initial_images[i].mod_start;
        unsigned long end = start + PFN_UP(initial_images[i].mod_end);

        if ( end > node_start && node_end > start )
            nr += min(node_end, end) - max(node_start, start);
    }

    return nr;
}

void __init discard_initial_images(void)
{
    unsigned int i;

    for ( i = 0; i < nr_initial_images; ++i )
    {
        uint64_t start = (uint64_t)initial_images[i].mod_start << PAGE_SHIFT;

        init_domheap_pages(start,
                           start + PAGE_ALIGN(initial_images[i].mod_end));
    }

    nr_initial_images = 0;
    initial_images = NULL;
}

extern char __init_begin[], __init_end[], __bss_start[], __bss_end[];

static void __init init_idle_domain(void)
{
    scheduler_init();
    set_current(idle_vcpu[0]);
    this_cpu(curr_vcpu) = current;
}

void srat_detect_node(int cpu)
{
    nodeid_t node;
    u32 apicid = x86_cpu_to_apicid[cpu];

    node = apicid < MAX_LOCAL_APIC ? apicid_to_node[apicid] : NUMA_NO_NODE;
    if ( node == NUMA_NO_NODE )
        node = 0;

    node_set_online(node);
    numa_set_node(cpu, node);

    if ( opt_cpu_info && acpi_numa > 0 )
        printk("CPU %d APIC %d -> Node %d\n", cpu, apicid, node);
}

/*
 * Sort CPUs by <node,package,core,thread> tuple. Fortunately this hierarchy is
 * reflected in the structure of modern APIC identifiers, so we sort based on
 * those. This is slightly complicated by the fact that the BSP must remain
 * CPU 0. Hence we do a variation on longest-prefix matching to do the best we
 * can while keeping CPU 0 static.
 */
static void __init normalise_cpu_order(void)
{
    unsigned int i, j, min_cpu;
    uint32_t apicid, diff, min_diff;

    for_each_present_cpu ( i )
    {
        apicid = x86_cpu_to_apicid[i];
        min_diff = min_cpu = ~0u;

        /*
         * Find remaining CPU with longest-prefix match on APIC ID.
         * Among identical longest-prefix matches, pick the smallest APIC ID.
         */
        for ( j = cpumask_next(i, &cpu_present_map);
              j < nr_cpu_ids;
              j = cpumask_next(j, &cpu_present_map) )
        {
            diff = x86_cpu_to_apicid[j] ^ apicid;
            while ( diff & (diff-1) )
                diff &= diff-1;
            if ( (diff < min_diff) ||
                 ((diff == min_diff) &&
                  (x86_cpu_to_apicid[j] < x86_cpu_to_apicid[min_cpu])) )
            {
                min_diff = diff;
                min_cpu = j;
            }
        }

        /* If no match then there must be no CPUs remaining to consider. */
        if ( min_cpu >= nr_cpu_ids )
        {
            BUG_ON(cpumask_next(i, &cpu_present_map) < nr_cpu_ids);
            break;
        }

        /* Switch the best-matching CPU with the next CPU in logical order. */
        j = cpumask_next(i, &cpu_present_map);
        apicid = x86_cpu_to_apicid[min_cpu];
        x86_cpu_to_apicid[min_cpu] = x86_cpu_to_apicid[j];
        x86_cpu_to_apicid[j] = apicid;
    }
}

#define BOOTSTRAP_MAP_BASE  (16UL << 20)
#define BOOTSTRAP_MAP_LIMIT (1UL << L3_PAGETABLE_SHIFT)

/*
 * Ensure a given physical memory range is present in the bootstrap mappings.
 * Use superpage mappings to ensure that pagetable memory needn't be allocated.
 */
void *__init bootstrap_map(const module_t *mod)
{
    static unsigned long __initdata map_cur = BOOTSTRAP_MAP_BASE;
    uint64_t start, end, mask = (1L << L2_PAGETABLE_SHIFT) - 1;
    void *ret;

    if ( system_state != SYS_STATE_early_boot )
        return mod ? mfn_to_virt(mod->mod_start) : NULL;

    if ( !mod )
    {
        destroy_xen_mappings(BOOTSTRAP_MAP_BASE, BOOTSTRAP_MAP_LIMIT);
        map_cur = BOOTSTRAP_MAP_BASE;
        return NULL;
    }

    start = (uint64_t)mod->mod_start << PAGE_SHIFT;
    end = start + mod->mod_end;
    if ( start >= end )
        return NULL;

    ret = (void *)(map_cur + (unsigned long)(start & mask));
    start &= ~mask;
    end = (end + mask) & ~mask;
    if ( end - start > BOOTSTRAP_MAP_LIMIT - map_cur )
        return NULL;

    map_pages_to_xen(map_cur, maddr_to_mfn(start),
                     PFN_DOWN(end - start), PAGE_HYPERVISOR);
    map_cur += end - start;
    return ret;
}

static void *__init move_memory(
    uint64_t dst, uint64_t src, unsigned int size, bool keep)
{
    unsigned int blksz = BOOTSTRAP_MAP_LIMIT - BOOTSTRAP_MAP_BASE;
    unsigned int mask = (1L << L2_PAGETABLE_SHIFT) - 1;

    if ( src + size > BOOTSTRAP_MAP_BASE )
        blksz >>= 1;

    while ( size )
    {
        module_t mod;
        unsigned int soffs = src & mask;
        unsigned int doffs = dst & mask;
        unsigned int sz;
        void *d, *s;

        mod.mod_start = (src - soffs) >> PAGE_SHIFT;
        mod.mod_end = soffs + size;
        if ( mod.mod_end > blksz )
            mod.mod_end = blksz;
        sz = mod.mod_end - soffs;
        s = bootstrap_map(&mod);

        mod.mod_start = (dst - doffs) >> PAGE_SHIFT;
        mod.mod_end = doffs + size;
        if ( mod.mod_end > blksz )
            mod.mod_end = blksz;
        if ( sz > mod.mod_end - doffs )
            sz = mod.mod_end - doffs;
        d = bootstrap_map(&mod);

        memmove(d + doffs, s + soffs, sz);

        dst += sz;
        src += sz;
        size -= sz;

        if ( keep )
            return size ? NULL : d + doffs;

        bootstrap_map(NULL);
    }

    return NULL;
}

#undef BOOTSTRAP_MAP_LIMIT

static uint64_t __init consider_modules(
    uint64_t s, uint64_t e, uint32_t size, const module_t *mod,
    unsigned int nr_mods, unsigned int this_mod)
{
    unsigned int i;

    if ( s > e || e - s < size )
        return 0;

    for ( i = 0; i < nr_mods ; ++i )
    {
        uint64_t start = (uint64_t)mod[i].mod_start << PAGE_SHIFT;
        uint64_t end = start + PAGE_ALIGN(mod[i].mod_end);

        if ( i == this_mod )
            continue;

        if ( s < end && start < e )
        {
            end = consider_modules(end, e, size, mod + i + 1,
                                   nr_mods - i - 1, this_mod - i - 1);
            if ( end )
                return end;

            return consider_modules(s, start, size, mod + i + 1,
                                    nr_mods - i - 1, this_mod - i - 1);
        }
    }

    return e;
}

static void __init setup_max_pdx(unsigned long top_page)
{
    max_pdx = pfn_to_pdx(top_page - 1) + 1;

    if ( max_pdx > (DIRECTMAP_SIZE >> PAGE_SHIFT) )
        max_pdx = DIRECTMAP_SIZE >> PAGE_SHIFT;

    if ( max_pdx > FRAMETABLE_NR )
        max_pdx = FRAMETABLE_NR;

    if ( max_pdx > MPT_VIRT_SIZE / sizeof(unsigned long) )
        max_pdx = MPT_VIRT_SIZE / sizeof(unsigned long);

#ifdef PAGE_LIST_NULL
    if ( max_pdx >= PAGE_LIST_NULL )
        max_pdx = PAGE_LIST_NULL - 1;
#endif

    max_page = pdx_to_pfn(max_pdx - 1) + 1;
}

/* A temporary copy of the e820 map that we can mess with during bootstrap. */
static struct e820map __initdata boot_e820;

#ifdef CONFIG_VIDEO
struct boot_video_info {
    u8  orig_x;             /* 0x00 */
    u8  orig_y;             /* 0x01 */
    u8  orig_video_mode;    /* 0x02 */
    u8  orig_video_cols;    /* 0x03 */
    u8  orig_video_lines;   /* 0x04 */
    u8  orig_video_isVGA;   /* 0x05 */
    u16 orig_video_points;  /* 0x06 */

    /* VESA graphic mode -- linear frame buffer */
    u32 capabilities;       /* 0x08 */
    u16 lfb_linelength;     /* 0x0c */
    u16 lfb_width;          /* 0x0e */
    u16 lfb_height;         /* 0x10 */
    u16 lfb_depth;          /* 0x12 */
    u32 lfb_base;           /* 0x14 */
    u32 lfb_size;           /* 0x18 */
    u8  red_size;           /* 0x1c */
    u8  red_pos;            /* 0x1d */
    u8  green_size;         /* 0x1e */
    u8  green_pos;          /* 0x1f */
    u8  blue_size;          /* 0x20 */
    u8  blue_pos;           /* 0x21 */
    u8  rsvd_size;          /* 0x22 */
    u8  rsvd_pos;           /* 0x23 */
    u16 vesapm_seg;         /* 0x24 */
    u16 vesapm_off;         /* 0x26 */
    u16 vesa_attrib;        /* 0x28 */
};
extern struct boot_video_info boot_vid_info;
#endif

static void __init parse_video_info(void)
{
#ifdef CONFIG_VIDEO
    struct boot_video_info *bvi = &bootsym(boot_vid_info);

    /* vga_console_info is filled directly on EFI platform. */
    if ( efi_enabled(EFI_BOOT) )
        return;

    if ( (bvi->orig_video_isVGA == 1) && (bvi->orig_video_mode == 3) )
    {
        vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
        vga_console_info.u.text_mode_3.font_height = bvi->orig_video_points;
        vga_console_info.u.text_mode_3.cursor_x = bvi->orig_x;
        vga_console_info.u.text_mode_3.cursor_y = bvi->orig_y;
        vga_console_info.u.text_mode_3.rows = bvi->orig_video_lines;
        vga_console_info.u.text_mode_3.columns = bvi->orig_video_cols;
    }
    else if ( bvi->orig_video_isVGA == 0x23 )
    {
        vga_console_info.video_type = XEN_VGATYPE_VESA_LFB;
        vga_console_info.u.vesa_lfb.width = bvi->lfb_width;
        vga_console_info.u.vesa_lfb.height = bvi->lfb_height;
        vga_console_info.u.vesa_lfb.bytes_per_line = bvi->lfb_linelength;
        vga_console_info.u.vesa_lfb.bits_per_pixel = bvi->lfb_depth;
        vga_console_info.u.vesa_lfb.lfb_base = bvi->lfb_base;
        vga_console_info.u.vesa_lfb.lfb_size = bvi->lfb_size;
        vga_console_info.u.vesa_lfb.red_pos = bvi->red_pos;
        vga_console_info.u.vesa_lfb.red_size = bvi->red_size;
        vga_console_info.u.vesa_lfb.green_pos = bvi->green_pos;
        vga_console_info.u.vesa_lfb.green_size = bvi->green_size;
        vga_console_info.u.vesa_lfb.blue_pos = bvi->blue_pos;
        vga_console_info.u.vesa_lfb.blue_size = bvi->blue_size;
        vga_console_info.u.vesa_lfb.rsvd_pos = bvi->rsvd_pos;
        vga_console_info.u.vesa_lfb.rsvd_size = bvi->rsvd_size;
        vga_console_info.u.vesa_lfb.gbl_caps = bvi->capabilities;
        vga_console_info.u.vesa_lfb.mode_attrs = bvi->vesa_attrib;
    }
#endif
}

static void __init kexec_reserve_area(struct e820map *e820)
{
#ifdef CONFIG_KEXEC
    unsigned long kdump_start = kexec_crash_area.start;
    unsigned long kdump_size  = kexec_crash_area.size;
    static bool __initdata is_reserved = false;

    kdump_size = (kdump_size + PAGE_SIZE - 1) & PAGE_MASK;

    if ( (kdump_start == 0) || (kdump_size == 0) || is_reserved )
        return;

    is_reserved = true;

    if ( !reserve_e820_ram(e820, kdump_start, kdump_start + kdump_size) )
    {
        printk("Kdump: DISABLED (failed to reserve %luMB (%lukB) at %#lx)"
               "\n", kdump_size >> 20, kdump_size >> 10, kdump_start);
        kexec_crash_area.start = kexec_crash_area.size = 0;
    }
    else
    {
        printk("Kdump: %luMB (%lukB) at %#lx\n",
               kdump_size >> 20, kdump_size >> 10, kdump_start);
    }
#endif
}

static inline bool using_2M_mapping(void)
{
    return !l1_table_offset((unsigned long)__2M_text_end) &&
           !l1_table_offset((unsigned long)__2M_rodata_start) &&
           !l1_table_offset((unsigned long)__2M_rodata_end) &&
           !l1_table_offset((unsigned long)__2M_init_start) &&
           !l1_table_offset((unsigned long)__2M_init_end) &&
           !l1_table_offset((unsigned long)__2M_rwdata_start) &&
           !l1_table_offset((unsigned long)__2M_rwdata_end);
}

static void noinline init_done(void)
{
    void *va;
    unsigned long start, end;

    system_state = SYS_STATE_active;

    printk("Unpausing initial domain: %u\n", initial_domain->domain_id);
    domain_unpause_by_systemcontroller(initial_domain);

    /* MUST be done prior to removing .init data. */
    unregister_init_virtual_region();

    /* Zero the .init code and data. */
    for ( va = __init_begin; va < _p(__init_end); va += PAGE_SIZE )
        clear_page(va);

    /* Destroy Xen's mappings, and reuse the pages. */
    if ( using_2M_mapping() )
    {
        start = (unsigned long)&__2M_init_start,
        end   = (unsigned long)&__2M_init_end;
    }
    else
    {
        start = (unsigned long)&__init_begin;
        end   = (unsigned long)&__init_end;
    }

    destroy_xen_mappings(start, end);
    init_xenheap_pages(__pa(start), __pa(end));
    printk("Freed %lukB init memory\n", (end - start) >> 10);

    startup_cpu_idle_loop();
}

/* Reinitalise all state referring to the old virtual address of the stack. */
static void __init noreturn reinit_bsp_stack(void)
{
    unsigned long *stack = (void*)(get_stack_bottom() & ~(STACK_SIZE - 1));

    /* Update TSS and ISTs */
    load_system_tables();

    /* Update SYSCALL trampolines */
    percpu_traps_init();

    stack_base[0] = stack;
    memguard_guard_stack(stack);

    reset_stack_and_jump_nolp(init_done);
}

/*
 * Some scripts add "placeholder" to work around a grub error where it ate the
 * first parameter.
 */
ignore_param("placeholder");

static bool __init loader_is_grub2(const char *loader_name)
{
    /* GRUB1="GNU GRUB 0.xx"; GRUB2="GRUB 1.xx" */
    const char *p = strstr(loader_name, "GRUB ");
    return (p != NULL) && (p[5] != '0');
}

static char * __init cmdline_cook(char *p, const char *loader_name)
{
    p = p ? : "";

    /* Strip leading whitespace. */
    while ( *p == ' ' )
        p++;

    /* GRUB2 and PVH don't not include image name as first item on command line. */
    if ( xen_guest || loader_is_grub2(loader_name) )
        return p;

    /* Strip image name plus whitespace. */
    while ( (*p != ' ') && (*p != '\0') )
        p++;
    while ( *p == ' ' )
        p++;

    return p;
}

static unsigned int __init copy_bios_e820(struct e820entry *map, unsigned int limit)
{
    unsigned int n = min(bootsym(bios_e820nr), limit);

    if ( n )
        memcpy(map, bootsym(bios_e820map), sizeof(*map) * n);

    return n;
}

void populate_module_maps(const multiboot_info_t *mbi,
                          const module_t *lcm_mod,
                          unsigned long *module_map_xsm_flask,
                          unsigned long *module_map_cpu_ucode,
                          unsigned long *module_map_domain_kernel,
                          unsigned long *module_map_ramdisk)
{
#ifdef CONFIG_BOOT_DOMAIN
    const struct lcm_entry *entry;
    unsigned int i, consumed;
    void *lcm_start;
    const struct lcm_header_info *hdr;

/* REMEMBER: the lcm_data is user-supplied, so validate anything used */
    consumed = sizeof(struct lcm_header_info);

    lcm_start = bootstrap_map(lcm_mod);
    hdr = (const struct lcm_header_info *)lcm_start;

    entry = &hdr->entries[0];
    for ( ; ; )
    {
        if ( (entry->len + consumed) > hdr->total_len )
        {
            panic("Excess entry length in LCM: (%u + %u) > %u\n",
                  entry->len, consumed, hdr->total_len);
        }
        if ( entry->len & 3 )
            panic("Misaligned entry length in LCM: %u\n", entry->len);

        if ( entry->type == LCM_DATA_MODULE_TYPES )
        {
            /* Validate the number of modules */
            if ( (sizeof(struct lcm_entry) +
                  sizeof(struct lcm_module_types) +
                  entry->module_types.num_modules) > entry->len )
            {
                panic("Incorrect LCM field for number of multiboot modules\n");
            }
            /* Subtract one for the LCM itself */
            if ( entry->module_types.num_modules != mbi->mods_count - 1 )
            {
                printk("WARNING: LCM declared module count (%u) doesn't match "
                       "number of multiboot modules supplied (%u).\n",
                       entry->module_types.num_modules, mbi->mods_count);
            }

            for ( i = 0; i < entry->module_types.num_modules; i++ )
            {
                switch ( entry->module_types.types[i] )
                {
                case LCM_MODULE_LAUNCH_CONTROL_MODULE:
                    printk("WARNING: ignoring LCM multiboot module #%u\n",
                           i + 1);
                    break;

                case LCM_MODULE_DOMAIN_KERNEL:
                    __set_bit(i + 1, module_map_domain_kernel);
                    break;

                case LCM_MODULE_DOMAIN_RAMDISK:
                    __set_bit(i + 1, module_map_ramdisk);
                    break;

                case LCM_MODULE_CPU_MICROCODE:
                    __set_bit(i + 1, module_map_cpu_ucode);
                    break;

                case LCM_MODULE_XSM_FLASK_POLICY:
                    __set_bit(i + 1, module_map_xsm_flask);
                    break;

                default:
                    printk("WARNING: unknown multiboot module type: %u\n",
                           entry->module_types.types[i]);
                case LCM_MODULE_IGNORE:
                    break;
                }
            }
        }

/* TODO: make sure there's only a single LCM_DATA_MODULE_TYPES entry */

        if ( (entry->len + consumed) == hdr->total_len )
            break; /* this was the terminal entry */

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }

    bootstrap_map(NULL);
#endif
}

static bool __initdata has_boot_domain = false;
static bool __initdata has_high_priv_domain = false;
#ifdef CONFIG_BOOT_DOMAIN
static bool __initdata has_hardware_domain = false;

void validate_launch_control_module(const struct lcm_header_info *hdr)
{
    const struct lcm_entry *entry;
    unsigned int consumed;

#define MAX_LCM_SIZE 4096 /* FIXME */
#define MIN_LCM_SIZE ( sizeof(struct lcm_header_info) + \
                       sizeof(struct lcm_entry) * 2  + \
                       sizeof(struct lcm_module_types) + \
                       sizeof(struct lcm_domain) )
    if ( (hdr->total_len > MAX_LCM_SIZE) || (hdr->total_len < MIN_LCM_SIZE) )
        panic("First multiboot module (LCM) reports invalid data length: %u\n",
              hdr->total_len);
    /* TODO: validate it against the mbi size */

    /* Enforce either:
     * a) there is a single boot domain, and a single hardware domain
     * or
     * b) there is a single high_priv domain (ie. a classic "dom0")
     */
    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);

    if ( (entry->len + consumed) == hdr->total_len )
        panic("Insufficient entries in the LCM\n");

    for ( ; ; )
    {
        if ( (entry->len + consumed) > hdr->total_len )
        {
            panic("Excess entry length in LCM: (%u + %u) > %u\n",
                  entry->len, consumed, hdr->total_len);
        }
        if ( entry->len & 3 )
            panic("Misaligned entry length in LCM: %u\n", entry->len);

        if ( entry->type == LCM_DATA_DOMAIN )
        {
            if ( entry->domain.flags & LCM_DOMAIN_HAS_BASIC_CONFIG )
            {
                if ( entry->domain.basic_config.functions &
                        LCM_DOMAIN_FUNCTION_BOOT )
                {
                    if ( has_boot_domain )
                        panic("Multiple boot domains defined in LCM\n");

                    has_boot_domain = true;
                }

                if ( entry->domain.basic_config.permissions &
                        LCM_DOMAIN_PERMISSION_HARDWARE )
                {
                    if ( has_hardware_domain )
                        panic("Multiple hardware domains defined in LCM\n");

                    has_hardware_domain = true;
                }
            }
            else if ( entry->domain.flags & LCM_DOMAIN_HAS_HIGH_PRIV_CONFIG )
            {
                if ( has_high_priv_domain )
                    panic("Multiple high privilege domains defined in LCM\n");

                has_high_priv_domain = true;
            }
        }

        if ( (entry->len + consumed) == hdr->total_len )
            break; /* this was the terminal entry */

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }

    if ( !has_high_priv_domain && !(has_boot_domain && has_hardware_domain) )
        panic("LCM missing either: boot dom + hw dom; or high priv dom\n");
}
#endif

void find_launch_control_module(const module_t *image)
{
#ifdef CONFIG_BOOT_DOMAIN
    unsigned long image_len = image->mod_end;
    const uint32_t lcm_magic_number = LCM_HEADER_MAGIC_NUMBER;
    void *image_start;
    struct lcm_header_info *hdr;

    if ( image_len < sizeof(struct lcm_header_info) )
        return;

    image_start = bootstrap_map(image);
    hdr = (struct lcm_header_info *)image_start;

    if ( memcmp(&hdr->magic_number, &lcm_magic_number, 4) == 0 )
    {
        /* TODO: verify hdr->checksum */

        printk("Found Launch Control Module\n");
        launch_control_enabled = true;

        validate_launch_control_module(hdr);
    }

    bootstrap_map(NULL);
#endif
}

static inline bool check_multiboot_indices(unsigned long k_idx,
                                           unsigned long r_idx,
                                           unsigned long mods_count,
                                       unsigned long *module_map_domain_kernel,
                                       unsigned long *module_map_ramdisk)
{
    /* 0th module is the LCM, so 0 index indicates absence. */

    if ( !k_idx || (k_idx >= mods_count) ||
         !test_bit(k_idx, module_map_domain_kernel) )
        return false;

    if ( (r_idx > 0) && ((r_idx >= mods_count) ||
                        !test_bit(r_idx, module_map_ramdisk)) )
            return false;

    return true;
}

bool find_boot_domain_modules(const module_t *image,
                              unsigned long *module_map_domain_kernel,
                              unsigned long *module_map_ramdisk,
                              unsigned int mods_count,
                              unsigned int *p_k_idx, unsigned int *p_r_idx)
{
#ifdef CONFIG_BOOT_DOMAIN
    void *image_start;
    struct lcm_header_info *hdr;
    const struct lcm_entry *entry;
    unsigned int consumed;

    image_start = bootstrap_map(image);
    hdr = (struct lcm_header_info *)image_start;

    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);
    for ( ; ; )
    {
        if ( (entry->type == LCM_DATA_DOMAIN) &&
             (entry->domain.flags & LCM_DOMAIN_HAS_BASIC_CONFIG) &&
             (entry->domain.basic_config.functions & LCM_DOMAIN_FUNCTION_BOOT) )
        {
            unsigned int k_idx = entry->domain.kernel_index;
            unsigned int r_idx = entry->domain.ramdisk_index;

            if ( !check_multiboot_indices(k_idx, r_idx, mods_count,
                                          module_map_domain_kernel,
                                          module_map_ramdisk) )
                return false;

            *p_r_idx = r_idx;
            *p_k_idx = k_idx;

            return true;
        }

        if ( (entry->len + consumed) == hdr->total_len )
            break; /* this was the terminal entry */

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }

#endif
    return false;
}

/* TODO: refactor common code with find_boot_domain_modules */
bool find_dom0_modules(const module_t *image,
                       unsigned long *module_map_domain_kernel,
                       unsigned long *module_map_ramdisk,
                       unsigned int mods_count,
                       unsigned int *p_k_idx, unsigned int *p_r_idx)
{
#ifdef CONFIG_BOOT_DOMAIN
    void *image_start;
    struct lcm_header_info *hdr;
    const struct lcm_entry *entry;
    unsigned int consumed;

    image_start = bootstrap_map(image);
    hdr = (struct lcm_header_info *)image_start;

    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);
    for ( ; ; )
    {
        if ( (entry->type == LCM_DATA_DOMAIN) &&
             (entry->domain.flags & LCM_DOMAIN_HAS_HIGH_PRIV_CONFIG) )
        {
            unsigned int k_idx = entry->domain.kernel_index;
            unsigned int r_idx = entry->domain.ramdisk_index;

            if ( !check_multiboot_indices(k_idx, r_idx, mods_count,
                                          module_map_domain_kernel,
                                          module_map_ramdisk) )
                return false;

            *p_r_idx = r_idx;
            *p_k_idx = k_idx;

            return true;
        }

        if ( (entry->len + consumed) == hdr->total_len )
            break; /* this was the terminal entry */

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }

#endif
    return false;
}

/* TODO: refactor common code with find_boot_domain_modules */
bool find_domain_modules(const module_t *lcm_image,
                         unsigned long *module_map_domain_kernel,
                         unsigned long *module_map_ramdisk,
                         unsigned int mods_count,
                         unsigned int domain_idx,
                         unsigned int *p_k_idx, unsigned int *p_r_idx,
                         struct lcm_domain_basic_config *p_cfg)
{
    bool rc = false;
#ifdef CONFIG_BOOT_DOMAIN
    void *image_start;
    struct lcm_header_info *hdr;
    const struct lcm_entry *entry;
    unsigned int consumed, cur_idx = 0;

    image_start = bootstrap_map(lcm_image);
    hdr = (struct lcm_header_info *)image_start;

    entry = &hdr->entries[0];
    consumed = sizeof(struct lcm_header_info);
    for ( ; ; )
    {
        if ( (entry->type == LCM_DATA_DOMAIN) &&
             (entry->domain.flags & LCM_DOMAIN_HAS_BASIC_CONFIG) )
        {
            unsigned int k_idx, r_idx;

            /* The boot domain has been accounted for - don't count it. */
            /* Seeking the nth domain basic config, indicated by the index. */
            if ( (entry->domain.basic_config.functions &
                        LCM_DOMAIN_FUNCTION_BOOT) ||
                 (cur_idx++ != domain_idx) )
            {
                if ( (entry->len + consumed) == hdr->total_len )
                    break; /* this was the terminal entry */

                consumed += entry->len;
                entry = (const struct lcm_entry *)
                            (((uint8_t *)entry) + entry->len);
                continue;
            }

            k_idx = entry->domain.kernel_index;
            r_idx = entry->domain.ramdisk_index;

            if ( !check_multiboot_indices(k_idx, r_idx, mods_count,
                                          module_map_domain_kernel,
                                          module_map_ramdisk) )
                break;

            *p_r_idx = r_idx;
            *p_k_idx = k_idx;
            *p_cfg = entry->domain.basic_config;
            rc = true;

            break;
        }

        if ( (entry->len + consumed) == hdr->total_len )
            break; /* this was the terminal entry */

        consumed += entry->len;
        entry = (const struct lcm_entry *)(((uint8_t *)entry) + entry->len);
    }

    bootstrap_map(NULL);
#endif
    return rc;
}

/* How much of the directmap is prebuilt at compile time. */
#define PREBUILT_MAP_LIMIT (1 << L2_PAGETABLE_SHIFT)

void __init noreturn __start_xen(unsigned long mbi_p)
{
    char *memmap_type = NULL;
    char *cmdline, *kextra, *loader;
    unsigned int dom0_kernel_idx = 0, dom0_ramdisk_idx = 0;
    unsigned int boot_dom_kernel_idx = 0, boot_dom_ramdisk_idx = 0;
    unsigned int num_parked = 0;
    multiboot_info_t *mbi;
    module_t *mod;
    unsigned long nr_pages, raw_max_page;
#define MODULE_MAP_SZ 1
    unsigned long module_map[MODULE_MAP_SZ];
    unsigned long raw_module_map_xsm_flask[MODULE_MAP_SZ];
    unsigned long raw_module_map_cpu_ucode[MODULE_MAP_SZ];
    unsigned long raw_module_map_domain_kernel[MODULE_MAP_SZ];
    unsigned long raw_module_map_ramdisk[MODULE_MAP_SZ];
    unsigned long *module_map_xsm_flask = raw_module_map_xsm_flask;
    unsigned long *module_map_cpu_ucode = raw_module_map_cpu_ucode;
    unsigned long *module_map_domain_kernel = raw_module_map_domain_kernel;
    unsigned long *module_map_ramdisk = raw_module_map_ramdisk;
    unsigned long modules_headroom[MAX_MULTIBOOT_MODS_COUNT];
    int i, j, e820_warn = 0, bytes = 0;
    bool acpi_boot_table_init_done = false, relocated = false;
    int ret;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };
    struct xen_domctl_createdomain dom0_cfg = {
        .flags = IS_ENABLED(CONFIG_TBOOT) ? XEN_DOMCTL_CDF_s3_integrity : 0,
        .max_evtchn_port = -1,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
    };
    const char *hypervisor_name;
    struct domain *dom0 = NULL; /* faulty compiler maybe-uninitialized */

    /* Critical region without IDT or TSS.  Any fault is deadly! */

    init_shadow_spec_ctrl_state();

    percpu_init_areas();

    init_idt_traps();
    load_system_tables();

    smp_prepare_boot_cpu();
    sort_exception_tables();

    setup_virtual_regions(__start___ex_table, __stop___ex_table);

    /* Full exception support from here on in. */

    /* Enable NMIs.  Our loader (e.g. Tboot) may have left them disabled. */
    enable_nmis();

    if ( pvh_boot )
    {
        /*
         * Force xen console to be enabled. We will reset it later in console
         * initialisation code.
         */
        opt_console_xen = -1;
        ASSERT(mbi_p == 0);
        pvh_init(&mbi, &mod);
    }
    else
    {
        mbi = __va(mbi_p);
        mod = __va(mbi->mods_addr);
    }

    loader = (mbi->flags & MBI_LOADERNAME)
        ? (char *)__va(mbi->boot_loader_name) : "unknown";

    /* Parse the command-line options. */
    cmdline = cmdline_cook((mbi->flags & MBI_CMDLINE) ?
                           __va(mbi->cmdline) : NULL,
                           loader);
    if ( (kextra = strstr(cmdline, " -- ")) != NULL )
    {
        /*
         * Options after ' -- ' separator belong to dom0.
         *  1. Orphan dom0's options from Xen's command line.
         *  2. Skip all but final leading space from dom0's options.
         */
        *kextra = '\0';
        kextra += 3;
        while ( kextra[1] == ' ' ) kextra++;
    }
    cmdline_parse(cmdline);

    /* Must be after command line argument parsing and before
     * allocing any xenheap structures wanted in lower memory. */
    kexec_early_calculations();

    /*
     * The probing has to be done _before_ initialising console,
     * otherwise we couldn't set up Xen's PV console correctly.
     */
    hypervisor_name = hypervisor_probe();

    parse_video_info();

    rdmsrl(MSR_EFER, this_cpu(efer));
    asm volatile ( "mov %%cr4,%0" : "=r" (get_cpu_info()->cr4) );

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550.irq     = 4;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550.irq     = 3;
    ns16550_init(1, &ns16550);
    ehci_dbgp_init();
    console_init_preirq();

    if ( pvh_boot )
        pvh_print_info();

    printk("Bootloader: %s\n", loader);

    printk("Command line: %s\n", cmdline);

    printk("Xen image load base address: %#lx\n", xen_phys_start);
    if ( hypervisor_name )
        printk("Running on %s\n", hypervisor_name);

#ifdef CONFIG_VIDEO
    printk("Video information:\n");

    /* Print VGA display mode information. */
    switch ( vga_console_info.video_type )
    {
    case XEN_VGATYPE_TEXT_MODE_3:
        printk(" VGA is text mode %dx%d, font 8x%d\n",
               vga_console_info.u.text_mode_3.columns,
               vga_console_info.u.text_mode_3.rows,
               vga_console_info.u.text_mode_3.font_height);
        break;
    case XEN_VGATYPE_VESA_LFB:
    case XEN_VGATYPE_EFI_LFB:
        printk(" VGA is graphics mode %dx%d, %d bpp\n",
               vga_console_info.u.vesa_lfb.width,
               vga_console_info.u.vesa_lfb.height,
               vga_console_info.u.vesa_lfb.bits_per_pixel);
        break;
    default:
        printk(" No VGA detected\n");
        break;
    }

    /* Print VBE/DDC EDID information. */
    if ( bootsym(boot_edid_caps) != 0x1313 )
    {
        u16 caps = bootsym(boot_edid_caps);
        printk(" VBE/DDC methods:%s%s%s; ",
               (caps & 1) ? " V1" : "",
               (caps & 2) ? " V2" : "",
               !(caps & 3) ? " none" : "");
        printk("EDID transfer time: %d seconds\n", caps >> 8);
        if ( *(u32 *)bootsym(boot_edid_info) == 0x13131313 )
        {
            printk(" EDID info not retrieved because ");
            if ( !(caps & 3) )
                printk("no DDC retrieval method detected\n");
            else if ( (caps >> 8) > 5 )
                printk("takes longer than 5 seconds\n");
            else
                printk("of reasons unknown\n");
        }
    }
#endif

    printk("Disc information:\n");
    printk(" Found %d MBR signatures\n",
           bootsym(boot_mbr_signature_nr));
    printk(" Found %d EDD information structures\n",
           bootsym(boot_edd_info_nr));

    /* Check that we have at least one Multiboot module. */
    if ( !(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0) )
        panic("dom0 kernel not specified. Check bootloader configuration\n");

    /* Check that we don't have a silly number of modules. */
    ASSERT(MAX_MULTIBOOT_MODS_COUNT <= sizeof(module_map) * 8);
    if ( mbi->mods_count > MAX_MULTIBOOT_MODS_COUNT )
    {
        mbi->mods_count = MAX_MULTIBOOT_MODS_COUNT;
        printk("Excessive multiboot modules - using the first %u only\n",
               mbi->mods_count);
    }

    bitmap_fill(module_map, mbi->mods_count);
    __clear_bit(0, module_map); /* first module is always used */

    if ( pvh_boot )
    {
        /* pvh_init() already filled in e820_raw */
        memmap_type = "PVH-e820";
    }
    else if ( efi_enabled(EFI_LOADER) )
    {
        set_pdx_range(xen_phys_start >> PAGE_SHIFT,
                      (xen_phys_start + BOOTSTRAP_MAP_BASE) >> PAGE_SHIFT);

        /* Clean up boot loader identity mappings. */
        destroy_xen_mappings(xen_phys_start,
                             xen_phys_start + BOOTSTRAP_MAP_BASE);

        /* Make boot page tables match non-EFI boot. */
        l3_bootmap[l3_table_offset(BOOTSTRAP_MAP_BASE)] =
            l3e_from_paddr(__pa(l2_bootmap), __PAGE_HYPERVISOR);

        memmap_type = loader;
    }
    else if ( efi_enabled(EFI_BOOT) )
        memmap_type = "EFI";
    else if ( (e820_raw.nr_map = 
                   copy_bios_e820(e820_raw.map,
                                  ARRAY_SIZE(e820_raw.map))) != 0 )
    {
        memmap_type = "Xen-e820";
    }
    else if ( mbi->flags & MBI_MEMMAP )
    {
        memmap_type = "Multiboot-e820";
        while ( bytes < mbi->mmap_length &&
                e820_raw.nr_map < ARRAY_SIZE(e820_raw.map) )
        {
            memory_map_t *map = __va(mbi->mmap_addr + bytes);

            /*
             * This is a gross workaround for a BIOS bug. Some bootloaders do
             * not write e820 map entries into pre-zeroed memory. This is
             * okay if the BIOS fills in all fields of the map entry, but
             * some broken BIOSes do not bother to write the high word of
             * the length field if the length is smaller than 4GB. We
             * detect and fix this by flagging sections below 4GB that
             * appear to be larger than 4GB in size.
             */
            if ( (map->base_addr_high == 0) && (map->length_high != 0) )
            {
                if ( !e820_warn )
                {
                    printk("WARNING: Buggy e820 map detected and fixed "
                           "(truncated length fields).\n");
                    e820_warn = 1;
                }
                map->length_high = 0;
            }

            e820_raw.map[e820_raw.nr_map].addr =
                ((u64)map->base_addr_high << 32) | (u64)map->base_addr_low;
            e820_raw.map[e820_raw.nr_map].size =
                ((u64)map->length_high << 32) | (u64)map->length_low;
            e820_raw.map[e820_raw.nr_map].type = map->type;
            e820_raw.nr_map++;

            bytes += map->size + 4;
        }
    }
    else if ( bootsym(lowmem_kb) )
    {
        memmap_type = "Xen-e801";
        e820_raw.map[0].addr = 0;
        e820_raw.map[0].size = bootsym(lowmem_kb) << 10;
        e820_raw.map[0].type = E820_RAM;
        e820_raw.map[1].addr = 0x100000;
        e820_raw.map[1].size = bootsym(highmem_kb) << 10;
        e820_raw.map[1].type = E820_RAM;
        e820_raw.nr_map = 2;
    }
    else if ( mbi->flags & MBI_MEMLIMITS )
    {
        memmap_type = "Multiboot-e801";
        e820_raw.map[0].addr = 0;
        e820_raw.map[0].size = mbi->mem_lower << 10;
        e820_raw.map[0].type = E820_RAM;
        e820_raw.map[1].addr = 0x100000;
        e820_raw.map[1].size = mbi->mem_upper << 10;
        e820_raw.map[1].type = E820_RAM;
        e820_raw.nr_map = 2;
    }
    else
        panic("Bootloader provided no memory information\n");

    /* This must come before e820 code because it sets paddr_bits. */
    early_cpu_init();

    /* Sanitise the raw E820 map to produce a final clean version. */
    max_page = raw_max_page = init_e820(memmap_type, &e820_raw);

    if ( !efi_enabled(EFI_BOOT) && e820_raw.nr_map >= 1 )
    {
        /*
         * Supplement the heuristics in l1tf_calculations() by assuming that
         * anything referenced in the E820 may be cacheable.
         */
        l1tf_safe_maddr =
            max(l1tf_safe_maddr,
                ROUNDUP(e820_raw.map[e820_raw.nr_map - 1].addr +
                        e820_raw.map[e820_raw.nr_map - 1].size, PAGE_SIZE));
    }

    /* Create a temporary copy of the E820 map. */
    memcpy(&boot_e820, &e820, sizeof(e820));

    /* Early kexec reservation (explicit static start address). */
    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
    set_kexec_crash_area_size((u64)nr_pages << PAGE_SHIFT);
    kexec_reserve_area(&boot_e820);

    initial_images = mod;
    nr_initial_images = mbi->mods_count;

    for ( i = 0; !efi_enabled(EFI_LOADER) && i < mbi->mods_count; i++ )
    {
        if ( mod[i].mod_start & (PAGE_SIZE - 1) )
            panic("Bootloader didn't honor module alignment request\n");
        mod[i].mod_end -= mod[i].mod_start;
        mod[i].mod_start >>= PAGE_SHIFT;
        mod[i].reserved = 0;
    }

    if ( xen_phys_start )
    {
        relocated = true;

        /*
         * This needs to remain in sync with xen_in_range() and the
         * respective reserve_e820_ram() invocation below.
         */
        mod[mbi->mods_count].mod_start = virt_to_mfn(_stext);
        mod[mbi->mods_count].mod_end = __2M_rwdata_end - _stext;
    }

    find_launch_control_module(mod); /* sets launch_control_enabled */

    if ( launch_control_enabled )
    {
        populate_module_maps(mbi, mod, module_map_xsm_flask,
                             module_map_cpu_ucode, module_map_domain_kernel,
                             module_map_ramdisk);

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            if ( test_bit(i, module_map_domain_kernel) )
            {
                modules_headroom[i] = bzimage_headroom(
                                        bootstrap_map(&mod[i]), mod[i].mod_end);
                bootstrap_map(NULL);
            }
            else
                modules_headroom[i] = 0;
        }
    }
    else
    {
        module_map_xsm_flask = module_map;
        module_map_cpu_ucode = module_map;
        module_map_domain_kernel = module_map;
        module_map_ramdisk = module_map;

        modules_headroom[0] = bzimage_headroom(bootstrap_map(mod),
                                               mod->mod_end);
        bootstrap_map(NULL);

        for ( i = 1; i < mbi->mods_count ; i++ )
            modules_headroom[i] = 0;
    }

#ifndef highmem_start
    /* Don't allow split below 4Gb. */
    if ( highmem_start < GB(4) )
        highmem_start = 0;
    else /* align to L3 entry boundary */
        highmem_start &= ~((1UL << L3_PAGETABLE_SHIFT) - 1);
#endif

    /*
     * Iterate backwards over all superpage-aligned RAM regions.
     *
     * We require superpage alignment because the boot allocator is
     * not yet initialised. Hence we can only map superpages in the
     * address range PREBUILT_MAP_LIMIT to 4GB, as this is guaranteed
     * not to require dynamic allocation of pagetables.
     *
     * As well as mapping superpages in that range, in preparation for
     * initialising the boot allocator, we also look for a region to which
     * we can relocate the dom0 kernel and other multiboot modules. Also, on
     * x86/64, we relocate Xen to higher memory.
     */
    for ( i = boot_e820.nr_map-1; i >= 0; i-- )
    {
        uint64_t s, e, mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        uint64_t end, limit = ARRAY_SIZE(l2_directmap) << L2_PAGETABLE_SHIFT;

        if ( boot_e820.map[i].type != E820_RAM )
            continue;

        /* Superpage-aligned chunks from PREBUILT_MAP_LIMIT. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, PREBUILT_MAP_LIMIT);
        if ( s >= e )
            continue;

        if ( s < limit )
        {
            end = min(e, limit);
            set_pdx_range(s >> PAGE_SHIFT, end >> PAGE_SHIFT);
            map_pages_to_xen((unsigned long)__va(s), maddr_to_mfn(s),
                             PFN_DOWN(end - s), PAGE_HYPERVISOR);
        }

        if ( e > min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                     1UL << (PAGE_SHIFT + 32)) )
            e = min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                    1UL << (PAGE_SHIFT + 32));
#define reloc_size ((__pa(__2M_rwdata_end) + mask) & ~mask)
        /* Is the region suitable for relocating Xen? */
        if ( !xen_phys_start && e <= limit )
        {
            /* Don't overlap with modules. */
            end = consider_modules(s, e, reloc_size + mask,
                                   mod, mbi->mods_count, -1);
            end &= ~mask;
        }
        else
            end = 0;

        /*
         * Is the region size greater than zero and does it begin
         * at or above the end of current Xen image placement?
         */
        if ( (end > s) && (end - reloc_size + XEN_IMG_OFFSET >= __pa(_end)) )
        {
            l4_pgentry_t *pl4e;
            l3_pgentry_t *pl3e;
            l2_pgentry_t *pl2e;
            int i, j, k;
            unsigned long pte_update_limit;

            /* Select relocation address. */
            xen_phys_start = end - reloc_size;
            e = xen_phys_start + XEN_IMG_OFFSET;
            bootsym(trampoline_xen_phys_start) = xen_phys_start;

            /*
             * No PTEs pointing above this address are candidates for relocation.
             * Due to possibility of partial overlap of the end of source image
             * and the beginning of region for destination image some PTEs may
             * point to addresses in range [e, e + XEN_IMG_OFFSET).
             */
            pte_update_limit = PFN_DOWN(e);

            /*
             * Perform relocation to new physical address.
             * Before doing so we must sync static/global data with main memory
             * with a barrier(). After this we must *not* modify static/global
             * data until after we have switched to the relocated pagetables!
             */
            barrier();
            move_memory(e, XEN_IMG_OFFSET, _end - _start, 1);

            /* Walk initial pagetables, relocating page directory entries. */
            pl4e = __va(__pa(idle_pg_table));
            for ( i = 0 ; i < L4_PAGETABLE_ENTRIES; i++, pl4e++ )
            {
                if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
                    continue;
                *pl4e = l4e_from_intpte(l4e_get_intpte(*pl4e) +
                                        xen_phys_start);
                pl3e = l4e_to_l3e(*pl4e);
                for ( j = 0; j < L3_PAGETABLE_ENTRIES; j++, pl3e++ )
                {
                    /* Not present, 1GB mapping, or already relocated? */
                    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) ||
                         (l3e_get_flags(*pl3e) & _PAGE_PSE) ||
                         (l3e_get_pfn(*pl3e) >= pte_update_limit) )
                        continue;
                    *pl3e = l3e_from_intpte(l3e_get_intpte(*pl3e) +
                                            xen_phys_start);
                    pl2e = l3e_to_l2e(*pl3e);
                    for ( k = 0; k < L2_PAGETABLE_ENTRIES; k++, pl2e++ )
                    {
                        /* Not present, PSE, or already relocated? */
                        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) ||
                             (l2e_get_flags(*pl2e) & _PAGE_PSE) ||
                             (l2e_get_pfn(*pl2e) >= pte_update_limit) )
                            continue;
                        *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) +
                                                xen_phys_start);
                    }
                }
            }

            /* The only data mappings to be relocated are in the Xen area. */
            pl2e = __va(__pa(l2_xenmap));
            /*
             * Undo the temporary-hooking of the l1_directmap.  __2M_text_start
             * is contained in this PTE.
             */
            BUG_ON(using_2M_mapping() &&
                   l2_table_offset((unsigned long)_erodata) ==
                   l2_table_offset((unsigned long)_stext));
            *pl2e++ = l2e_from_pfn(xen_phys_start >> PAGE_SHIFT,
                                   PAGE_HYPERVISOR_RX | _PAGE_PSE);
            for ( i = 1; i < L2_PAGETABLE_ENTRIES; i++, pl2e++ )
            {
                unsigned int flags;

                if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) ||
                     (l2e_get_pfn(*pl2e) >= pte_update_limit) )
                    continue;

                if ( !using_2M_mapping() )
                {
                    *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) +
                                            xen_phys_start);
                    continue;
                }

                if ( i < l2_table_offset((unsigned long)&__2M_text_end) )
                {
                    flags = PAGE_HYPERVISOR_RX | _PAGE_PSE;
                }
                else if ( i >= l2_table_offset((unsigned long)&__2M_rodata_start) &&
                          i <  l2_table_offset((unsigned long)&__2M_rodata_end) )
                {
                    flags = PAGE_HYPERVISOR_RO | _PAGE_PSE;
                }
                else if ( i >= l2_table_offset((unsigned long)&__2M_init_start) &&
                          i <  l2_table_offset((unsigned long)&__2M_init_end) )
                {
                    flags = PAGE_HYPERVISOR_RWX | _PAGE_PSE;
                }
                else if ( (i >= l2_table_offset((unsigned long)&__2M_rwdata_start) &&
                           i <  l2_table_offset((unsigned long)&__2M_rwdata_end)) )
                {
                    flags = PAGE_HYPERVISOR_RW | _PAGE_PSE;
                }
                else
                {
                    *pl2e = l2e_empty();
                    continue;
                }

                *pl2e = l2e_from_paddr(
                    l2e_get_paddr(*pl2e) + xen_phys_start, flags);
            }

            /* Re-sync the stack and then switch to relocated pagetables. */
            asm volatile (
                "rep movsq        ; " /* re-sync the stack */
                "movq %%cr4,%%rsi ; "
                "andb $0x7f,%%sil ; "
                "movq %%rsi,%%cr4 ; " /* CR4.PGE == 0 */
                "movq %[pg],%%cr3 ; " /* CR3 == new pagetables */
                "orb $0x80,%%sil  ; "
                "movq %%rsi,%%cr4   " /* CR4.PGE == 1 */
                : "=&S" (i), "=&D" (i), "=&c" (i) /* All outputs discarded. */
                :  [pg] "r" (__pa(idle_pg_table)), "0" (cpu0_stack),
                   "1" (__va(__pa(cpu0_stack))), "2" (STACK_SIZE / 8)
                : "memory" );

            bootstrap_map(NULL);

            printk("New Xen image base address: %#lx\n", xen_phys_start);
        }

        /* Is the region suitable for relocating the multiboot modules? */
        for ( j = mbi->mods_count - 1; j >= 0; j-- )
        {
            unsigned long headroom = modules_headroom[j];
            unsigned long size = PAGE_ALIGN(headroom + mod[j].mod_end);

            if ( mod[j].reserved )
                continue;

            /* Don't overlap with other modules (or Xen itself). */
            end = consider_modules(s, e, size, mod,
                                   mbi->mods_count + relocated, j);

            if ( highmem_start && end > highmem_start )
                continue;

            if ( s < end &&
                 (headroom ||
                  ((end - size) >> PAGE_SHIFT) > mod[j].mod_start) )
            {
                move_memory(end - size + headroom,
                            (uint64_t)mod[j].mod_start << PAGE_SHIFT,
                            mod[j].mod_end, 0);
                mod[j].mod_start = (end - size) >> PAGE_SHIFT;
                mod[j].mod_end += headroom;
                mod[j].reserved = 1;
            }
        }

#ifdef CONFIG_KEXEC
        /*
         * Looking backwards from the crash area limit, find a large
         * enough range that does not overlap with modules.
         */
        while ( !kexec_crash_area.start )
        {
            /* Don't overlap with modules (or Xen itself). */
            e = consider_modules(s, e, PAGE_ALIGN(kexec_crash_area.size), mod,
                                 mbi->mods_count + relocated, -1);
            if ( s >= e )
                break;
            if ( e > kexec_crash_area_limit )
            {
                e = kexec_crash_area_limit & PAGE_MASK;
                continue;
            }
            kexec_crash_area.start = (e - kexec_crash_area.size) & PAGE_MASK;
        }
#endif
    }

    for ( i = 0; i < mbi->mods_count; ++i )
    {
        uint64_t s = (uint64_t)mod[i].mod_start << PAGE_SHIFT;

        if ( modules_headroom[i] && !mod[i].reserved )
            panic("Not enough memory to relocate kernel image, mod: %d\n", i);

        reserve_e820_ram(&boot_e820, s, s + PAGE_ALIGN(mod[i].mod_end));
    }

    if ( !xen_phys_start )
        panic("Not enough memory to relocate Xen\n");

    /* This needs to remain in sync with xen_in_range(). */
    reserve_e820_ram(&boot_e820, __pa(_stext), __pa(__2M_rwdata_end));

    /* Late kexec reservation (dynamic start address). */
    kexec_reserve_area(&boot_e820);

    setup_max_pdx(raw_max_page);
    if ( highmem_start )
        xenheap_max_mfn(PFN_DOWN(highmem_start - 1));

    /*
     * Walk every RAM region and map it in its entirety (on x86/64, at least)
     * and notify it to the boot allocator.
     */
    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        uint64_t s, e, mask = PAGE_SIZE - 1;
        uint64_t map_s, map_e;

        if ( boot_e820.map[i].type != E820_RAM )
            continue;

        /* Only page alignment required now. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, 1<<20);
        if ( s >= e )
            continue;

        if ( !acpi_boot_table_init_done &&
             s >= (1ULL << 32) &&
             !acpi_boot_table_init() )
        {
            acpi_boot_table_init_done = true;
            srat_parse_regions(s);
            setup_max_pdx(raw_max_page);
        }

        if ( pfn_to_pdx((e - 1) >> PAGE_SHIFT) >= max_pdx )
        {
            if ( pfn_to_pdx(s >> PAGE_SHIFT) >= max_pdx )
            {
                for ( j = i - 1; ; --j )
                {
                    if ( boot_e820.map[j].type == E820_RAM )
                        break;
                    ASSERT(j);
                }
                map_e = boot_e820.map[j].addr + boot_e820.map[j].size;
                for ( j = 0; j < mbi->mods_count; ++j )
                {
                    uint64_t end = pfn_to_paddr(mod[j].mod_start) +
                                   mod[j].mod_end;

                    if ( map_e < end )
                        map_e = end;
                }
                if ( PFN_UP(map_e) < max_page )
                {
                    max_page = PFN_UP(map_e);
                    max_pdx = pfn_to_pdx(max_page - 1) + 1;
                }
                printk(XENLOG_WARNING "Ignoring inaccessible memory range"
                                      " %013"PRIx64"-%013"PRIx64"\n",
                       s, e);
                continue;
            }
            map_e = e;
            e = (pdx_to_pfn(max_pdx - 1) + 1ULL) << PAGE_SHIFT;
            printk(XENLOG_WARNING "Ignoring inaccessible memory range"
                                  " %013"PRIx64"-%013"PRIx64"\n",
                   e, map_e);
        }

        set_pdx_range(s >> PAGE_SHIFT, e >> PAGE_SHIFT);

        /* Need to create mappings above PREBUILT_MAP_LIMIT. */
        map_s = max_t(uint64_t, s, PREBUILT_MAP_LIMIT);
        map_e = min_t(uint64_t, e,
                      ARRAY_SIZE(l2_directmap) << L2_PAGETABLE_SHIFT);

        /* Pass mapped memory to allocator /before/ creating new mappings. */
        init_boot_pages(s, min(map_s, e));
        s = map_s;
        if ( s < map_e )
        {
            uint64_t mask = (1UL << L2_PAGETABLE_SHIFT) - 1;

            map_s = (s + mask) & ~mask;
            map_e &= ~mask;
            init_boot_pages(map_s, map_e);
        }

        if ( map_s > map_e )
            map_s = map_e = s;

        /* Create new mappings /before/ passing memory to the allocator. */
        if ( map_e < e )
        {
            uint64_t limit = __pa(HYPERVISOR_VIRT_END - 1) + 1;
            uint64_t end = min(e, limit);

            if ( map_e < end )
            {
                map_pages_to_xen((unsigned long)__va(map_e), maddr_to_mfn(map_e),
                                 PFN_DOWN(end - map_e), PAGE_HYPERVISOR);
                init_boot_pages(map_e, end);
                map_e = end;
            }
        }
        if ( map_e < e )
        {
            /* This range must not be passed to the boot allocator and
             * must also not be mapped with _PAGE_GLOBAL. */
            map_pages_to_xen((unsigned long)__va(map_e), maddr_to_mfn(map_e),
                             PFN_DOWN(e - map_e), __PAGE_HYPERVISOR_RW);
        }
        if ( s < map_s )
        {
            map_pages_to_xen((unsigned long)__va(s), maddr_to_mfn(s),
                             PFN_DOWN(map_s - s), PAGE_HYPERVISOR);
            init_boot_pages(s, map_s);
        }
    }

    for ( i = 0; i < mbi->mods_count; ++i )
    {
        set_pdx_range(mod[i].mod_start,
                      mod[i].mod_start + PFN_UP(mod[i].mod_end));
        map_pages_to_xen((unsigned long)mfn_to_virt(mod[i].mod_start),
                         _mfn(mod[i].mod_start),
                         PFN_UP(mod[i].mod_end), PAGE_HYPERVISOR);
    }

#ifdef CONFIG_KEXEC
    if ( kexec_crash_area.size )
    {
        unsigned long s = PFN_DOWN(kexec_crash_area.start);
        unsigned long e = min(s + PFN_UP(kexec_crash_area.size),
                              PFN_UP(__pa(HYPERVISOR_VIRT_END - 1)));

        if ( e > s ) 
            map_pages_to_xen((unsigned long)__va(kexec_crash_area.start),
                             _mfn(s), e - s, PAGE_HYPERVISOR);
    }
#endif

    xen_virt_end = ((unsigned long)_end + (1UL << L2_PAGETABLE_SHIFT) - 1) &
                   ~((1UL << L2_PAGETABLE_SHIFT) - 1);
    destroy_xen_mappings(xen_virt_end, XEN_VIRT_START + BOOTSTRAP_MAP_BASE);

    /*
     * If not using 2M mappings to gain suitable pagetable permissions
     * directly from the relocation above, remap the code/data
     * sections with decreased permissions.
     */
    if ( !using_2M_mapping() )
    {
        /* Mark .text as RX (avoiding the first 2M superpage). */
        modify_xen_mappings(XEN_VIRT_START + MB(2),
                            (unsigned long)&__2M_text_end,
                            PAGE_HYPERVISOR_RX);

        /* Mark .rodata as RO. */
        modify_xen_mappings((unsigned long)&__2M_rodata_start,
                            (unsigned long)&__2M_rodata_end,
                            PAGE_HYPERVISOR_RO);

        /* Mark .data and .bss as RW. */
        modify_xen_mappings((unsigned long)&__2M_rwdata_start,
                            (unsigned long)&__2M_rwdata_end,
                            PAGE_HYPERVISOR_RW);

        /* Drop the remaining mappings in the shattered superpage. */
        destroy_xen_mappings((unsigned long)&__2M_rwdata_end,
                             ROUNDUP((unsigned long)&__2M_rwdata_end, MB(2)));
    }

    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
    printk("System RAM: %luMB (%lukB)\n",
           nr_pages >> (20 - PAGE_SHIFT),
           nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    /* Sanity check for unwanted bloat of certain hypercall structures. */
    BUILD_BUG_ON(sizeof(((struct xen_platform_op *)0)->u) !=
                 sizeof(((struct xen_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_domctl *)0)->u) !=
                 sizeof(((struct xen_domctl *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_sysctl *)0)->u) !=
                 sizeof(((struct xen_sysctl *)0)->u.pad));

    BUILD_BUG_ON(sizeof(start_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(shared_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct vcpu_info) != 64);

    BUILD_BUG_ON(sizeof(((struct compat_platform_op *)0)->u) !=
                 sizeof(((struct compat_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(start_info_compat_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct compat_vcpu_info) != 64);

    /* Check definitions in public headers match internal defs. */
    BUILD_BUG_ON(__HYPERVISOR_VIRT_START != HYPERVISOR_VIRT_START);
    BUILD_BUG_ON(__HYPERVISOR_VIRT_END   != HYPERVISOR_VIRT_END);
    BUILD_BUG_ON(MACH2PHYS_VIRT_START != RO_MPT_VIRT_START);
    BUILD_BUG_ON(MACH2PHYS_VIRT_END   != RO_MPT_VIRT_END);

    init_frametable();

    if ( !acpi_boot_table_init_done )
        acpi_boot_table_init();

    acpi_numa_init();

    numa_initmem_init(0, raw_max_page);

    if ( max_page - 1 > virt_to_mfn(HYPERVISOR_VIRT_END - 1) )
    {
        unsigned long limit = virt_to_mfn(HYPERVISOR_VIRT_END - 1);
        uint64_t mask = PAGE_SIZE - 1;

        if ( !highmem_start )
            xenheap_max_mfn(limit);

        end_boot_allocator();

        /* Pass the remaining memory to the allocator. */
        for ( i = 0; i < boot_e820.nr_map; i++ )
        {
            uint64_t s, e;

            if ( boot_e820.map[i].type != E820_RAM )
                continue;
            s = (boot_e820.map[i].addr + mask) & ~mask;
            e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
            if ( PFN_DOWN(e) <= limit )
                continue;
            if ( PFN_DOWN(s) <= limit )
                s = pfn_to_paddr(limit + 1);
            init_domheap_pages(s, e);
        }
    }
    else
        end_boot_allocator();

    system_state = SYS_STATE_boot;
    /*
     * No calls involving ACPI code should go between the setting of
     * SYS_STATE_boot and vm_init() (or else acpi_os_{,un}map_memory()
     * will break).
     */
    vm_init();

    console_init_ring();
    vesa_init();

    tasklet_subsys_init();

    paging_init();

    tboot_probe();

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    find_smp_config();

    dmi_scan_machine();

    generic_apic_probe();

    mmio_ro_ranges = rangeset_new(NULL, "r/o mmio ranges",
                                  RANGESETF_prettyprint_hex);

    xsm_multiboot_init(module_map_xsm_flask, mbi);

    setup_system_domains();

    acpi_boot_init();

    if ( smp_found_config )
        get_smp_config();

    /*
     * In the shim case, the number of CPUs should be solely controlled by the
     * guest configuration file.
     */
    if ( pv_shim )
    {
        opt_nosmp = false;
        max_cpus = 0;
    }
    if ( opt_nosmp )
    {
        max_cpus = 0;
        set_nr_cpu_ids(1);
    }
    else
    {
        set_nr_cpu_ids(max_cpus);
        if ( !max_cpus )
            max_cpus = nr_cpu_ids;
    }

    if ( hypervisor_name )
        hypervisor_setup();

    /* Low mappings were only needed for some BIOS table parsing. */
    zap_low_mappings();

    init_apic_mappings();

    normalise_cpu_order();

    init_cpu_to_node();

    x2apic_bsp_setup();

    ret = init_irq_data();
    if ( ret < 0 )
        panic("Error %d setting up IRQ data\n", ret);

    console_init_irq();

    init_IRQ();

    microcode_grab_module(module_map_cpu_ucode, mbi);

    timer_init();

    early_microcode_init();

    tsx_init(); /* Needs microcode.  May change HLE/RTM feature bits. */

    identify_cpu(&boot_cpu_data);

    set_in_cr4(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);

    /* Do not enable SMEP/SMAP in PV shim on AMD and Hygon by default */
    if ( opt_smep == -1 )
        opt_smep = !pv_shim || !(boot_cpu_data.x86_vendor &
                                 (X86_VENDOR_AMD | X86_VENDOR_HYGON));
    if ( opt_smap == -1 )
        opt_smap = !pv_shim || !(boot_cpu_data.x86_vendor &
                                 (X86_VENDOR_AMD | X86_VENDOR_HYGON));

    if ( !opt_smep )
        setup_clear_cpu_cap(X86_FEATURE_SMEP);
    if ( cpu_has_smep && opt_smep != SMEP_HVM_ONLY )
        setup_force_cpu_cap(X86_FEATURE_XEN_SMEP);
    if ( boot_cpu_has(X86_FEATURE_XEN_SMEP) )
        set_in_cr4(X86_CR4_SMEP);

    if ( !opt_smap )
        setup_clear_cpu_cap(X86_FEATURE_SMAP);
    if ( cpu_has_smap && opt_smap != SMAP_HVM_ONLY )
        setup_force_cpu_cap(X86_FEATURE_XEN_SMAP);
    if ( boot_cpu_has(X86_FEATURE_XEN_SMAP) )
        set_in_cr4(X86_CR4_SMAP);

    cr4_pv32_mask = mmu_cr4_features & XEN_CR4_PV32_BITS;

    if ( boot_cpu_has(X86_FEATURE_FSGSBASE) )
        set_in_cr4(X86_CR4_FSGSBASE);

    if ( opt_invpcid && cpu_has_invpcid )
        use_invpcid = true;

    init_speculation_mitigations();

    init_idle_domain();

    this_cpu(stubs.addr) = alloc_stub_page(smp_processor_id(),
                                           &this_cpu(stubs).mfn);
    BUG_ON(!this_cpu(stubs.addr));

    trap_init();

    rcu_init();

    early_time_init();

    arch_init_memory();

    alternative_instructions();

    local_irq_enable();

    vesa_mtrr_init();

    early_msi_init();

    iommu_setup();    /* setup iommu if available */

    smp_prepare_cpus();

    spin_debug_enable();

    /*
     * Initialise higher-level timer functions. We do this fairly late
     * (after interrupts got enabled) because the time bases and scale
     * factors need to be updated regularly.
     */
    init_xen_time();

    initialize_keytable();

    console_init_postirq();

    system_state = SYS_STATE_smp_boot;

    do_presmp_initcalls();

    alternative_branches();

    /*
     * NB: when running as a PV shim VCPUOP_up/down is wired to the shim
     * physical cpu_add/remove functions, so launch the guest with only
     * the BSP online and let it bring up the other CPUs as required.
     */
    if ( !pv_shim )
    {
        for_each_present_cpu ( i )
        {
            /* Set up cpu_to_node[]. */
            srat_detect_node(i);
            /* Set up node_to_cpumask based on cpu_to_node[]. */
            numa_add_cpu(i);

            if ( (park_offline_cpus || num_online_cpus() < max_cpus) &&
                 !cpu_online(i) )
            {
                ret = cpu_up(i);
                if ( ret != 0 )
                    printk("Failed to bring up CPU %u (error %d)\n", i, ret);
                else if ( num_online_cpus() > max_cpus ||
                          (!opt_smt &&
                           cpu_data[i].compute_unit_id == INVALID_CUID &&
                           cpumask_weight(per_cpu(cpu_sibling_mask, i)) > 1) )
                {
                    ret = cpu_down(i);
                    if ( !ret )
                        ++num_parked;
                    else
                        printk("Could not re-offline CPU%u (%d)\n", i, ret);
                }
            }
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    if ( num_parked )
        printk(XENLOG_INFO "Parked %u CPUs\n", num_parked);
    smp_cpus_done();

    do_initcalls();

    if ( opt_watchdog ) 
        watchdog_setup();

    if ( !tboot_protect_mem_regions() )
        panic("Could not protect TXT memory regions\n");

    init_guest_cpuid();
    init_guest_msr_policy();

    if ( has_boot_domain )
    {
        /* If we're launching the boot domain, create it first, now. */
        struct xen_domctl_createdomain dom_boot_cfg = {
            .flags = (IS_ENABLED(CONFIG_TBOOT) ?
                        XEN_DOMCTL_CDF_s3_integrity : 0) |
                     (hvm_hap_supported() ? XEN_DOMCTL_CDF_hvm : 0) |
                     XEN_DOMCTL_CDF_hap,
            .max_evtchn_port = -1,
            .max_grant_frames = -1,
            .max_maptrack_frames = -1,
            .max_vcpus = 1,
            .arch.emulation_flags = X86_EMU_LAPIC,
        };

        initial_domain = domain_create(DOMID_BOOT_DOMAIN, &dom_boot_cfg, false);
        if ( IS_ERR(initial_domain) )
            panic("Error creating the boot domain\n");

        printk("Set initial_domain to %u\n", initial_domain->domain_id);

        initial_domain->node_affinity = node_online_map;
        initial_domain->auto_node_affinity = 1;
        if ( vcpu_create(initial_domain, 0) == NULL )
            panic("Error setting VCPU0 for the boot domain\n");

        if ( !find_boot_domain_modules(mod, module_map_domain_kernel,
                                       module_map_ramdisk, mbi->mods_count,
                                       &boot_dom_kernel_idx,
                                       &boot_dom_ramdisk_idx) )
            panic("Could not locate boot domain kernel multiboot module(s)\n");
    }

    if ( opt_dom0_pvh )
    {
        dom0_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                           ((hvm_hap_supported() && !opt_dom0_shadow) ?
                            XEN_DOMCTL_CDF_hap : 0));

        dom0_cfg.arch.emulation_flags |=
            XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
    }
    dom0_cfg.max_vcpus = dom0_max_vcpus();

    if ( iommu_enabled )
        dom0_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    if ( has_high_priv_domain || !launch_control_enabled )
    {
        /* Create initial domain 0. */
        dom0 = domain_create((pv_shim ? get_pv_shim_domain_id() : 0),
                             &dom0_cfg, !pv_shim);
        if ( IS_ERR(dom0) || (alloc_dom0_vcpu0(dom0) == NULL) )
            panic("Error creating domain 0\n");

        if ( !has_boot_domain )
        {
            initial_domain = dom0;
            printk("Set initial_domain to %u\n", initial_domain->domain_id);
        }

        if ( launch_control_enabled &&
             !find_dom0_modules(mod, module_map_domain_kernel,
                                module_map_ramdisk, mbi->mods_count,
                                &dom0_kernel_idx, &dom0_ramdisk_idx) )
            panic("Could not locate dom0 multiboot modules\n");

        /* Grab the DOM0 command line. */
        cmdline = (char *)(mod[dom0_kernel_idx].string ?
                           __va(mod[dom0_kernel_idx].string) : NULL);
        if ( (cmdline != NULL) || (kextra != NULL) )
        {
            static char __initdata dom0_cmdline[MAX_GUEST_CMDLINE];

            cmdline = cmdline_cook(cmdline, loader);
            safe_strcpy(dom0_cmdline, cmdline);

            if ( kextra != NULL )
                /* kextra always includes exactly one leading space. */
                safe_strcat(dom0_cmdline, kextra);

            /* Append any extra parameters. */
            if ( skip_ioapic_setup && !strstr(dom0_cmdline, "noapic") )
                safe_strcat(dom0_cmdline, " noapic");
            if ( (strlen(acpi_param) == 0) && acpi_disabled )
            {
                printk("ACPI is disabled, notifying Domain 0 (acpi=off)\n");
                safe_strcpy(acpi_param, "off");
            }
            if ( (strlen(acpi_param) != 0) && !strstr(dom0_cmdline, "acpi=") )
            {
                safe_strcat(dom0_cmdline, " acpi=");
                safe_strcat(dom0_cmdline, acpi_param);
            }

            cmdline = dom0_cmdline;
        }

        if ( !launch_control_enabled )
        {
            dom0_ramdisk_idx = find_first_bit(module_map_ramdisk,
                                              mbi->mods_count);
            if ( bitmap_weight(module_map, mbi->mods_count) > 1 )
                printk(XENLOG_WARNING
                       "Multiple initrd candidates, picking module #%u\n",
                       dom0_ramdisk_idx);
        }
    }

    if ( xen_cpuidle )
        xen_processor_pmbits |= XEN_PROCESSOR_PM_CX;
    /*
     * Temporarily clear SMAP in CR4 to allow user-accesses in construct_dom0().
     * This saves a large number of corner cases interactions with
     * copy_from_user().
     */
    if ( cpu_has_smap )
    {
        cr4_pv32_mask &= ~X86_CR4_SMAP;
        write_cr4(read_cr4() & ~X86_CR4_SMAP);
    }

    printk("%sNX (Execute Disable) protection %sactive\n",
           cpu_has_nx ? XENLOG_INFO : XENLOG_WARNING "Warning: ",
           cpu_has_nx ? "" : "not ");

    if ( has_boot_domain )
    {
        char *boot_dom_cmdline =
            (char *)(mod[boot_dom_kernel_idx].string ?
                     __va(mod[boot_dom_kernel_idx].string) : NULL);

        /* TODO: investigate use of alternative cmdline obtained from the LCM */

        if ( construct_boot_domain(
                initial_domain, mod, &mod[boot_dom_kernel_idx],
                modules_headroom[boot_dom_kernel_idx],
                (boot_dom_ramdisk_idx > 0) ? mod + boot_dom_ramdisk_idx
                                           : NULL,
                boot_dom_cmdline) != 0 )
            panic("Could not set up boot domain guest OS\n");
    }

    if ( has_high_priv_domain || !launch_control_enabled )
    {
        /*
         * We're going to setup domain0 using the module(s) that we stashed
         * safely above our heap.
         */
        if ( construct_dom0(dom0, &mod[dom0_kernel_idx],
                            modules_headroom[dom0_kernel_idx],
                            (dom0_ramdisk_idx > 0) &&
                                (dom0_ramdisk_idx < mbi->mods_count) ?
                                    mod + dom0_ramdisk_idx : NULL,
                            cmdline) != 0 )
            panic("Could not set up DOM0 guest OS\n");
    }

    /* create and construct the remaining initial domains */
    if ( launch_control_enabled )
    {
        unsigned int dom_idx;
        domid_t next_initial_domid = 1;
        unsigned int misses = 0;

        for ( dom_idx = 0; dom_idx < MAX_NUM_INITIAL_DOMAINS; dom_idx++ )
        {
            unsigned int k_idx, r_idx;
            struct lcm_domain_basic_config basic_cfg;
            struct xen_domctl_createdomain dom_cfg;
            char *dom_cmdline;
            struct domain *dom;
            domid_t dom_id;

            if ( !find_domain_modules(mod, module_map_domain_kernel,
                                     module_map_ramdisk, mbi->mods_count,
                                     dom_idx, &k_idx, &r_idx, &basic_cfg) )
            {
                /* allow one for the boot domain */
                if ( ++misses == 1 )
                    continue;

                break;
            }

            dom_id = next_initial_domid++;

            printk("*** Building initial domain %u ***\n", dom_id);

            /* populate dom_cfg from basic_cfg */
            dom_cfg.flags = IS_ENABLED(CONFIG_TBOOT) ?
                                XEN_DOMCTL_CDF_s3_integrity: 0;
            dom_cfg.flags |= basic_cfg.functions & LCM_DOMAIN_FUNCTION_XENSTORE ?
                             XEN_DOMCTL_CDF_xs_domain : 0;
            dom_cfg.ssidref = basic_cfg.xsm_sid;
            for ( i = 0; i < sizeof(dom_cfg.handle); i++ )
                dom_cfg.handle[i] = basic_cfg.domain_handle[i];

            dom_cfg.max_vcpus = basic_cfg.cpus;

            /* TODO: review these settings -> add to basic_config ? */
            dom_cfg.max_evtchn_port = -1;
            dom_cfg.max_grant_frames = -1;
            dom_cfg.max_maptrack_frames = -1;

            if ( basic_cfg.permissions & LCM_DOMAIN_PERMISSION_HARDWARE )
            {
                if ( !(basic_cfg.mode & LCM_DOMAIN_MODE_PARAVIRTUALIZED) )
                    panic("FIXME: hardware domain must be PV\n");

                if ( iommu_enabled )
                    dom_cfg.flags |= XEN_DOMCTL_CDF_iommu;

                dom_cfg.arch.emulation_flags = 0;
                hardware_domid = dom_id;
            }

            /* Apply extra flags for PVH */
            if ( !(basic_cfg.mode & LCM_DOMAIN_MODE_PARAVIRTUALIZED) )
            {
                printk("Initial domain %u is PVH-mode\n", dom_id);
                dom_cfg.flags |= (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap);
                dom_cfg.arch.emulation_flags = X86_EMU_LAPIC;
            }
            else /* FIXME: deny non-PV domains besides hwdom or dom0 for now */
            {
                if ( !(basic_cfg.permissions & LCM_DOMAIN_PERMISSION_HARDWARE) )
                    panic("FIXME: non-hardware domains must be PVH\n");

                printk("Initial domain %u is hardware PV-mode\n", dom_id);
            }

            dom = domain_create(dom_id, &dom_cfg,
                    basic_cfg.permissions & LCM_DOMAIN_PERMISSION_PRIVILEGED);

            if ( IS_ERR(dom) )
                panic("Error creating domain #%d\n", dom_id);
                /* FIXME: better failure handling */

            /* FIXME: vcpu assignment */
            dom->node_affinity = node_online_map;
            dom->auto_node_affinity = 1;
            if ( vcpu_create(dom, 0) == NULL )
                panic("Error setting VCPU0 for the domain %u\n", dom_id);

            dom_cmdline =
                (char *)(mod[k_idx].string ? __va(mod[k_idx].string) : NULL);

            if ( basic_cfg.permissions & LCM_DOMAIN_PERMISSION_HARDWARE )
            {
                if ( dom != hardware_domain )
                    panic("Failed to create hardware domain\n");

                /* FIXME: don't use dom0 construction */
                if ( dom0_construct_pv(dom, &mod[k_idx], modules_headroom[k_idx],
                                    (r_idx > 0) && (r_idx < mbi->mods_count) ?
                                                    mod + r_idx : NULL,
                                    dom_cmdline) != 0 )
                    panic("Could not set up hardware domain guest OS\n");

                /* Without a boot domain or dom0, set hardware domain as initial */
                if ( !has_high_priv_domain )
                {
                    if ( !has_boot_domain )
                    {
                        initial_domain = dom;
                        printk("Set initial_domain to %u\n", initial_domain->domain_id);
                    }
                }
            }
            else
            {
                if ( construct_initial_domain(dom, mod, dom_idx, &mod[k_idx],
                                              modules_headroom[k_idx],
                                              (r_idx > 0) ? mod + r_idx : NULL,
                                              dom_cmdline) != 0 )
                    panic("Could not set up initial domain %u guest OS\n",
                          dom_idx+1);
            }
        }
    }

    printk("Initial domain construction completed\n");

    /* Free temporary buffers. */
    discard_initial_images();

    if ( cpu_has_smap )
    {
        write_cr4(read_cr4() | X86_CR4_SMAP);
        cr4_pv32_mask |= X86_CR4_SMAP;
    }

    heap_init_late();

    init_trace_bufs();

    init_constructors();

    console_endboot(initial_domain->domain_id);

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    dmi_end_boot();

    setup_io_bitmap(hardware_domain);

    if ( bsp_delay_spec_ctrl )
    {
        get_cpu_info()->spec_ctrl_flags &= ~SCF_use_shadow;
        barrier();
        wrmsrl(MSR_SPEC_CTRL, default_xen_spec_ctrl);
    }

    /* Jump to the 1:1 virtual mappings of cpu0_stack. */
    asm volatile ("mov %[stk], %%rsp; jmp %c[fn]" ::
                  [stk] "g" (__va(__pa(get_stack_bottom()))),
                  [fn] "i" (reinit_bsp_stack) : "memory");
    unreachable();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    if ( IS_ENABLED(CONFIG_PV) )
    {
        snprintf(s, sizeof(s), "xen-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
    }
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);
    }
}

int __hwdom_init xen_in_range(unsigned long mfn)
{
    paddr_t start, end;
    int i;

    enum { region_s3, region_ro, region_rw, nr_regions };
    static struct {
        paddr_t s, e;
    } xen_regions[nr_regions] __hwdom_initdata;

    /* initialize first time */
    if ( !xen_regions[0].s )
    {
        /* S3 resume code (and other real mode trampoline code) */
        xen_regions[region_s3].s = bootsym_phys(trampoline_start);
        xen_regions[region_s3].e = bootsym_phys(trampoline_end);

        /*
         * This needs to remain in sync with the uses of the same symbols in
         * - __start_xen() (above)
         * - is_xen_fixed_mfn()
         * - tboot_shutdown()
         */

        /* hypervisor .text + .rodata */
        xen_regions[region_ro].s = __pa(&_stext);
        xen_regions[region_ro].e = __pa(&__2M_rodata_end);
        /* hypervisor .data + .bss */
        xen_regions[region_rw].s = __pa(&__2M_rwdata_start);
        xen_regions[region_rw].e = __pa(&__2M_rwdata_end);
    }

    start = (paddr_t)mfn << PAGE_SHIFT;
    end = start + PAGE_SIZE;
    for ( i = 0; i < nr_regions; i++ )
        if ( (start < xen_regions[i].e) && (end > xen_regions[i].s) )
            return 1;

    return 0;
}

static int __hwdom_init io_bitmap_cb(unsigned long s, unsigned long e,
                                     void *ctx)
{
    struct domain *d = ctx;
    unsigned int i;

    ASSERT(e <= INT_MAX);
    for ( i = s; i <= e; i++ )
        __clear_bit(i, d->arch.hvm.io_bitmap);

    return 0;
}

void __hwdom_init setup_io_bitmap(struct domain *d)
{
    int rc;

    if ( is_hvm_domain(d) )
    {
        bitmap_fill(d->arch.hvm.io_bitmap, 0x10000);
        rc = rangeset_report_ranges(d->arch.ioport_caps, 0, 0x10000,
                                    io_bitmap_cb, d);
        BUG_ON(rc);
        /*
         * NB: we need to trap accesses to 0xcf8 in order to intercept
         * 4 byte accesses, that need to be handled by Xen in order to
         * keep consistency.
         * Access to 1 byte RTC ports also needs to be trapped in order
         * to keep consistency with PV.
         */
        __set_bit(0xcf8, d->arch.hvm.io_bitmap);
        __set_bit(RTC_PORT(0), d->arch.hvm.io_bitmap);
        __set_bit(RTC_PORT(1), d->arch.hvm.io_bitmap);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
