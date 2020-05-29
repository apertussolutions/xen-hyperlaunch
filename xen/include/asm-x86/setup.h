#ifndef __X86_SETUP_H_
#define __X86_SETUP_H_

#include <xen/multiboot.h>
#include <asm/numa.h>

extern const char __2M_text_start[], __2M_text_end[];
extern const char __2M_rodata_start[], __2M_rodata_end[];
extern char __2M_init_start[], __2M_init_end[];
extern char __2M_rwdata_start[], __2M_rwdata_end[];

extern unsigned long xenheap_initial_phys_start;
extern uint64_t boot_tsc_stamp;

void early_cpu_init(void);
void early_time_init(void);

void set_nr_cpu_ids(unsigned int max_cpus);

void numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn);
void arch_init_memory(void);
void subarch_init_memory(void);

void init_IRQ(void);

#ifdef CONFIG_VIDEO
void vesa_init(void);
void vesa_mtrr_init(void);
#else
static inline void vesa_init(void) {};
static inline void vesa_mtrr_init(void) {};
#endif

int construct_dom0(
    struct domain *d,
    const module_t *kernel, unsigned long kernel_headroom,
    module_t *initrd,
    char *cmdline);
int construct_boot_domain(
    struct domain *d, const module_t *lcm,
    const module_t *kernel, unsigned long kernel_headroom,
    const module_t *initrd,
    char *cmdline);
int construct_initial_domain(
    struct domain *d, const module_t *lcm,
    const module_t *kernel, unsigned long kernel_headroom,
    const module_t *initrd,
    char *cmdline);
void setup_io_bitmap(struct domain *d);

unsigned long initial_images_nrpages(nodeid_t node);
void discard_initial_images(void);
void *bootstrap_map(const module_t *mod);

int xen_in_range(unsigned long mfn);

void microcode_grab_module(
    unsigned long *, const multiboot_info_t *);

extern uint8_t kbd_shift_flags;

#ifdef NDEBUG
# define highmem_start 0
#else
extern unsigned long highmem_start;
#endif

extern int8_t opt_smt;

#ifdef CONFIG_BOOT_DOMAIN
extern bool launch_control_enabled;
#else
#define launch_control_enabled false
#endif
#ifdef CONFIG_SHADOW_PAGING
extern bool opt_dom0_shadow;
#else
#define opt_dom0_shadow false
#endif
extern bool opt_dom0_pvh;
extern bool opt_dom0_verbose;
extern bool opt_dom0_cpuid_faulting;

#define max_init_domid (0)

#endif
