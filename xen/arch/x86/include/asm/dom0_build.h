#ifndef _DOM0_BUILD_H_
#define _DOM0_BUILD_H_

#include <xen/bootinfo.h>
#include <xen/libelf.h>
#include <xen/sched.h>

#include <asm/setup.h>

extern unsigned int dom0_memflags;

unsigned long dom_avail_nr_pages(
    struct boot_domain *bd, nodemask_t nodes);

unsigned long dom0_compute_nr_pages(
    struct boot_domain *bd, struct elf_dom_parms *parms,
    unsigned long initrd_len);

unsigned long dom_compute_nr_pages(
    struct boot_domain *bd, struct elf_dom_parms *parms,
    unsigned long initrd_len);

int dom0_setup_permissions(struct domain *d);

int dom0_construct_pv(struct boot_domain *bd);

int dom0_construct_pvh(struct boot_domain *bd);

unsigned long dom0_paging_pages(const struct domain *d,
                                unsigned long nr_pages);

void dom_update_physmap(bool compat, unsigned long pfn,
                         unsigned long mfn, unsigned long vphysmap_s);

#endif	/* _DOM0_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
