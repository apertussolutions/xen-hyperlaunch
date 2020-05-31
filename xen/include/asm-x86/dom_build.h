#ifndef _DOM_BUILD_H_
#define _DOM_BUILD_H_

#include <xen/sched.h>

#include <asm/setup.h>

int construct_pvh_boot_domain(struct domain *d,
                              const module_t *lcm_image,
                              const module_t *kernel_image,
                              unsigned long image_headroom,
                              const module_t *initrd,
                              char *cmdline);

int construct_pvh_initial_domain(struct domain *d,
                                 const module_t *lcm_image,
                                 unsigned int lcm_dom_idx,
                                 const module_t *kernel_image,
                                 unsigned long image_headroom,
                                 const module_t *initrd,
                                 char *cmdline);

#endif	/* _DOM_BUILD_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
