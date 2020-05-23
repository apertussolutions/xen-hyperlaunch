/*
 * hvm/dom_build.c
 *
 * Domain builder for PVH guest.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 * Copyright (C) 2020 Star Lab Corp
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>

#include <asm/dom_build.h>

int __init construct_pvh_boot_domain(struct domain *d, const module_t *image,
                                     unsigned long image_headroom,
                                     const module_t *initrd,
                                     const char *cmdline)
{
    printk(XENLOG_INFO "*** Building a PVH Domain %d ***\n", d->domain_id);

    panic("Not implemented yet\n");

    return 0;
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
