/*
 *  Copyright (C) 2005 IBM Corporation
 *
 *  Authors:
 *  Reiner Sailer, <sailer@watson.ibm.com>
 *  Stefan Berger, <stefanb@watson.ibm.com>
 *
 *  Contributors:
 *  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *  George Coker, <gscoker@alpha.ncsc.mil>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 *
 *
 *  This file contains the XSM policy init functions for Xen.
 *
 */

#include <xen/bitops.h>
#include <xen/bootinfo.h>
#include <xsm/xsm.h>

#ifdef CONFIG_HAS_DEVICE_TREE
# include <xen/device_tree.h>
#endif

# include <asm/setup.h>

#ifndef CONFIG_HAS_DEVICE_TREE
int __init xsm_bootmodule_policy_init(
    const struct boot_info *bi, const unsigned char **policy_buffer,
    size_t *policy_size)
{
    unsigned long idx = 0;
    int rc = -ENOENT;
    u32 *_policy_start;
    unsigned long _policy_len;

#ifdef CONFIG_XSM_FLASK_POLICY
    /* Initially set to builtin policy, overriden if boot module is found. */
    *policy_buffer = xsm_flask_init_policy;
    *policy_size = xsm_flask_init_policy_size;
    rc = 0;
#endif

    idx = bootmodule_next_idx_by_kind(bi, BOOTMOD_UNKNOWN, idx);
    while ( idx < bi->nr_mods )
    {
        _policy_start = bootstrap_map(&bi->mods[idx]);
        _policy_len   = bi->mods[idx].size;

        if ( (xsm_magic_t)(*_policy_start) == XSM_MAGIC )
        {
            *policy_buffer = (unsigned char *)_policy_start;
            *policy_size = _policy_len;

            printk("Policy len %#lx, start at %p.\n",
                   _policy_len,_policy_start);

            bi->mods[idx].kind = BOOTMOD_XSM;
            rc = 0;
            break;
        }

        bootstrap_map(NULL);
        idx = bootmodule_next_idx_by_kind(bi, BOOTMOD_UNKNOWN, ++idx);
    }

    return rc;
}

#else

int __init xsm_dt_policy_init(void **policy_buffer, size_t *policy_size)
{
    struct bootmodule *mod = boot_module_find_by_kind(BOOTMOD_XSM);
    paddr_t paddr, len;

    if ( !mod || !mod->size )
        return 0;

    paddr = mod->start;
    len = mod->size;

    if ( !has_xsm_magic(paddr) )
    {
        printk(XENLOG_ERR "xsm: Invalid magic for XSM blob\n");
        return -EINVAL;
    }

    printk("xsm: Policy len = 0x%"PRIpaddr" start at 0x%"PRIpaddr"\n",
           len, paddr);

    *policy_buffer = xmalloc_bytes(len);
    if ( !*policy_buffer )
        return -ENOMEM;

    copy_from_paddr(*policy_buffer, paddr, len);
    *policy_size = len;

    return 0;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
