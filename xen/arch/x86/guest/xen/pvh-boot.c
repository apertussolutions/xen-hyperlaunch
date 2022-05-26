/******************************************************************************
 * arch/x86/guest/pvh-boot.c
 *
 * PVH boot time support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/bootinfo.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#include <asm/e820.h>
#include <asm/guest.h>

#include <public/arch-x86/hvm/start_info.h>

/* Initialised in head.S, before .bss is zeroed. */
bool __initdata pvh_boot;
uint32_t __initdata pvh_start_info_pa;

static struct boot_info __initdata pvh_bi;
static struct arch_boot_info __initdata arch_pvh_bi;
static struct boot_module __initdata pvh_mods[CONFIG_NR_BOOTMODS + 1];
static struct arch_bootmodule __initdata arch_pvh_mods[CONFIG_NR_BOOTMODS + 1];
static char __initdata *pvh_loader = "PVH Directboot";

static struct boot_info __init *init_pvh_info(void)
{
    int i;

    pvh_bi.arch = &arch_pvh_bi;
    pvh_bi.mods = pvh_mods;

    for ( i=0; i <= CONFIG_NR_BOOTMODS; i++ )
        pvh_bi.mods[i].arch = &arch_pvh_mods[i];

    pvh_bi.arch->boot_loader_name = pvh_loader;

    return &pvh_bi;
}

static void __init convert_pvh_info(struct boot_info *bi)
{
    const struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    const struct hvm_modlist_entry *entry;
    unsigned int i;

    if ( pvh_info->magic != XEN_HVM_START_MAGIC_VALUE )
        panic("Magic value is wrong: %x\n", pvh_info->magic);

    /*
     * Temporary module array needs to be at least one element bigger than
     * required. The extra element is used to aid relocation. See
     * arch/x86/setup.c:__start_xen().
     */
    if ( ARRAY_SIZE(pvh_mods) <= pvh_info->nr_modules )
        panic("The module array is too small, size %zu, requested %u\n",
              ARRAY_SIZE(pvh_mods), pvh_info->nr_modules);

    /*
     * Turn hvm_start_info into mbi. Luckily all modules are placed under 4GB
     * boundary on x86.
     */
    bi->arch->flags = BOOTINFO_FLAG_X86_CMDLINE | BOOTINFO_FLAG_X86_MODULES
                      | BOOTINFO_FLAG_X86_LOADERNAME;

    BUG_ON(pvh_info->cmdline_paddr >> 32);
    bi->cmdline = _p(__va(pvh_info->cmdline_paddr));

    BUG_ON(pvh_info->nr_modules >= ARRAY_SIZE(pvh_mods));
    bi->nr_mods = pvh_info->nr_modules;

    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        BUG_ON(entry[i].paddr >> 32);
        BUG_ON(entry[i].cmdline_paddr >> 32);

        bi->mods[i].start = entry[i].paddr;
        bi->mods[i].size  = entry[i].size;
        if ( entry[i].cmdline_paddr)
        {
            char *c = _p(__va(entry[i].cmdline_paddr));

            safe_strcpy(bi->mods[i].string.bytes, c);
            bi->mods[i].string.kind = BOOTSTR_CMDLINE;
        }
    }

    rsdp_hint = pvh_info->rsdp_paddr;
}

static void __init get_memory_map(void)
{
    struct xen_memory_map memmap = {
        .nr_entries = E820MAX,
    };

    set_xen_guest_handle(memmap.buffer, e820_raw.map);
    BUG_ON(xen_hypercall_memory_op(XENMEM_memory_map, &memmap));
    e820_raw.nr_map = memmap.nr_entries;

    /* :( Various toolstacks don't sort the memory map. */
    sanitize_e820_map(e820_raw.map, &e820_raw.nr_map);
}

void __init pvh_init(struct boot_info **bi)
{
    *bi = init_pvh_info();
    convert_pvh_info(*bi);

    hypervisor_probe();
    ASSERT(xen_guest);

    (*bi)->arch->xen_guest = xen_guest;

    get_memory_map();
}

void __init pvh_print_info(void)
{
    const struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    const struct hvm_modlist_entry *entry;
    unsigned int i;

    ASSERT(pvh_info->magic == XEN_HVM_START_MAGIC_VALUE);

    printk("PVH start info: (pa %08x)\n", pvh_start_info_pa);
    printk("  version:    %u\n", pvh_info->version);
    printk("  flags:      %#"PRIx32"\n", pvh_info->flags);
    printk("  nr_modules: %u\n", pvh_info->nr_modules);
    printk("  modlist_pa: %016"PRIx64"\n", pvh_info->modlist_paddr);
    printk("  cmdline_pa: %016"PRIx64"\n", pvh_info->cmdline_paddr);
    if ( pvh_info->cmdline_paddr )
        printk("  cmdline:    '%s'\n", (char *)__va(pvh_info->cmdline_paddr));
    printk("  rsdp_pa:    %016"PRIx64"\n", pvh_info->rsdp_paddr);

    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        printk("    mod[%u].pa:         %016"PRIx64"\n", i, entry[i].paddr);
        printk("    mod[%u].size:       %016"PRIu64"\n", i, entry[i].size);
        printk("    mod[%u].cmdline_pa: %016"PRIx64"\n",
               i, entry[i].cmdline_paddr);
        if ( entry[i].cmdline_paddr )
            printk("    mod[%1u].cmdline:    '%s'\n", i,
                   (char *)__va(entry[i].cmdline_paddr));
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
