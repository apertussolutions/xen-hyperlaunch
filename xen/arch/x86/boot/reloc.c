/*
 * reloc.c
 *
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 *
 * Copyright (c) 2009, Citrix Systems, Inc.
 * Copyright (c) 2013-2016 Oracle and/or its affiliates. All rights reserved.
 *
 * Authors:
 *    Keir Fraser <keir@xen.org>
 *    Daniel Kiper <daniel.kiper@oracle.com>
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with:
 *   - 0x04(%esp) = MAGIC,
 *   - 0x08(%esp) = INFORMATION_ADDRESS,
 *   - 0x0c(%esp) = TOPMOST_LOW_MEMORY_STACK_ADDRESS.
 *   - 0x10(%esp) = BOOT_VIDEO_INFO_ADDRESS.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  reloc                    \n"
    );

#include "defs.h"
#include "boot_info32.h"
#include "../../../include/xen/multiboot.h"
#include "../../../include/xen/multiboot2.h"

#include "../../../include/xen/kconfig.h"
#include <public/arch-x86/hvm/start_info.h>

#ifdef CONFIG_VIDEO
# include "video.h"

/* VESA control information */
struct __packed vesa_ctrl_info {
    uint8_t signature[4];
    uint16_t version;
    uint32_t oem_name;
    uint32_t capabilities;
    uint32_t mode_list;
    uint16_t mem_size;
    /* We don't use any further fields. */
};

/* VESA 2.0 mode information */
struct vesa_mode_info {
    uint16_t attrib;
    uint8_t window[14]; /* We don't use the individual fields. */
    uint16_t bytes_per_line;
    uint16_t width;
    uint16_t height;
    uint8_t cell_width;
    uint8_t cell_height;
    uint8_t nr_planes;
    uint8_t depth;
    uint8_t memory[5]; /* We don't use the individual fields. */
    struct boot_video_colors colors;
    uint8_t direct_color;
    uint32_t base;
    /* We don't use any further fields. */
};
#endif /* CONFIG_VIDEO */

#define get_mb2_data(tag, type, member)   (((multiboot2_tag_##type##_t *)(tag))->member)
#define get_mb2_string(tag, type, member) ((u32)get_mb2_data(tag, type, member))

static u32 alloc;

static u32 alloc_mem(u32 bytes)
{
    return alloc -= ALIGN_UP(bytes, 16);
}

static void zero_mem(u32 s, u32 bytes)
{
    while ( bytes-- )
        *(char *)s++ = 0;
}

static u32 copy_mem(u32 src, u32 bytes)
{
    u32 dst, dst_ret;

    dst = alloc_mem(bytes);
    dst_ret = dst;

    while ( bytes-- )
        *(char *)dst++ = *(char *)src++;

    return dst_ret;
}

static u32 copy_string(u32 src)
{
    u32 p;

    if ( !src )
        return 0;

    for ( p = src; *(char *)p != '\0'; p++ )
        continue;

    return copy_mem(src, p - src + 1);
}

static struct hvm_start_info *pvh_info_reloc(u32 in)
{
    struct hvm_start_info *out;

    out = _p(copy_mem(in, sizeof(*out)));

    if ( out->cmdline_paddr )
        out->cmdline_paddr = copy_string(out->cmdline_paddr);

    if ( out->nr_modules )
    {
        unsigned int i;
        struct hvm_modlist_entry *mods;

        out->modlist_paddr =
            copy_mem(out->modlist_paddr,
                     out->nr_modules * sizeof(struct hvm_modlist_entry));

        mods = _p(out->modlist_paddr);

        for ( i = 0; i < out->nr_modules; i++ )
        {
            if ( mods[i].cmdline_paddr )
                mods[i].cmdline_paddr = copy_string(mods[i].cmdline_paddr);
        }
    }

    return out;
}

static struct boot_info *mbi_reloc(u32 mbi_in)
{
    const multiboot_info_t *mbi = _p(mbi_in);
    struct boot_info *binfo;
    struct arch_boot_info *arch_binfo;
    int i;
    uint32_t ptr;

    ptr = alloc_mem(sizeof(*binfo));
    zero_mem(ptr, sizeof(*binfo));
    binfo = _p(ptr);

    ptr = alloc_mem(sizeof(*arch_binfo));
    zero_mem(ptr, sizeof(*arch_binfo));
    binfo->arch = ptr;
    arch_binfo = _p(ptr);

    if ( mbi->flags & MBI_CMDLINE )
    {
        ptr = copy_string(mbi->cmdline);
        binfo->cmdline = ptr;
        arch_binfo->flags |= BOOTINFO_FLAG_X86_CMDLINE;
    }

    if ( mbi->flags & MBI_MODULES )
    {
        module_t *mods;
        struct boot_module *bi_mods;
        struct arch_bootmodule *arch_bi_mods;

        /*
         * We have to allocate one more module slot here. At some point
         * __start_xen() may put Xen image placement into it.
         */
        ptr = alloc_mem((mbi->mods_count + 1) * sizeof(*bi_mods));
        binfo->nr_mods = mbi->mods_count;
        binfo->mods = ptr;
        bi_mods = _p(ptr);

        ptr = alloc_mem((mbi->mods_count + 1) * sizeof(*arch_bi_mods));
        arch_bi_mods = _p(ptr);

        /* map the +1 allocated for Xen image */
        bi_mods[mbi->mods_count].arch = _addr(&arch_bi_mods[mbi->mods_count]);

        arch_binfo->flags |= BOOTINFO_FLAG_X86_MODULES;

        mods = _p(mbi->mods_addr);

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            bi_mods[i].start = mods[i].mod_start;
            bi_mods[i].size = mods[i].mod_end - mods[i].mod_start;

            if ( mods[i].string )
            {
                int j;
                char *c = _p(mods[i].string);

                for ( j = 0; *c != '\0'; j++, c++ )
                    bi_mods[i].string.bytes[j] = *c;

                bi_mods[i].string.len = j + 1;
            }

            bi_mods[i].arch = _addr(&arch_bi_mods[i]);
        }
    }

    if ( mbi->flags & MBI_MEMMAP )
    {
        arch_binfo->mmap_addr = copy_mem(mbi->mmap_addr, mbi->mmap_length);
        arch_binfo->mmap_length = mbi->mmap_length;
        arch_binfo->flags |= BOOTINFO_FLAG_X86_MEMMAP;
    }

    if ( mbi->flags & MBI_LOADERNAME )
    {
        ptr = copy_string(mbi->boot_loader_name);
        arch_binfo->boot_loader_name = ptr;
        arch_binfo->flags |= BOOTINFO_FLAG_X86_LOADERNAME;
    }

    return binfo;
}

static struct boot_info *mbi2_reloc(uint32_t mbi_in, uint32_t video_out)
{
    const multiboot2_fixed_t *mbi_fix = _p(mbi_in);
    const multiboot2_memory_map_t *mmap_src;
    const multiboot2_tag_t *tag;
    memory_map_t *mmap_dst;
    struct boot_info *binfo;
    struct arch_boot_info *arch_binfo;
    struct boot_module *bi_mods;
    struct arch_bootmodule *arch_bi_mods;
#ifdef CONFIG_VIDEO
    struct boot_video_info *video = NULL;
#endif
    u32 ptr;
    unsigned int i, mod_idx = 0;

    ptr = alloc_mem(sizeof(*binfo));
    zero_mem(ptr, sizeof(*binfo));
    binfo = _p(ptr);

    ptr = alloc_mem(sizeof(*arch_binfo));
    zero_mem(ptr, sizeof(*arch_binfo));
    binfo->arch = ptr;
    arch_binfo = _p(ptr);

    /* Skip Multiboot2 information fixed part. */
    ptr = ALIGN_UP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Get the number of modules. */
    for ( tag = _p(ptr); (u32)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
    {
        if ( tag->type == MULTIBOOT2_TAG_TYPE_MODULE )
            ++binfo->nr_mods;
        else if ( tag->type == MULTIBOOT2_TAG_TYPE_END )
            break;
    }

    if ( binfo->nr_mods )
    {
        /*
         * We have to allocate one more module slot here. At some point
         * __start_xen() may put Xen image placement into it.
         */
        ptr = alloc_mem((binfo->nr_mods + 1) * sizeof(*bi_mods));
        binfo->mods = ptr;
        bi_mods = _p(ptr);

        ptr = alloc_mem((binfo->nr_mods + 1) * sizeof(*arch_bi_mods));
        arch_bi_mods = _p(ptr);

        /* map the +1 allocated for Xen image */
        bi_mods[binfo->nr_mods].arch = _addr(&arch_bi_mods[binfo->nr_mods]);

        arch_binfo->flags |= BOOTINFO_FLAG_X86_MODULES;
    }

    /* Skip Multiboot2 information fixed part. */
    ptr = ALIGN_UP(mbi_in + sizeof(*mbi_fix), MULTIBOOT2_TAG_ALIGN);

    /* Put all needed data into mbi_out. */
    for ( tag = _p(ptr); (u32)tag - mbi_in < mbi_fix->total_size;
          tag = _p(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN)) )
        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME:
            ptr = get_mb2_string(tag, string, string);
            arch_binfo->boot_loader_name = copy_string(ptr);
            arch_binfo->flags |= BOOTINFO_FLAG_X86_LOADERNAME;
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            ptr = get_mb2_string(tag, string, string);
            binfo->cmdline = copy_string(ptr);
            arch_binfo->flags |= BOOTINFO_FLAG_X86_CMDLINE;
            break;

        case MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO:
            arch_binfo->mem_lower = get_mb2_data(tag, basic_meminfo, mem_lower);
            arch_binfo->mem_upper = get_mb2_data(tag, basic_meminfo, mem_upper);
            break;

        case MULTIBOOT2_TAG_TYPE_MMAP:
            if ( get_mb2_data(tag, mmap, entry_size) < sizeof(*mmap_src) )
                break;

            arch_binfo->mmap_length = get_mb2_data(tag, mmap, size);
            arch_binfo->mmap_length -= sizeof(multiboot2_tag_mmap_t);
            arch_binfo->mmap_length /= get_mb2_data(tag, mmap, entry_size);
            arch_binfo->mmap_length *= sizeof(*mmap_dst);

            arch_binfo->mmap_addr = alloc_mem(arch_binfo->mmap_length);
            arch_binfo->flags |= BOOTINFO_FLAG_X86_MEMMAP;

            mmap_src = get_mb2_data(tag, mmap, entries);
            mmap_dst = _p(arch_binfo->mmap_addr);

            for ( i = 0; i < arch_binfo->mmap_length / sizeof(*mmap_dst); i++ )
            {
                /* Init size member properly. */
                mmap_dst[i].size = sizeof(*mmap_dst);
                mmap_dst[i].size -= sizeof(mmap_dst[i].size);
                /* Now copy a given region data. */
                mmap_dst[i].base_addr_low = (u32)mmap_src->addr;
                mmap_dst[i].base_addr_high = (u32)(mmap_src->addr >> 32);
                mmap_dst[i].length_low = (u32)mmap_src->len;
                mmap_dst[i].length_high = (u32)(mmap_src->len >> 32);
                mmap_dst[i].type = mmap_src->type;
                mmap_src = _p(mmap_src) + get_mb2_data(tag, mmap, entry_size);
            }
            break;

        case MULTIBOOT2_TAG_TYPE_MODULE:
            if ( mod_idx >= binfo->nr_mods )
                break;

            bi_mods[mod_idx].start = get_mb2_data(tag, module, mod_start);
            bi_mods[mod_idx].size = get_mb2_data(tag, module, mod_end)
                                            - bi_mods[mod_idx].start;

            ptr = get_mb2_string(tag, module, cmdline);
            if ( ptr )
            {
                int i;
                char *c = _p(ptr);

                for ( i = 0; *c != '\0'; i++, c++ )
                    bi_mods[mod_idx].string.bytes[i] = *c;

                bi_mods[mod_idx].string.len = i + 1;
            }

            bi_mods[mod_idx].arch = _addr(&arch_bi_mods[mod_idx]);

            ++mod_idx;
            break;

#ifdef CONFIG_VIDEO
        case MULTIBOOT2_TAG_TYPE_VBE:
            if ( video_out )
            {
                const struct vesa_ctrl_info *ci;
                const struct vesa_mode_info *mi;

                video = _p(video_out);
                ci = (void *)get_mb2_data(tag, vbe, vbe_control_info);
                mi = (void *)get_mb2_data(tag, vbe, vbe_mode_info);

                if ( ci->version >= 0x0200 && (mi->attrib & 0x9b) == 0x9b )
                {
                    video->capabilities = ci->capabilities;
                    video->lfb_linelength = mi->bytes_per_line;
                    video->lfb_width = mi->width;
                    video->lfb_height = mi->height;
                    video->lfb_depth = mi->depth;
                    video->lfb_base = mi->base;
                    video->lfb_size = ci->mem_size;
                    video->colors = mi->colors;
                    video->vesa_attrib = mi->attrib;
                }

                video->vesapm.seg = get_mb2_data(tag, vbe, vbe_interface_seg);
                video->vesapm.off = get_mb2_data(tag, vbe, vbe_interface_off);
            }
            break;

        case MULTIBOOT2_TAG_TYPE_FRAMEBUFFER:
            if ( (get_mb2_data(tag, framebuffer, framebuffer_type) !=
                  MULTIBOOT2_FRAMEBUFFER_TYPE_RGB) )
            {
                video_out = 0;
                video = NULL;
            }
            break;
#endif /* CONFIG_VIDEO */

        case MULTIBOOT2_TAG_TYPE_END:
            goto end; /* Cannot "break;" here. */

        default:
            break;
        }

 end:

#ifdef CONFIG_VIDEO
    if ( video )
        video->orig_video_isVGA = 0x23;
#endif

    return binfo;
}

void *__stdcall reloc(
    uint32_t magic, uint32_t in, uint32_t trampoline, uint32_t video_info)
{
    alloc = trampoline;

    switch ( magic )
    {
    case MULTIBOOT_BOOTLOADER_MAGIC:
        return mbi_reloc(in);

    case MULTIBOOT2_BOOTLOADER_MAGIC:
        return mbi2_reloc(in, video_info);

    case XEN_HVM_START_MAGIC_VALUE:
        if ( IS_ENABLED(CONFIG_PVH_GUEST) )
            return pvh_info_reloc(in);
        /* Fallthrough */

    default:
        /* Nothing we can do */
        return NULL;
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
