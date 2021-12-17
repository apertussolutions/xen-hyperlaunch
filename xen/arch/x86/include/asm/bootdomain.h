#ifndef __ARCH_X86_BOOTDOMAIN_H__
#define __ARCH_X86_BOOTDOMAIN_H__

struct memsize {
    long nr_pages;
    unsigned int percent;
    bool minus;
};

static inline bool memsize_gt_zero(const struct memsize *sz)
{
    return !sz->minus && sz->nr_pages;
}

static inline unsigned long get_memsize(
    const struct memsize *sz, unsigned long avail)
{
    unsigned long pages;

    pages = sz->nr_pages + sz->percent * avail / 100;
    return sz->minus ? avail - pages : pages;
}

struct arch_domain_mem {
    struct memsize mem_size;
    struct memsize mem_min;
    struct memsize mem_max;
};

#endif
