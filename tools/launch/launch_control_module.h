/*
 * Structures defining the format of the the Launch Control Module
 *
 * Copyright (c) 2020, Star Lab Corporation
 */

/* Module data pertaining to a domain kernel */
struct lcm_kernel {

    /*
     * The basic domain configuration is parsed by the hypervisor for
     * performing initial domain construction.
     * Fixed size and offset fields are mandatory here.
     */
    struct {

        uint8_t privileged:1, hardware:1;

        uint8_t boot:1, console:1;

        uint8_t /* reserved bits! */ :2, mode :2;

        uint8_t domain_handle[16]; /* xen_domain_handle_t *handle */

        /* Domain size in bytes */
        uint64_t mem_size;

        /* XSM/Flask sid */
        uint32_t domain_sid;
    } basic_config;

    /*
     * The extended domain configuration data is not parsed by the hypervisor
     * and is provided to DomB to apply the domain configuration.
     *
     * The length of this string is determined by the len field of
     * the lcm_module struct, minus the fixed-length fields in lcm_module
     * and lcm_kernel.
     */
    char *extended_config[0];
};

/* Module data pertaining to a domain ramdisk */
struct lcm_ramdisk {
    /* TODO */
};

/* Module data for a CPU microcode binary */
struct lcm_microcode {
    /* For values, see: xen/include/asm-x86/x86-vendors.h */
    /* TODO: do we need to consider identifiers for ARM CPU vendors? */
    uint8_t vendor;
    /* TODO: is the following data required? */
    uint8_t family;
    uint8_t model;
    uint8_t step;
};

/* Module data pertaining to a XSM/Flask Policy file */
struct lcm_xsm_flask_policy {
    /* TODO: Does the LCM need to carry this data? */
    uint8_t version;
};

struct lcm_module {
    /* Type of this multiboot module */
    uint16_t type;
#define LCM_MODULE_IGNORE                   0 /* Skip this module */
#define LCM_MODULE_LAUNCH_CONTROL_MODULE    1
#define LCM_MODULE_DOMAIN_KERNEL            2
#define LCM_MODULE_DOMAIN_RAMDISK           3
#define LCM_MODULE_CPU_MICROCODE            4
#define LCM_MODULE_XSM_FLASK_POLICY         5

    /* Length of this lcm_module struct including the subtype union */
    uint32_t len;

    /* Index of this module in the multiboot module array */
    uint8_t mb_index;

    /* Padding to ensure that the union field is 4-byte aligned */
    uint8_t pad[1];

    /* Module-type-specific module data */
    union {
        uint8_t raw[0];
        struct lcm_kernel kernel[0];
        struct lcm_ramdisk ramdisk[0];
        struct lcm_microcode microcode[0];
        struct lcm_xsm_flask_policy xsm_flask_policy[0];
    };
};

/* File format */
struct lcm_header_info {
    uint32_t magic_number;
    struct lcm_module modules[0];
};
