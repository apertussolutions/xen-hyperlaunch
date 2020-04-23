/*
 * Structures defining the format of the the Launch Control Module
 *
 * Copyright (c) 2020, Star Lab Corporation
 */

/*
 * Basic domain configuration data pertaining to a domain,
 * parsed by the hypervisor for performing initial domain construction.
 */
struct lcm_domain_basic_config {
    /*
     * Fixed size and offset fields are mandatory in this structure
     * and alignment of fields to 4-bytes is required.
     */
    uint32_t permissions;
#define LCM_DOMAIN_PERMISSION_PRIVILEGED    (1 << 0)
#define LCM_DOMAIN_PERMISSION_HARDWARE      (1 << 1)

    uint32_t functions;
#define LCM_DOMAIN_FUNCTION_BOOT            (1 << 0)
#define LCM_DOMAIN_FUNCTION_CONSOLE         (1 << 1)

    uint32_t mode;
#define LCM_DOMAIN_MODE_PARAVIRTUALIZED     (1 << 0) /* PV | PVH/HVM */
#define LCM_DOMAIN_MODE_ENABLE_DEVICE_MODEL (1 << 1) /* PVH | HVM */

    /* xen_domain_handle_t : see handle field in struct domain */
    uint8_t domain_handle[16];

    /* Domain size in bytes */
    uint64_t mem_size;

    /* XSM/Flask sid */
    uint32_t domain_sid;
};

/*
 * Basic domain configuration data pertaining to a highly-privileged domain,
 * parsed by the hypervisor for performing initial domain construction.
 * This supports construction of a classic dom0 domain.
 */
struct lcm_domain_high_priv_config {
    /*
     * Fixed size and offset fields are mandatory in this structure
     * and alignment of fields to 4-bytes is required.
     */
    uint32_t mode;
#define LCM_DOMAIN_HIGH_PRIV_MODE_PARAVIRTUALIZED  (1 << 0) /* PV | PVH/HVM */
};

/*
 * The extended domain configuration data is not parsed by the hypervisor.
 * It is provided to the boot domain to apply the configuration.
 */
struct lcm_domain_extended_config {
    /*
     * The length of this string is determined by the len field of the
     * lcm_module struct, minus all fixed-length fields in lcm_module.
     */
    char *config_string[0];
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
    /* Type of data in this struct describing a multiboot module */
    uint16_t type;
#define LCM_MODULE_IGNORE                   0 /* Skip this data */
#define LCM_MODULE_LAUNCH_CONTROL_MODULE    1
#define LCM_MODULE_DOMAIN_BASIC_CONFIG      2
#define LCM_MODULE_DOMAIN_HIGH_PRIV_CONFIG  3
#define LCM_MODULE_DOMAIN_EXTENDED_CONFIG   4
#define LCM_MODULE_DOMAIN_RAMDISK           5
#define LCM_MODULE_CPU_MICROCODE            6
#define LCM_MODULE_XSM_FLASK_POLICY         7

    /* Length of this lcm_module struct including the subtype union */
    uint32_t len;

    /* Index of this module in the multiboot module array */
    uint8_t mb_index;

    /* Padding to ensure that the union field is 4-byte aligned */
    uint8_t pad[1];

    /* Module-type-specific module data */
    union {
        uint8_t raw[0];
        struct lcm_domain_basic_config basic_config;
        struct lcm_domain_high_priv_config high_priv_config;
        struct lcm_domain_extended_config extended_config;
        struct lcm_ramdisk ramdisk;
        struct lcm_microcode microcode;
        struct lcm_xsm_flask_policy xsm_flask_policy;
    };
};

/* File format */
struct lcm_header_info {
    uint32_t magic_number;
#define LCM_HEADER_MAGIC_NUMBER 0x4d434c78 /* xLCM */
    struct lcm_module modules[0];
};
