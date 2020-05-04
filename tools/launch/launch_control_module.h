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

    /* xen_domain_handle_t : see handle field in Xen's struct domain */
    uint8_t domain_handle[16];

    /* Domain size in bytes */
    uint64_t mem_size;

    /* XSM/Flask sid */
    uint32_t xsm_sid;

    /* Initial and maximum number of vCPUs for the domain */
    uint32_t cpus;
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

    /*
     * Explicit padding so that sizeof(struct lcm_domain_basic_config) ==
     *                          sizeof(struct lcm_domain_high_priv_config))
     */
    uint8_t pad[44];
};

/*
 * The extended domain configuration data is not parsed by the hypervisor.
 * It is provided to the boot domain to apply the configuration.
 */
struct lcm_domain_extended_config {
    /* Length of the string in config_string */
    uint32_t string_len;
    uint8_t config_string[0];
};

struct lcm_domain {
    /* Flags here indicate which field structs are populated */
    uint16_t flags;
#define LCM_DOMAIN_HAS_BASIC_CONFIG      1 << 0
#define LCM_DOMAIN_HAS_HIGH_PRIV_CONFIG  1 << 1
#define LCM_DOMAIN_HAS_EXTENDED_CONFIG   1 << 2

    /* Index of the domain kernel in the multiboot module array */
    uint8_t kernel_index;
    /*
     * Index of the domain ramdisk in the multiboot module array
     * or 0 if the domain does not have a ramdisk module.
     */
    uint8_t ramdisk_index;

    /* Basic and High-Priv config types are mutually exclusive */
    union {
        struct lcm_domain_basic_config basic_config;
        struct lcm_domain_high_priv_config high_priv_config;
    };
    /* The extended config for a domain is optional */
    union {
        uint8_t raw[0];
        struct lcm_domain_extended_config extended_config;
    };
};

/* Structure containing an array declaring the type of each multiboot module */
struct lcm_module_types {
    uint32_t num_modules;

    /* Array of: type of each multiboot module */
    uint8_t types[0];
#define LCM_MODULE_IGNORE                   0
#define LCM_MODULE_LAUNCH_CONTROL_MODULE    1
#define LCM_MODULE_DOMAIN_KERNEL            2
#define LCM_MODULE_DOMAIN_RAMDISK           3
#define LCM_MODULE_CPU_MICROCODE            4
#define LCM_MODULE_XSM_FLASK_POLICY         5
};

/* Structure containing cryptographic checksum of a multiboot module */
struct lcm_module_checksum {
    uint8_t module_index;
    uint8_t algorithm;
/* TODO: declare algorithm identifier enumeration values here */
    uint16_t hash_len;
    uint8_t bytes[0];
};

struct lcm_entry {
    uint32_t type;
#define LCM_DATA_IGNORE             0 /* Skip this data */
#define LCM_DATA_MODULE_TYPES       1 /* Declare multiboot module types */
#define LCM_DATA_DOMAIN             2 /* Defintion for an initial domain */
#define LCM_DATA_MODULE_CHECKSUM    3 /* Checksum of a multiboot module */

    /* Length of this lcm_entry struct including the subtype union */
    uint32_t len;

    union {
        uint8_t raw[0];
        struct lcm_module_types module_types;
        struct lcm_domain domain;
        struct lcm_module_checksum checksum;
    };
};

/* File format */
struct lcm_header_info {
    uint32_t magic_number;
#define LCM_HEADER_MAGIC_NUMBER 0x4d434c78 /* xLCM */

    /* Total length of all data, including this header and all entries */
    uint32_t total_len;

    struct lcm_entry entries[0];
};
