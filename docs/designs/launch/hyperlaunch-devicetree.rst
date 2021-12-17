-------------------------------------
Xen Hyperlaunch Device Tree Bindings
-------------------------------------

The Xen Hyperlaunch device tree adopts the dom0less device tree structure and
extends it to meet the requirements for the Hyperlaunch capability. The primary
difference is the introduction of the ``hypervisor`` node that is under the
``/chosen`` node. The move to a dedicated node was driven by:

1. Reduces the need to walk over nodes that are not of interest, e.g. only
   nodes of interest should be in ``/chosen/hypervisor``

2. Allows for the domain construction information to easily be sanitized by
   simple removing the ``/chosen/hypervisor`` node.


The Hypervisor node
-------------------

The ``hypervisor`` node is a top level container for the domains that will be built
by hypervisor on start up. The node will be named ``hypervisor``  with a ``compatible``
property to identify which hypervisors the configuration is intended. The hypervisor
node will consist of one or more config nodes and one or more domain nodes.

Properties
""""""""""

compatible
  Identifies which hypervisors the configuration is compatible. Required.

  Format: "hypervisor,<hypervisor name>", e.g "hypervisor,xen"

Child Nodes
"""""""""""

* config
* domain

Config Node
-----------

A ``config`` node is for passing configuration data and identifying any boot
modules that is of interest to the hypervisor.  For example this would be where
Xen would be informed of microcode or XSM policy locations. Each ``config``
node will require a unique device-tree compliant name as there may be one or
more ``config`` nodes present in a single dtb file. To identify which
hypervisor the configuration is intended, the required ``compatible`` property
must be present.

While the config node is not meant to replace the hypervisor commandline, there
may be cases where it is better suited for passing configuration details at
boot time.  This additional information may be carried in properties assigned
to a ``config`` node. If there are any boot modules that are intended for the
hypervisor, then a ``module`` child node should be provided to identify the
boot module.

Properties
""""""""""

compatible
  Identifies the hypervisor the confiugration is intended. Required.

  Format: "<hypervisor name>,config", e.g "xen,config"

Child Nodes
"""""""""""

* module

Domain Node
-----------

A ``domain`` node is for describing the construction of a domain. Since there
may be one or more domain nodes, each one requires a unique, DTB compliant name
and a ``compatible`` property to identify as a domain node.

A ``domain`` node  may provide a ``domid`` property which will be used as the
requested domain id for the domain with a value of “0” signifying to use the
next available domain id, which is the default behavior if omitted. It should
be noted that a domain configuration is not able to request a domid of “0”.
Beyond that a domain node may have any of the following optional properties.

Properties
""""""""""

compatible
  Identifies the node as a domain node and for which hypervisor. Required.

  Format: "<hypervisor name>,domain", e.g "xen,domain"

domid
  Identifies the domid requested to assign to the domain.

  Format: Integer, e.g <0>

permissions
  This sets what Discretionary Access Control permissions
  a domain is assigned. Optional, default is none.

  Format: Bitfield, e.g <3> or <0x00000003>

          PERMISSION_NONE          (0)
          PERMISSION_CONTROL       (1 << 0)
          PERMISSION_HARDWARE      (1 << 1)

functions
  This identifies what system functions a domain will fulfill.
  Optional, the default is none.

  Format: Bitfield, e.g <3221225487> or <0xC0000007>

          FUNCTION_NONE            (0)
          FUNCTION_BOOT            (1 << 0)
          FUNCTION_CRASH           (1 << 1)
          FUNCTION_CONSOLE         (1 << 2)
          FUNCTION_XENSTORE        (1 << 30)
          FUNCTION_LEGACY_DOM0     (1 << 31)

.. note::  The `functions` bits that have been selected to indicate
   ``FUNCTION_XENSTORE`` and ``FUNCTION_LEGACY_DOM0`` are the last two bits
   (30, 31) such that should these features ever be fully replaced or retired,
   the flags may be dropped without leaving a gap in the flag set.

mode
  The mode the domain will be executed under. Required.

  Format: Bitfield, e.g <5> or <0x00000005>

          MODE_PARAVIRTUALIZED     (1 << 0) PV | PVH/HVM
          MODE_ENABLE_DEVICE_MODEL (1 << 1) HVM | PVH
          MODE_LONG                (1 << 2) 64 BIT | 32 BIT

domain-uuid
  A globally unique identifier for the domain. Optional,
  the default is NULL.

  Format: Byte Array, e.g [B3 FB 98 FB 8F 9F 67 A3]

cpus
  The number of vCPUs to be assigned to the domain. Optional,
  the default is “1”.

  Format: Integer, e.g <0>

memory
  The amount of memory to assign to the domain, in KBs. This field uses a DTB
  Reg which contains a start and size. For memory allocation start may or may
  not have significance but size will always be used for the amount of memory
  Required.

  Format: DTB Reg <min:start size>, [<max: start size>], e.g. <0x0 0x20000>

security-id
  The security identity to be assigned to the domain when XSM
  is the access control mechanism being used. Optional,
  the default is “system_u:system_r:domU_t”.

  Format: string, e.g. "system_u:system_r:domU_t"

Child Nodes
"""""""""""

* module

Module node
-----------

This node describes a boot module loaded by the boot loader. A ``module`` node
will often appear repeatedly and will require a unique and DTB compliant name
for each instance. The compatible property is required to identify that the
node is a ``module`` node, the type of boot module, and what it represents.

Depending on the type of boot module, the ``module`` node will require either a
``mb-index`` or ``module-addr`` property must be present. They provide the boot
module specific way of locating the boot module in memory.

Properties
""""""""""

compatible
  This identifies what the module is and thus what the hypervisor
  should use the module for during domain construction. Required.

  Format: "module,<module type>"[, "<boot module type>,module"]
          module type: kernel, ramdisk, device-tree, microcode, xsm-policy,
                       config

          boot module type: multiboot

mb-index
  This identifies the index for this module in the multiboot module chain.
  Required for multiboot environments.

  Format: Integer, e.g. <0>

module-addr
  This identifies where in memory this module is located. Required for
  non-multiboot environments.

  Format: DTB Reg <start size>, e.g. <0x0 0x20000>

bootargs
  This is used to provide the boot params to kernel modules.

  Format: String, e.g. "ro quiet"

.. note::  The bootargs property is intended for situations where the same kernel multiboot module is used for more than one domain.

Example Configuration
---------------------

Below are examples device tree definitions for the hypervisor node. The first
is an example of booting a dom0 only configuration. Afterh that are a
multiboot-based configuration for x86 and a module-based configuration for Arm.

Multiboot x86 Configuration Dom0-only:
""""""""""""""""""""""""""""""""""""""
The following dts file can be provided to the Device Tree compiler, ``dtc``, to
produce a dtb file. 
::

  /dts-v1/;

  / {
      chosen {
          hypervisor {
              compatible = "hypervisor,xen";

              dom0 {
                  compatible = "xen,domain";

                  domid = <0>;

                  permissions = <3>;
                  functions = <0xC000000F>;
                  mode = <5>;

                  domain-uuid = [B3 FB 98 FB 8F 9F 67 A3 8A 6E 62 5A 09 13 F0 8C];                                               

                  cpus = <1>;
                  memory = <0x0 0x20000000>;

                  kernel {
                      compatible = "module,kernel", "multiboot,module";
                      mb-index = <1>;
                  };
              };

          };
      };
  };

The resulting dtb file, in this case dom0-only.dtb, can then be used with a
GRUB menuentry as such,
::

  menuentry 'Devuan GNU/Linux, with Xen hyperlaunch' {
        insmod part_gpt
        insmod ext2
        set root='hd0,gpt2'

        echo    'Loading Xen hyperlaunch ...'

        multiboot2      /xen.gz placeholder sync_console
        echo    'Loading Dom0 hyperlaunch dtb ...'
        module2 --nounzip   /dom0-only.dtb
        echo    'Loading Linux 5.4.36+ ...'
        module2 /vmlinuz-5.4.36+ placeholder root=/dev/mapper/test01--vg-root ro  quiet
        echo    'Loading initial ramdisk ...'
        module2 --nounzip   /initrd.img-5.4.36+
  }


Multiboot x86 Configuration:
""""""""""""""""""""""""""""

::

    hypervisor {
        #address-cells = <1>;
        #size-cells = <0>;
        compatible = “hypervisor,xen”

        // Configuration container
        xen-config {
            compatible = "xen,config";

            microcode {
                compatible = "module,microcode", "multiboot,module";
                mb-index = <1>;
            };

            policy {
                compatible = "module,xsm-policy", "multiboot,module";
                mb-index = <2>;
            };
        };

        // Boot Domain definition
        domB {
            compatible = "xen,domain";

            domid = <0x7FF5>;

            functions = <0x00000001>;

            memory = <0x0 0x20000>;
            cpus = <1>;

            kernel {
                compatible = "module,kernel", "multiboot,module";
                mb-index = <3>;
            };
            initrd {
                compatible = "module,ramdisk", "multiboot,module";
                mb-index = <4>;
            };
            dom-config {
                compatible = "module,config", "multiboot,module";
                mb-index = <5>;
            };

        // Classic Dom0 definition
        dom0 {
            compatible = "xen,domain";

            domid = <0>;

            permissions = <3>;
            functions = <0xC0000006>;
            mode = <5>; /* 64 BIT, PV */

            domain-uuid = [B3 FB 98 FB 8F 9F 67 A3];

            cpus = <1>;
            memory = <0x0 0x20000>;
            security-id = “system_u:system_r:dom0_t;

            kernel {
                compatible = "module,kernel", "multiboot,module";
                mb-index = <6>;
                bootargs = "console=hvc0";
            };
            initrd {
                compatible = "module,ramdisk", "multiboot,module";
                mb-index = <7>;
            };
    };

The multiboot modules supplied when using the above config would be, in order:

* (the above config, compiled)
* CPU microcode
* XSM policy
* kernel for boot domain
* ramdisk for boot domain
* boot domain configuration file
* kernel for the classic dom0 domain
* ramdisk for the classic dom0 domain

Module Arm Configuration:
"""""""""""""""""""""""""

::

    hypervisor {
        compatible = “hypervisor,xen”

        // Configuration container
        xen-config {
            compatible = "xen,config";

            microcode {
                compatible = "module,microcode”;
                module-addr = <0x0000ff00 0x80>;
            };

            policy {
                compatible = "module,xsm-policy";
                module-addr = <0x0000ff00 0x80>;

            };
        };

        // Boot Domain definition
        domB {
            compatible = "xen,domain";

            domid = <0x7FF5>;

            functions = <0x00000001>;

            memory = <0x0 0x20000>;
            cpus = <1>;

            kernel {
                compatible = "module,kernel";
                module-addr = <0x0000ff00 0x80>;
            };
            initrd {
                compatible = "module,ramdisk";
                module-addr = <0x0000ff00 0x80>;
            };
            dom-config {
                compatible = "module,config";
                module-addr = <0x0000ff00 0x80>;
            };

        // Classic Dom0 definition
        dom0 {
            compatible = "xen,domain";

            domid = <0>;

            permissions = <3>;
            functions = <0xC0000006>;
            mode = <5>; /* 64 BIT, PV */

            domain-uuid = [B3 FB 98 FB 8F 9F 67 A3];

            cpus = <1>;
            memory = <0x0 0x20000>;
            security-id = “system_u:system_r:dom0_t”;

            kernel {
                compatible = "module,kernel";
                module-addr = <0x0000ff00 0x80>;
                bootargs = "console=hvc0";
            };
            intird {
                compatible = "module,ramdisk";
                module-addr = <0x0000ff00 0x80>;
            };
    };

The modules that would be supplied when using the above config would be:

* (the above config, compiled into hardware tree)
* CPU microcode
* XSM policy
* kernel for boot domain
* ramdisk for boot domain
* boot domain configuration file
* kernel for the classic dom0 domain
* ramdisk for the classic dom0 domain

The hypervisor device tree would be compiled into the hardware device tree and
provided to Xen using the standard method currently in use. The remaining
modules would need to be loaded in the respective addresses specified in the
`module-addr` property.

