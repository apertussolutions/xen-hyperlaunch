/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XEN_SETUP_H
#define XEN_SETUP_H

#include <asm/setup.h>

#ifdef CONFIG_HYPERLAUNCH
extern bool hyperlaunch_enabled;
#else
#define hyperlaunch_enabled false
#endif

#endif /* XEN_SETUP_H */
