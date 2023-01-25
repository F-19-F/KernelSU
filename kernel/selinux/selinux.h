#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include "linux/types.h"
#include "linux/version.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define HAVE_CURRENT_SID
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define HAVE_SELINUX_STATE
#define SELINUX_POLICYCAP_NNP_NOSUID_TRANSITION
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define SELINUX_POLICY_INSTEAD_SELINUX_SS
#endif

#define KERNEL_SU_DOMAIN "u:r:su:s0"
#ifndef SELINUX_POLICYCAP_NNP_NOSUID_TRANSITION
#define INIT_DOMAIN "u:r:init:s0"

static const char *init_domain = INIT_DOMAIN;
static const char *su_domain = KERNEL_SU_DOMAIN;
#endif

void setup_selinux();

void setenforce(bool);

bool getenforce();

bool is_ksu_domain();

void apply_kernelsu_rules();

#endif
