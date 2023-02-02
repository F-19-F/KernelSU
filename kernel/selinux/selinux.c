#include "selinux.h"
#include "objsec.h"
#include "linux/version.h"
#include "../klog.h" // IWYU pragma: keep

static u32 ksu_sid;

static int transive_to_domain(const char *domain)
{
	struct cred *cred;
	struct task_security_struct *tsec;
	u32 sid;
	int error;

	cred = (struct cred *)__task_cred(current);

	tsec = cred->security;
	if (!tsec) {
		pr_err("tsec == NULL!\n");
		return -1;
	}

	error = security_secctx_to_secid(domain, strlen(domain), &sid);
	pr_info("error: %d, sid: %d\n", error, sid);
	if (!error) {
		if (!ksu_sid)
			ksu_sid = sid;

		tsec->sid = sid;
		tsec->create_sid = 0;
		tsec->keycreate_sid = 0;
		tsec->sockcreate_sid = 0;
	}
	return error;
}

void setup_selinux()
{
	if (transive_to_domain(KERNEL_SU_DOMAIN)) {
		pr_err("transive domain failed.");
		return;
	}

	/* we didn't need this now, we have change selinux rules when boot!
if (!is_domain_permissive) {
  if (set_domain_permissive() == 0) {
      is_domain_permissive = true;
  }
}*/
}

void setenforce(bool enforce)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	selinux_state.enforcing = enforce;
#else
	selinux_enabled = enforce;
#endif
#endif
#else
    selinux_enabled = enforce;
#endif
}

bool getenforce()
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 0)
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	if (selinux_state.disabled) {
#else
	if (selinux_disabled) {
#endif
		return false;
	}
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	return selinux_state.enforcing;
#else
	return selinux_enabled;
#endif
#else
	return true;
#endif
#else
    return selinux_enabled;
#endif

}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
	const struct task_security_struct *tsec = current_security();

	return tsec->sid;
}
#endif

bool is_ksu_domain()
{
	return ksu_sid && current_sid() == ksu_sid;
}
