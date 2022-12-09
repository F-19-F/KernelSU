#include "linux/uidgid.h"
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm-generic/errno-base.h>

#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h> 
#include <linux/fs_struct.h>
#include <linux/namei.h>

#include <linux/delay.h> // mslepp

#include "selinux/selinux.h"
#include "klog.h"
#include "apk_sign.h"
#include "allowlist.h"

#define KERNEL_SU_VERSION 3

#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_GRANT_ROOT 0

#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_ALLOW_SU 3
#define CMD_DENY_SU 4
#define CMD_GET_ALLOW_LIST 5
#define CMD_GET_DENY_LIST 6

static void escape_to_root(void) {
	struct cred* cred;

	cred = (struct cred *)__task_cred(current);

	memset(&cred->uid, 0, sizeof(cred->uid));
	memset(&cred->gid, 0, sizeof(cred->gid));
	memset(&cred->suid, 0, sizeof(cred->suid));
	memset(&cred->euid, 0, sizeof(cred->euid));
	memset(&cred->egid, 0, sizeof(cred->egid));
	memset(&cred->fsuid, 0, sizeof(cred->fsuid));
	memset(&cred->fsgid, 0, sizeof(cred->fsgid));
	memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
	memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));

	// DISABLE SECCOMP
	current_thread_info()->flags = 0;
	current->seccomp.mode = 0;
	current->seccomp.filter = NULL;

	setup_selinux();
}

int startswith(char* s, char* prefix) {
	return strncmp(s, prefix, strlen(prefix));
}

int endswith(const char *s, const char *t)
{
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen) return 1;
    return strcmp(s + slen - tlen, t);
}

static uid_t __manager_uid;

static bool is_manager() {
	return __manager_uid == current_uid().val;
}

static bool become_manager() {
	if (__manager_uid != 0) {
		pr_info("manager already exist: %d\n", __manager_uid);
		return true;
	}
	// list current process's files
	struct files_struct *current_files; 
 	struct fdtable *files_table;
 	int i = 0;
 	struct path files_path;
	char *cwd;
 	char *buf = (char *)kmalloc(GFP_KERNEL, PATH_MAX);
	bool result = false;

 	current_files = current->files;
    files_table = files_fdtable(current_files);
	// 找到apk路径并判断签名是否是管理器的
	// todo: use iterate_fd
 	while(files_table->fd[i] != NULL) { 
 		files_path = files_table->fd[i]->f_path;
		if (!d_is_reg(files_path.dentry)) {
			i++;
			continue;
		}
		cwd = d_path(&files_path, buf, PATH_MAX);
		if (startswith(cwd, "/data/app/") == 0 && endswith(cwd, "/base.apk") == 0) {
			// we have found the apk!
			pr_info("found apk: %s", cwd);
			if (is_manager_apk(cwd) == 0) {
				// check passed
				uid_t uid = current_uid().val;
				pr_info("manager uid: %d\n", uid);

				__manager_uid = uid;

				result = true;
				goto clean;
			} else {
				pr_info("manager signature invalid!");
			}

			break;
		}
 		i++;
 	}

clean:
	kfree(buf);
	return result;
}

static bool is_allow_su() {
	uid_t uid = current_uid().val;
	if (uid == __manager_uid) {
		// we are manager, allow!
		return true;
	}

	if (uid == 0) {
		// we are already root, allow!
		return true;
	}

	return ksu_is_allow_uid(uid);
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {

	struct pt_regs* real_regs = (struct pt_regs*) regs->regs[0];
// 获取调用参数
    int option = (int) real_regs->regs[0];
    unsigned long arg2 = (unsigned long) real_regs->regs[1];
    unsigned long arg3 = (unsigned long) real_regs->regs[2];
    unsigned long arg4 = (unsigned long) real_regs->regs[3];
    unsigned long arg5 = (unsigned long) real_regs->regs[4];

	// if success, we modify the arg5 as result!
	u32* result = (u32*) arg5;
	u32 reply_ok = KERNEL_SU_OPTION;
// 正常调用
	if (KERNEL_SU_OPTION != option) { 
		return 0;
	}

	pr_info("option: 0x%x, cmd: %ld\n", option, arg2);

	if (arg2 == CMD_BECOME_MANAGER) {
		// 记录管理器的uid
		// someone wants to be root manager, just check it!
		bool success = become_manager();
		if (success) {
			copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
		return 0;
	}

	if (arg2 == CMD_GRANT_ROOT) {
		if (is_allow_su()) {
			pr_info("allow root for: %d\n", current_uid());
			// 切换到root,并修改secontext到特权domain,调用进程直接成root特权进程...，以往是创建一个新root进程
			escape_to_root();
		} else {
			pr_info("deny root for: %d\n", current_uid());
			// add it to deny list!
			ksu_allow_uid(current_uid().val, false);
		}
		return 0;
	}

	// all other cmds are for 'root manager'
	if (!is_manager()) {
		pr_info("Only manager can do cmd: %d\n", arg2);
		return 0;
	}
	// 管理接口
	// we are already manager
	if (arg2 == CMD_ALLOW_SU || arg2 == CMD_DENY_SU) {
		bool allow = arg2 == CMD_ALLOW_SU;
		bool success = false;
		uid_t uid = (uid_t) arg3;
		success = ksu_allow_uid(uid, allow);
		if (success) {
			copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
	}  else if (arg2 == CMD_GET_ALLOW_LIST || arg2 == CMD_GET_DENY_LIST) {
		u32 array[128];
		u32 array_length;
		bool success = ksu_get_allow_list(array, &array_length, arg2 == CMD_GET_ALLOW_LIST);
		if (success) {
			copy_to_user(arg4, &array_length, sizeof(array_length));
			copy_to_user(arg3, array, sizeof(u32) * array_length);

			copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
	} else if (arg2 == CMD_GET_VERSION) {
		u32 version = KERNEL_SU_VERSION;
		copy_to_user(arg3, &version, sizeof(version));
	}

    return 0;
}
// hook prctl 系统调用
static struct kprobe kp = {
    .symbol_name = "__arm64_sys_prctl",
    .pre_handler = handler_pre,
};

int kernelsu_init(void){
	int rc = 0;
// 初始化配置
	ksu_allowlist_init();
// 注册hook
	rc = register_kprobe(&kp);

	return rc;
}

void kernelsu_exit(void){
	// should never happen...
	unregister_kprobe(&kp);

	ksu_allowlist_exit();
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android GKI KernelSU");