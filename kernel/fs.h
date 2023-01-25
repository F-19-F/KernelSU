#ifndef __KSU_H_FS
#define __KSU_H_FS

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define KERNEL_READ_WRITE_NEW_PROTOTYPES
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#define FILP_OPEN_WORKS_IN_WORKER
#elif defined(MODULE)
#error cannot build as module due to a Kprobes problem on 4.9
#endif

#ifdef KERNEL_READ_WRITE_NEW_PROTOTYPES
ssize_t kernel_read_compat(struct file *, void *, size_t, loff_t *);
#else
ssize_t kernel_read_compat(struct file *, void *, unsigned long, loff_t *);
#endif

ssize_t kernel_write_compat(struct file *, const void *, size_t, loff_t *);
#endif
