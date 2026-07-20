#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT

#include <linux/fs.h>
#include <linux/jump_label.h>
#include <linux/types.h>
#include <linux/version.h>

#include "runtime/ksud.h"

extern struct static_key_true ksu_su_compat_enabled;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

int ksu_handle_execveat_init(struct filename *filename,
			     struct user_arg_ptr *argv_user,
			     struct user_arg_ptr *envp_user);

int ksu_handle_execveat(int *fd,
			struct filename **filename_ptr,
			void *argv,
			void *envp,
			int *flags);

int ksu_handle_execveat_sucompat(int *fd,
				 struct filename **filename_ptr,
				 void *argv,
				 void *envp,
				 int *flags);

int ksu_handle_faccessat(int *dfd,
			 const char __user **filename_user,
			 int *mode,
			 int *flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd,
		    struct filename **filename,
		    int *flags);
#else
int ksu_handle_stat(int *dfd,
		    const char __user **filename_user,
		    int *flags);
#endif

#endif
