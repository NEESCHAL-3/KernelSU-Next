#include <asm/current.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <linux/susfs_def.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "feature/adb_root.h"
#include "feature/sucompat.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "runtime/ksud.h"
#include "selinux/selinux.h"
#include "sulog/event.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static const char sh_path[] = SH_PATH;
static const char su_path[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;

DEFINE_STATIC_KEY_TRUE(ksu_su_compat_enabled);

static int su_compat_feature_get(u64 *value)
{
	*value = static_key_enabled(&ksu_su_compat_enabled) ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	bool enabled = static_key_enabled(&ksu_su_compat_enabled);

	if (enable && !enabled)
		static_branch_enable(&ksu_su_compat_enabled);
	else if (!enable && enabled)
		static_branch_disable(&ksu_su_compat_enabled);

	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *data, size_t len)
{
	unsigned long user_sp;
	char __user *ptr;

	user_sp = user_stack_pointer(task_pt_regs(current));
	ptr = (char __user *)(user_sp - len);

	return copy_to_user(ptr, data, len) ? NULL : ptr;
}

static char __user *sh_user_path(void)
{
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

/*
 * Return zero when no additional sucompat handling should be performed.
 * A nonzero result permits normal sucompat checks to continue.
 */
int ksu_handle_execveat_init(struct filename *filename,
			     struct user_arg_ptr *argv_user,
			     struct user_arg_ptr *envp_user)
{
	int ret;

	if (!filename || IS_ERR(filename) || !filename->name)
		return -EINVAL;

	if (current->pid == 1)
		return -EINVAL;

	if (!is_init(get_current_cred()))
		return -EINVAL;

	if (unlikely(!strcmp(filename->name, KSUD_PATH))) {
		struct ksu_sulog_pending_event *pending;

		pr_info("escape to root for init executing ksud: %d\n",
			current->pid);

		pending = ksu_sulog_capture_sucompat(
			filename->name, argv_user, GFP_KERNEL);

		ret = escape_to_root_for_init();
		if (ret)
			pr_err("escape_to_root_for_init failed: %d\n", ret);

		ksu_sulog_emit_pending(pending, ret, GFP_KERNEL);
		return 0;
	}

	if (likely(!strstr(filename->name, "/app_process") &&
		   !strstr(filename->name, "/adbd"))) {
		susfs_set_current_proc_umounted();
		return 0;
	}

#ifdef CONFIG_COMPAT
	if (unlikely(envp_user->is_compat))
		ret = ksu_adb_root_handle_execve(
			filename->name,
			(void __user ***)&envp_user->ptr.compat);
	else
		ret = ksu_adb_root_handle_execve(
			filename->name,
			(void __user ***)&envp_user->ptr.native);
#else
	ret = ksu_adb_root_handle_execve(
		filename->name,
		(void __user ***)&envp_user->ptr.native);
#endif

	if (ret)
		pr_err("adb root failed: %d\n", ret);

	return ret;
}

int ksu_handle_execveat_sucompat(int *fd,
				 struct filename **filename_ptr,
				 void *argv_user,
				 void *envp_user,
				 int *flags)
{
	struct filename *filename;
	struct ksu_sulog_pending_event *pending;
	int ret;

	if (!filename_ptr)
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename) || !filename || !filename->name)
		return 0;

	if (!ksu_handle_execveat_init(
		    filename,
		    (struct user_arg_ptr *)argv_user,
		    (struct user_arg_ptr *)envp_user))
		return 0;

	if (!__ksu_is_allow_uid_for_current(current_uid().val))
		return 0;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	if (current_chrooted()) {
		pr_err("sucompat: blocked su execution inside chroot\n");
		return 0;
	}

	pr_info("sucompat: su execution detected\n");

	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	pending = ksu_sulog_capture_sucompat(
		filename->name,
		(struct user_arg_ptr *)argv_user,
		GFP_KERNEL);

	ret = escape_with_root_profile();
	if (ret)
		pr_err("escape_with_root_profile failed: %d\n", ret);

	ksu_sulog_emit_pending(pending, ret, GFP_KERNEL);
	return 0;
}

extern struct static_key_true is_first_zygote;

int ksu_handle_execveat(int *fd,
			struct filename **filename_ptr,
			void *argv,
			void *envp,
			int *flags)
{
	if (static_branch_unlikely(&is_first_zygote))
		(void)ksu_handle_execveat_ksud(
			fd, filename_ptr, argv, envp, flags);

	return ksu_handle_execveat_sucompat(
		fd, filename_ptr, argv, envp, flags);
}

int ksu_handle_faccessat(int *dfd,
			 const char __user **filename_user,
			 int *mode,
			 int *flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (!filename_user || !*filename_user)
		return 0;

	if (strncpy_from_user(path, *filename_user, sizeof(path)) < 0)
		return 0;

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		if (current_chrooted()) {
			pr_err("sucompat: blocked faccessat inside chroot\n");
			return 0;
		}

		pr_info("sucompat: faccessat su -> sh\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd,
		    struct filename **filename,
		    int *flags)
{
	if (!filename || IS_ERR(*filename) ||
	    !*filename || !(*filename)->name)
		return 0;

	if (likely(memcmp((*filename)->name,
			  su_path, sizeof(su_path))))
		return 0;

	if (current_chrooted()) {
		pr_err("sucompat: blocked stat inside chroot\n");
		return 0;
	}

	pr_info("sucompat: stat su -> sh\n");
	memcpy((void *)(*filename)->name, sh_path, sizeof(sh_path));

	return 0;
}
#else
int ksu_handle_stat(int *dfd,
		    const char __user **filename_user,
		    int *flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (!filename_user || !*filename_user)
		return 0;

	if (strncpy_from_user(path, *filename_user, sizeof(path)) < 0)
		return 0;

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		if (current_chrooted()) {
			pr_err("sucompat: blocked stat inside chroot\n");
			return 0;
		}

		pr_info("sucompat: stat su -> sh\n");
		*filename_user = sh_user_path();
	}

	return 0;
}
#endif

void __init ksu_sucompat_init(void)
{
	if (ksu_register_feature_handler(&su_compat_handler))
		pr_err("Failed to register su_compat feature handler\n");
}

void __exit ksu_sucompat_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
