#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>
#include <linux/susfs_def.h>
#include "selinux/selinux.h"

#include "policy/allowlist.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "supercall/supercall.h"
#include "feature/kernel_umount.h"

extern u32 susfs_zygote_sid;
extern void disable_seccomp(void);
extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
	if (work_pending(&susfs_extra_works))
		return;

	schedule_work(&susfs_extra_works);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	/*
	 * The direct kernel hook calls this before credentials are committed.
	 * Only handle processes spawned from the zygote SELinux domain.
	 */
	if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
		return 0;

	/* Isolated services must always receive an unmounted namespace. */
	if (is_isolated_process(ruid))
		goto do_umount;

	/*
	 * The manager is deliberately excluded from the allowlist, so handle it
	 * before the normal per-UID unmount decision.
	 */
	if (likely(ksu_is_manager_appid_valid()) &&
	    unlikely(is_uid_manager(ruid))) {
		disable_seccomp();
		pr_info("install fd for manager: %d\n", ruid);
		ksu_install_fd();
		return 0;
	}

	/* WebView zygote does not execute ordinary application code. */
	if (unlikely(ruid == WEBVIEW_ZYGOTE_UID))
		return 0;

	/* Normal applications marked for namespace cleanup. */
	if (likely(is_appuid(ruid) && ksu_uid_should_umount(ruid)))
		goto do_umount;

	/* Root-allowed applications may need unrestricted seccomp handling. */
	if (ksu_is_allow_uid_for_current(ruid))
		disable_seccomp();

	return 0;

do_umount:
	ksu_handle_umount(current_uid().val, ruid);
	ksu_handle_extra_susfs_work();
	susfs_set_current_proc_umounted();

	return 0;
}

void __init ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
}
