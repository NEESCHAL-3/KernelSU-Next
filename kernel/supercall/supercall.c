#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"

#include "sulog/event.h"

uint32_t ksuver_override = 0;

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

int ksu_install_fd(void)
{
    struct file *filp;
    int fd;

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        return fd;
    }

    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

static int ksu_queue_install_fd(void __user *arg)
{
	struct ksu_install_fd_tw *tw;

	if (!arg)
		return -EINVAL;

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw)
		return -ENOMEM;

	tw->outp = (int __user *)arg;
	tw->cb.func = ksu_install_fd_tw_func;

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("install fd add task_work failed\n");
		return -EINVAL;
	}

	return 0;
}

static int ksu_change_spoof_uname(void __user *arg)
{
	char release_buf[65];
	char version_buf[65];
	static char original_release_buf[65];
	static char original_version_buf[65];
	void __user **user_indirect;
	uint64_t user_ptr_ptr = 0;
	uint64_t user_ptr = 0;
	struct new_utsname *uts;

	if (!arg)
		return -EINVAL;

	user_indirect = (void __user **)arg;

	if (copy_from_user(
		    &user_ptr_ptr,
		    user_indirect,
		    sizeof(user_ptr_ptr)))
		return -EINVAL;

	if (copy_from_user(
		    &user_ptr,
		    (void __user *)(uintptr_t)user_ptr_ptr,
		    sizeof(user_ptr)))
		return -EINVAL;

	if (strncpy_from_user(
		    release_buf,
		    (char __user *)(uintptr_t)user_ptr,
		    sizeof(release_buf)) < 0)
		return -EINVAL;

	release_buf[sizeof(release_buf) - 1] = '\0';

	if (strncpy_from_user(
		    version_buf,
		    (char __user *)(uintptr_t)(
			    user_ptr + strlen(release_buf) + 1),
		    sizeof(version_buf)) < 0)
		return -EINVAL;

	version_buf[sizeof(version_buf) - 1] = '\0';

	uts = utsname();

	if (!original_release_buf[0]) {
		strscpy(
			original_release_buf,
			uts->release,
			sizeof(original_release_buf));

		strscpy(
			original_version_buf,
			uts->version,
			sizeof(original_version_buf));
	}

	if (!strcmp(release_buf, "default") ||
	    !strcmp(version_buf, "default")) {
		strscpy(
			release_buf,
			original_release_buf,
			sizeof(release_buf));

		strscpy(
			version_buf,
			original_version_buf,
			sizeof(version_buf));
	}

	down_write(&uts_sem);

	strscpy(
		uts->release,
		release_buf,
		sizeof(uts->release));

	strscpy(
		uts->version,
		version_buf,
		sizeof(uts->version));

	up_write(&uts_sem);

	return 0;
}

int ksu_supercall_reboot_handler(
	int magic2,
	unsigned int cmd,
	void __user **arg)
{
	void __user *user_arg;
	unsigned long reply;

	if (!arg)
		return -EINVAL;

	user_arg = *arg;
	reply = (unsigned long)user_arg;

	switch (magic2) {
	case KSU_INSTALL_MAGIC2:
		return ksu_queue_install_fd(user_arg);

	case CHANGE_MANAGER_UID:
		if (current_uid().val != 0)
			return -EINVAL;

		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid() &&
		    copy_to_user(
			    user_arg,
			    &reply,
			    sizeof(reply)))
			return -EINVAL;

		return 0;

	case GET_SULOG_DUMP_V2:
		if (current_uid().val != 0)
			return -EINVAL;

		if (ksu_sulog_handle_compat_dump(user_arg))
			return -EINVAL;

		if (copy_to_user(
			    user_arg,
			    &reply,
			    sizeof(reply)))
			return -EINVAL;

		return 0;

	case CHANGE_KSUVER:
		if (current_uid().val != 0)
			return -EINVAL;

		ksuver_override = cmd;

		if (copy_to_user(
			    user_arg,
			    &reply,
			    sizeof(reply)))
			return -EINVAL;

		return 0;

	case CHANGE_SPOOF_UNAME:
		if (current_uid().val != 0)
			return -EINVAL;

		if (ksu_change_spoof_uname(user_arg))
			return -EINVAL;

		if (copy_to_user(
			    user_arg,
			    &reply,
			    sizeof(reply)))
			return -EINVAL;

		return 0;

	default:
		return -EINVAL;
	}
}

void __init ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();
}

void __exit ksu_supercalls_exit(void)
{
	ksu_supercall_cleanup_state();
}
