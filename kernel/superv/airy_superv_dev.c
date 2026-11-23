// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_superv_dev.c — /dev/airy_superv fault channel for macro_d.
 *
 * The Micro-Supervisor records fault details in a bounded ring and wakes
 * the Macro-Supervisor through a registered eventfd, but until this device
 * existed neither side was reachable from user space: the eventfd could
 * only be registered by kernel code and the detail ring had no reader.
 * The device closes both gaps for the single supervisor process.
 *
 * Ownership is exclusive: opening it succeeds once, so the detail ring
 * keeps its single-consumer contract. Binding replaces any previous
 * eventfd; closing the device unbinds it so a crashed supervisor cannot
 * leave a stale context behind.
 *
 * Design rationale: docs-linux/20-modules/09-kernel-agent-supervisor.md §5
 */

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <linux/airymax/error.h>
#include <linux/airymax/superv.h>

#include "../../security/airy/airy_cap.h"
#include "airy_superv.h"

#define AIRY_SUPERV_DEV_NAME	"airy_superv"

static dev_t superv_devt;
static struct cdev superv_cdev;
static struct class *superv_class;
static atomic_t superv_open = ATOMIC_INIT(0);

/* 绑定方信息：只在成功 open 后填写，供 /sys/airy/daemons 读取。 */
static DEFINE_SPINLOCK(superv_bind_lock);
static u32 superv_bind_pid;
static u64 superv_bind_ns;

static int superv_open_dev(struct inode *inode, struct file *file)
{
	unsigned long flags;

	if (!capable(CAP_SYS_PTRACE))
		return -EPERM;
	if (atomic_cmpxchg(&superv_open, 0, 1))
		return -EBUSY;

	spin_lock_irqsave(&superv_bind_lock, flags);
	superv_bind_pid = (u32)task_tgid_nr(current);
	superv_bind_ns  = ktime_get_mono_fast_ns();
	spin_unlock_irqrestore(&superv_bind_lock, flags);

	return 0;
}

static int superv_release_dev(struct inode *inode, struct file *file)
{
	unsigned long flags;

	airy_eventfd_unregister();

	spin_lock_irqsave(&superv_bind_lock, flags);
	superv_bind_pid = 0;
	superv_bind_ns  = 0;
	spin_unlock_irqrestore(&superv_bind_lock, flags);

	atomic_set(&superv_open, 0);
	return 0;
}

void airy_svdev_snapshot(struct airy_svdev_info *out)
{
	unsigned long flags;

	if (!out)
		return;

	spin_lock_irqsave(&superv_bind_lock, flags);
	out->active   = (u32)atomic_read(&superv_open);
	out->pid      = superv_bind_pid;
	out->since_ns = superv_bind_ns;
	spin_unlock_irqrestore(&superv_bind_lock, flags);
}

static ssize_t superv_read(struct file *file, char __user *buf, size_t len,
			   loff_t *ppos)
{
	size_t done = 0;

	if (len < AIRY_FAULT_EVENT_SIZE)
		return -EINVAL;

	while (len - done >= AIRY_FAULT_EVENT_SIZE) {
		struct airy_fault_event ev;
		int ret = airy_fev_fetch(&ev);

		if (ret)
			break;
		if (copy_to_user(buf + done, &ev, sizeof(ev)))
			return done ? (ssize_t)done : -EFAULT;
		done += sizeof(ev);
	}

	return done ? (ssize_t)done : -EAGAIN;
}

static long superv_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	__s32 efd;
	__u32 lost;

	switch (cmd) {
	case AIRY_SUPERV_IOC_BIND_EFD:
		if (get_user(efd, (__s32 __user *)arg))
			return -EFAULT;
		return airy_eventfd_register(efd);
	case AIRY_SUPERV_IOC_UNBIND:
		airy_eventfd_unregister();
		return 0;
	case AIRY_SUPERV_IOC_LOST:
		lost = airy_fev_lost();
		return put_user(lost, (__u32 __user *)arg) ? -EFAULT : 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations superv_fops = {
	.owner		= THIS_MODULE,
	.open		= superv_open_dev,
	.release	= superv_release_dev,
	.read		= superv_read,
	.unlocked_ioctl	= superv_ioctl,
	.compat_ioctl	= superv_ioctl,
	.llseek		= no_llseek,
};

static int __init airy_superv_dev_init(void)
{
	int rc;

	rc = alloc_chrdev_region(&superv_devt, 0, 1, AIRY_SUPERV_DEV_NAME);
	if (rc)
		return rc;

	cdev_init(&superv_cdev, &superv_fops);
	superv_cdev.owner = THIS_MODULE;
	rc = cdev_add(&superv_cdev, superv_devt, 1);
	if (rc)
		goto err_region;

	superv_class = class_create(AIRY_SUPERV_DEV_NAME);
	if (IS_ERR(superv_class)) {
		rc = PTR_ERR(superv_class);
		superv_class = NULL;
		goto err_cdev;
	}

	if (IS_ERR(device_create(superv_class, NULL, superv_devt, NULL,
				 AIRY_SUPERV_DEV_NAME))) {
		rc = -ENODEV;
		goto err_class;
	}

	return 0;

err_class:
	class_destroy(superv_class);
	superv_class = NULL;
err_cdev:
	cdev_del(&superv_cdev);
err_region:
	unregister_chrdev_region(superv_devt, 1);
	return rc;
}
postcore_initcall(airy_superv_dev_init);
