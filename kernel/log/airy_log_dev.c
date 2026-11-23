// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_dev.c — A-ULP 日志环的字符设备前端。
 *
 * 内核写者与 printk 桥共享一个全局环；Logger Daemon 通过 /dev/airy_log
 * 打开它，用 AIRY_LOG_IOC_GEOM 查询几何、mmap 共享区零拷贝读取，
 * 再用 AIRY_LOG_IOC_EFD 注册 eventfd 获得有新记录时的唤醒。
 * 设备本身不搬运数据：所有读写都发生在 mmap 出来的同一组页上。
 *
 * SSoT: docs-linux/40-dataflows/05-ring-buffer-logging.md §4、§5。
 */

#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <linux/airymax/log_ring.h>

#include "airy_log_internal.h"

static struct airy_log_ring	airy_ring;
static dev_t			airy_devt;
static struct cdev		airy_cdev;
static struct class		*airy_class;

struct airy_log_ring *airy_log_global(void)
{
	return &airy_ring;
}

static int airy_log_open(struct inode *inode, struct file *file)
{
	struct airy_log_ring *ring = airy_log_global();

	if (!READ_ONCE(ring->kaddr))
		return -ENODEV;

	file->private_data = ring;
	return 0;
}

static int airy_log_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int log_geom(struct airy_log_ring *ring, unsigned long arg)
{
	struct airy_log_ring_header *hdr = ring->kaddr;
	struct airy_log_geom geom;

	memset(&geom, 0, sizeof(geom));
	geom.abi	= AIRY_LOG_RING_ABI;
	geom.capacity	= hdr->capacity;
	geom.record_size = hdr->record_size;
	geom.hdr_size	= sizeof(*hdr);
	geom.ring_bytes	= ring->size;

	if (copy_to_user((void __user *)arg, &geom, sizeof(geom)))
		return -EFAULT;

	return 0;
}

static long airy_log_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct airy_log_ring *ring = file->private_data;
	__s32 efd;

	if (!ring || !READ_ONCE(ring->kaddr))
		return -ENODEV;

	switch (cmd) {
	case AIRY_LOG_IOC_EFD:
		if (copy_from_user(&efd, (void __user *)arg, sizeof(efd)))
			return -EFAULT;
		if (efd < 0)
			return -EINVAL;
		return airy_log_ring_register_eventfd(ring, efd);
	case AIRY_LOG_IOC_GEOM:
		return log_geom(ring, arg);
	case AIRY_LOG_IOC_FREEZE:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		airy_log_ring_freeze(ring);
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations airy_log_fops = {
	.owner		= THIS_MODULE,
	.open		= airy_log_open,
	.release	= airy_log_release,
	.mmap		= airy_log_ring_mmap,
	.unlocked_ioctl	= airy_log_ioctl,
	.compat_ioctl	= airy_log_ioctl,
	.llseek		= no_llseek,
};

static int __init airy_log_dev_init(void)
{
	struct airy_log_ring_header *hdr;
	int rc;

	rc = airy_log_ring_init(&airy_ring, CONFIG_AIRY_LOG_RING_BYTES);
	if (rc)
		return rc;

	hdr = airy_ring.kaddr;

	rc = alloc_chrdev_region(&airy_devt, 0, 1, AIRY_LOG_DEV_NAME);
	if (rc)
		goto err_ring;

	cdev_init(&airy_cdev, &airy_log_fops);
	airy_cdev.owner = THIS_MODULE;
	rc = cdev_add(&airy_cdev, airy_devt, 1);
	if (rc)
		goto err_region;

	airy_class = class_create(AIRY_LOG_DEV_NAME);
	if (IS_ERR(airy_class)) {
		rc = PTR_ERR(airy_class);
		airy_class = NULL;
		goto err_cdev;
	}

	if (IS_ERR(device_create(airy_class, NULL, airy_devt, NULL,
				 AIRY_LOG_DEV_NAME))) {
		rc = -ENODEV;
		goto err_class;
	}

	pr_info("airy_log: %zu KiB ring, %u slots of %u B at %s\n",
		airy_ring.size >> 10, hdr->capacity, hdr->record_size,
		AIRY_LOG_DEV_PATH);
	return 0;

err_class:
	class_destroy(airy_class);
	airy_class = NULL;
err_cdev:
	cdev_del(&airy_cdev);
err_region:
	unregister_chrdev_region(airy_devt, 1);
err_ring:
	airy_log_ring_destroy(&airy_ring);
	return rc;
}
postcore_initcall(airy_log_dev_init);
