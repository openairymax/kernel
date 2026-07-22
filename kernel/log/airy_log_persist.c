/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025-2026 SPHARX Ltd.
 *
 * airy_log_persist.c — A-ULP PMEM/file persistence backend.
 *
 * Flushes 128-byte log records to a backing file (default
 * /var/log/airy/airy.log) using filp_open() + kernel_write().  This is
 * the durable sink for the in-memory ring buffer.
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/airymax/log_types.h>

/* ─── Module parameter: persistence target path ───────────────────────── */
static char *airy_log_persist_path = "/var/log/airy/airy.log";
module_param(airy_log_persist_path, charp, 0644);
MODULE_PARM_DESC(airy_log_persist_path,
		 "Persistent log file path (default: /var/log/airy/airy.log)");

/* ─── Serialises concurrent flush/init against interleaved writes ──── */
static DEFINE_MUTEX(airy_log_persist_lock);

/* ─── Open the backing file in append mode ────────────────────────────── */
static struct file *airy_log_persist_open(void)
{
	if (!airy_log_persist_path || !*airy_log_persist_path)
		return ERR_PTR(-EINVAL);

	return filp_open(airy_log_persist_path,
			 O_WRONLY | O_CREAT | O_APPEND, 0644);
}

/* ─── Init: create the file and write a session marker ────────────────── */
int airy_log_persist_init(void)
{
	struct file *filp;
	static const char hdr[] = "airy-log-persist: session start\n";
	loff_t pos = 0;
	ssize_t wr;

	mutex_lock(&airy_log_persist_lock);

	filp = airy_log_persist_open();
	if (IS_ERR(filp)) {
		mutex_unlock(&airy_log_persist_lock);
		return PTR_ERR(filp);
	}

	wr = kernel_write(filp, hdr, sizeof(hdr) - 1, &pos);
	filp_close(filp, NULL);

	mutex_unlock(&airy_log_persist_lock);

	if (wr < 0)
		return (int)wr;
	return 0;
}

/* ─── Flush an array of records to the backing file ───────────────────── */
int airy_log_persist_flush(const struct airy_log_record *records, size_t n)
{
	struct file *filp;
	loff_t pos = 0;
	size_t i;
	ssize_t wr;

	if (!records || n == 0)
		return -EINVAL;

	mutex_lock(&airy_log_persist_lock);

	filp = airy_log_persist_open();
	if (IS_ERR(filp)) {
		mutex_unlock(&airy_log_persist_lock);
		return PTR_ERR(filp);
	}

	for (i = 0; i < n; i++) {
		wr = kernel_write(filp, &records[i],
				  sizeof(records[i]), &pos);
		if (wr != sizeof(records[i])) {
			int err = (wr < 0) ? (int)wr : -EIO;
			filp_close(filp, NULL);
			mutex_unlock(&airy_log_persist_lock);
			return err;
		}
	}

	filp_close(filp, NULL);
	mutex_unlock(&airy_log_persist_lock);
	return 0;
}
