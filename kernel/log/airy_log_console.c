// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_log_console.c — printk 到 A-ULP 日志环的桥接控制台。
 *
 * 注册一个只写环、不写终端的控制台：printk 的每条消息都会按 96 字节
 * 分片进入共享日志环，Logger Daemon 因而能在开机阶段就落盘内核日志，
 * 不必等 systemd-journald 接管。注册时带 CON_PRINTBUFFER，把注册前
 * 已经进入 printk 缓冲区的启动日志整体回放一遍。
 *
 * 该路径运行在 console_lock 上下文，可能是原子上下文，因此只使用
 * 预分配页与事件通知，不睡眠、不分配内存。
 *
 * SSoT: docs-linux/40-dataflows/05-ring-buffer-logging.md §3。
 */

#include <linux/console.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/types.h>

#include <linux/airymax/log_types.h>

#include "airy_log_internal.h"

/* printk 的 8 级优先权到 A-ULP 5 级语义的映射。 */
static const __u16 airy_console_level[8] = {
	AIRY_LOG_FATAL,	/* KERN_EMERG	*/
	AIRY_LOG_FATAL,	/* KERN_ALERT	*/
	AIRY_LOG_FATAL,	/* KERN_CRIT	*/
	AIRY_LOG_ERROR,	/* KERN_ERR	*/
	AIRY_LOG_WARN,	/* KERN_WARNING	*/
	AIRY_LOG_INFO,	/* KERN_NOTICE	*/
	AIRY_LOG_INFO,	/* KERN_INFO	*/
	AIRY_LOG_DEBUG,	/* KERN_DEBUG	*/
};

static __u16 airy_console_parse(const char *text, unsigned int len,
				unsigned int *skip)
{
	if (len >= 3 && text[0] == '<' && text[2] == '>' &&
	    text[1] >= '0' && text[1] <= '7') {
		*skip = 3;
		return airy_console_level[text[1] - '0'];
	}

	*skip = 0;
	return AIRY_LOG_INFO;
}

static void airy_console_write(struct console *con, const char *text,
			       unsigned int len)
{
	struct airy_log_ring *ring = airy_log_global();
	unsigned int skip, chunk;
	__u16 level;

	if (!ring || !READ_ONCE(ring->kaddr) || !len)
		return;

	level = airy_console_parse(text, len, &skip);
	text += skip;
	len -= skip;

	while (len) {
		chunk = min(len, (unsigned int)96);
		airy_log_write(ring, level, AIRY_LOG_FAC_KERN, text, chunk);
		text += chunk;
		len -= chunk;
	}
}

static struct console airy_console = {
	.name	= "airy",
	.write	= airy_console_write,
	.flags	= CON_PRINTBUFFER,
	.index	= -1,
};

static int __init airy_console_init(void)
{
	struct airy_log_ring *ring = airy_log_global();

	if (!ring || !READ_ONCE(ring->kaddr))
		return -ENODEV;

	register_console(&airy_console);
	return 0;
}
device_initcall(airy_console_init);
