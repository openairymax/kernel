// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026 SPHARX Ltd. All Rights Reserved.
 *
 * airy_bpf_probe.c — Airymax BPF observability probe.
 *
 * Provides airy_bpf_probe_trace() for lightweight tracing from BPF
 * struct_ops callbacks.  Implemented on top of the kernel printk ring
 * buffer (the equivalent of trace_bpf_trace_printk() in mainline).
 * Only compiled when CONFIG_BPF=y.
 */

#include <linux/printk.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

/* ─── Trace probe entry point ────────────────────────────────────────── */
int airy_bpf_probe_trace(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (!fmt)
		return -EINVAL;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	/*
	 * Emit to the kernel log ring buffer.  The %pV specifier expands
	 * the nested va_list safely.
	 */
	pr_info("airy_bpf_probe: %pV\n", &vaf);

	va_end(args);
	return 0;
}
