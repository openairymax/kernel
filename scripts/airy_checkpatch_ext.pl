#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0
#
# airy_checkpatch_ext.pl — AirymaxOS 专属 checkpatch 扩展规则引擎
#
# 本引擎在上游 scripts/checkpatch.pl 之外，补充 AirymaxOS 子系统的架构
# 约束检查（AIRY-CHECKPATCH-001 ~ 011）。上游 checkpatch 负责通用内核
# 风格；本引擎负责 AirymaxOS 特有约束：日志接口、命名前缀、并发内存序、
# IPC 入口、LSM 注册、DMA 使用、配置项黑白名单，以及文件头规范。
#
# 规则依据：
#   docs/AirymaxOS/80-testing/05-static-analysis.md §7.2（001~010）
#   docs/AirymaxOS/50-engineering-standards/01-coding-standards.md §8.5.3（011）
#
# 用法与退出码见 --help。

use strict;
use warnings;

use File::Basename qw(basename dirname);
use File::Find ();
use Cwd qw(abs_path);
use Getopt::Long qw(GetOptions);

use constant {
	EX_OK    => 0,
	EX_ERROR => 1,
	EX_USAGE => 2,
};

# 默认扫描目录：AirymaxOS 在 kernel 树内的全部落点（相对仓库根）。
my @DEFAULT_DIRS = (
	'security/airy',
	'kernel/superv',
	'kernel/syscalls',
	'kernel/corekern',
	'kernel/log',
	'kernel/ipc',
	'include/airymax',
	'include/uapi/linux/airymax',
);

# 文件头前导注释区上限（OS-STD-STY-007：SPDX 首行 + ≤20 行模块描述）。
use constant HEADER_MAX => 20;

# 规则严重性：error 阻断，warning 不阻断。
my %SEVERITY = (
	'AIRY-CHECKPATCH-001' => 'error',
	'AIRY-CHECKPATCH-002' => 'error',
	'AIRY-CHECKPATCH-003' => 'error',
	'AIRY-CHECKPATCH-004' => 'error',
	'AIRY-CHECKPATCH-005' => 'warning',
	'AIRY-CHECKPATCH-006' => 'error',
	'AIRY-CHECKPATCH-007' => 'error',
	'AIRY-CHECKPATCH-008' => 'error',
	'AIRY-CHECKPATCH-009' => 'error',
	'AIRY-CHECKPATCH-010' => 'error',
	'AIRY-CHECKPATCH-011' => 'error',
);

# C 语言关键字：用于排除把控制语句误判为函数定义。
my %C_KEYWORDS = map { $_ => 1 } qw(
	if else for while do switch case default return sizeof typeof __typeof__
	goto break continue struct union enum typedef static extern inline const
	volatile register auto signed unsigned void int char short long float double
);

my ($opt_help, $opt_quiet);
GetOptions(
	'help|h'  => \$opt_help,
	'quiet|q' => \$opt_quiet,
) or usage(EX_USAGE);

if ($opt_help) {
	print <<"USAGE";
$0 — AirymaxOS 专属 checkpatch 扩展规则引擎

用法:
  $0 [选项] [路径 ...]

路径可以是文件或目录；省略时扫描 AirymaxOS 在 kernel 树内的默认落点:
  @{[ join("\n  ", @DEFAULT_DIRS) ]}

选项:
  -h, --help    显示本帮助后退出
  -q, --quiet   仅输出违规项与汇总，不输出进度信息

规则:
  001 error    必须使用 pr_*() 而非 printk()
  002 error    AirymaxOS 函数必须以 airy_/stc_ 前缀命名
  003 error    airy_agent_state 访问必须使用 READ_ONCE/WRITE_ONCE
  004 error    airy_ipc_send() 调用必须检查返回值
  005 warning  airy_cap_check() 调用必须显式处理 -EPERM
  006 error    禁止在 airy_* 函数中直接调用 printk()
  007 error    AirymaxOS LSM 注册必须使用 security_hook_list
  008 error    禁止在 airy_ipc/airy_mem 路径中调用 dma_alloc_coherent()
  009 error    禁止在 AirymaxOS 路径中启用 CONFIG_BPF_LSM=y
  010 error    禁止在 AirymaxOS 路径中启用 CONFIG_SCHED_EXT=y
  011 error    文件头规范：SPDX 首行 + 前导注释区 ≤ @{[ HEADER_MAX ]} 行

退出码:
  0  无 error 级违规
  1  存在 error 级违规
  2  用法或 IO 错误
USAGE
	exit EX_OK;
}

# --- 仓库根与目标集合 -----------------------------------------
my $script = abs_path($0) // $0;
my $repo_root = dirname(dirname($script));

my @targets = @ARGV ? @ARGV : map { "$repo_root/$_" } @DEFAULT_DIRS;

# Airy 配置片段（defconfig）也纳入配置项检查。
foreach my $cfg (glob("$repo_root/arch/*/configs/airy*_defconfig")) {
	push @targets, $cfg;
}

my @files = collect_files(@targets);

if (!@files) {
	print STDERR "$0: no input files found\n" unless $opt_quiet;
	exit EX_USAGE;
}

# --- 扫描 ------------------------------------------------------
my @violations;
foreach my $file (sort @files) {
	next if -B $file;
	my $lines = read_lines($file);
	next unless $lines;
	push @violations, check_file($file, $lines);
}

# --- 输出 ------------------------------------------------------
my ($errors, $warnings) = (0, 0);
foreach my $v (@violations) {
	my $rel = rel_path($v->{file});
	printf "%s:%d: %s %s: %s\n",
		$rel, $v->{line}, uc($v->{sev}), $v->{id}, $v->{msg};
	if ($v->{sev} eq 'error') { $errors++; } else { $warnings++; }
}

printf "airy_checkpatch_ext: %d files checked, %d errors, %d warnings\n",
	scalar(@files), $errors, $warnings;

exit($errors ? EX_ERROR : EX_OK);

# ---------------------------------------------------------------
# 子程序
# ---------------------------------------------------------------

sub usage {
	my ($code) = @_;
	print STDERR "$0: invalid usage; try '$0 --help'\n";
	exit $code;
}

sub rel_path {
	my ($p) = @_;
	my $r = $p;
	$r =~ s/^\Q$repo_root\E\///;
	return $r;
}

# 收集目标中的普通文件（递归目录展开），去重。
sub collect_files {
	my (@paths) = @_;
	my %seen;
	my @out;
	foreach my $p (@paths) {
		if (-d $p) {
			File::Find::find(
				{
					no_chdir => 1,
					wanted   => sub {
						my $f = $File::Find::name;
						return unless -f $f;
						return if $seen{$f}++;
						push @out, $f;
					},
				},
				$p
			);
		} elsif (-f $p) {
			my $a = abs_path($p) // $p;
			next if $seen{$a}++;
			push @out, $a;
		}
	}
	return @out;
}

sub read_lines {
	my ($file) = @_;
	open my $fh, '<', $file or return undef;
	my @raw = <$fh>;
	close $fh;
	chomp @raw;
	s/\r$// for @raw;
	return \@raw;
}

# 把注释与字符串字面量替换为空格，保留列位置，用于代码级规则。
sub strip_file {
	my ($raw) = @_;
	my @out;
	my $in_block = 0;
	foreach my $line (@$raw) {
		my $res = '';
		my $i = 0;
		my $n = length($line);
		my $in_str = 0;
		my $delim = '';
		while ($i < $n) {
			my $c = substr($line, $i, 1);
			my $two = substr($line, $i, 2);
			if ($in_block) {
				if ($two eq '*/') { $in_block = 0; $i += 2; $res .= '  '; next; }
				$res .= ' ';
				$i++;
				next;
			}
			if ($in_str) {
				if ($c eq '\\') { $res .= '  '; $i += 2; next; }
				$in_str = 0 if $c eq $delim;
				$res .= ' ';
				$i++;
				next;
			}
			if ($two eq '/*') { $in_block = 1; $res .= '  '; $i += 2; next; }
			last if $two eq '//';
			if ($c eq '"' || $c eq "'") {
				$in_str = 1;
				$delim  = $c;
				$res .= ' ';
				$i++;
				next;
			}
			$res .= $c;
			$i++;
		}
		push @out, $res;
	}
	return \@out;
}

# 判断一行是否为「非 static 函数定义」，是则返回函数名。
sub def_name_in_line {
	my ($s, $prev) = @_;
	return undef unless defined $s && length $s;
	return undef if $s =~ /^\s/;
	return undef if $s =~ /^\s*[{};]/;
	return undef if $s =~ /^\s*#/;
	return undef if $s =~ /^\s*(?:static|extern|typedef)\b/;
	return undef unless $s =~ /\([^;]*\)\s*\{?\s*$/;
	my $idx = index($s, '(');
	return undef if $idx <= 0;
	my $prefix = substr($s, 0, $idx);
	my ($name) = $prefix =~ /([A-Za-z_][A-Za-z0-9_]*)\s*$/;
	return undef unless defined $name;
	return undef if $name eq 'main';
	return undef if $name =~ /[A-Z]/;
	return undef if $C_KEYWORDS{$name};
	my $before = substr($prefix, 0, length($prefix) - length($name));
	$before =~ s/\s+$//;
	if ($before eq '') {
		return undef unless defined $prev && $prev =~ /^[A-Za-z_][\w\s\*]*$/;
		return undef if $prev =~ /[();={}]/;
	}
	return $name;
}

# 计算每行所处的函数名（用于区分规则 001 与 006）。
sub compute_enclosing {
	my ($codes) = @_;
	my @enc  = ('') x scalar(@$codes);
	my $depth = 0;
	my $prev_depth = 0;
	my $cur = '';
	for my $i (0 .. $#$codes) {
		my $s = $codes->[$i];
		if ($depth == 0) {
			my $nm = def_name_in_line($s, undef);
			$cur = $nm if defined $nm;
		}
		$enc[$i] = $cur;
		my $o = ($s =~ tr/{//);
		my $c = ($s =~ tr/}//);
		$depth += $o - $c;
		$depth = 0 if $depth < 0;
		$cur = '' if $depth == 0 && $prev_depth > 0;
		$prev_depth = $depth;
	}
	return \@enc;
}

sub is_c_source {
	my ($file) = @_;
	return $file =~ /\.(?:c|h)$/;
}

sub check_file {
	my ($file, $raw) = @_;
	my @vio;
	my $codes = strip_file($raw);
	my $enc   = compute_enclosing($codes);
	my $c_src = is_c_source($file);
	my $rel   = rel_path($file);

	# 011：文件头规范（仅源文件）
	if ($c_src) {
		push_vio(\@vio, $file, 1, 'AIRY-CHECKPATCH-011',
			'line 1 must carry an SPDX-License-Identifier')
			unless ($raw->[0] // '') =~ /SPDX-License-Identifier/;

		my $lead = scalar(@$codes);
		for my $i (0 .. $#$codes) {
			if ($codes->[$i] =~ /\S/) { $lead = $i; last; }
		}
		if ($lead > HEADER_MAX) {
			push_vio(\@vio, $file, 1, 'AIRY-CHECKPATCH-011',
				"leading comment block is $lead lines (max " . HEADER_MAX .
				'); move design rationale to git log / docs');
		}
	}

	for my $i (0 .. $#$codes) {
		my $s   = $codes->[$i];
		my $lin = $i + 1;

		# 002：非 static 函数定义命名前缀
		if ($c_src) {
			my $prev = $i > 0 ? $codes->[$i - 1] : undef;
			my $name = def_name_in_line($s, $prev);
			if (defined $name && $name !~ /^(?:airy_|stc_)/) {
				push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-002',
					"function '$name' must use the airy_/stc_ prefix");
				next;
			}
		}

		# 008：airy_ipc/airy_mem 路径禁止 dma_alloc_coherent
		if ($c_src && $rel =~ /airy_ipc|airy_mem/ && $s =~ /\bdma_alloc_coherent\s*\(/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-008',
				'dma_alloc_coherent() forbidden in airy_ipc/airy_mem path');
			next;
		}

		# 009/010：配置项黑名单
		if ($s !~ /^\s*#/ && $s =~ /\bCONFIG_BPF_LSM\b\s*=\s*y\b/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-009',
				'CONFIG_BPF_LSM=y forbidden — pure-C LSM enforced');
			next;
		}
		if ($s !~ /^\s*#/ && $s =~ /\bCONFIG_SCHED_EXT\b\s*=\s*y\b/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-010',
				'CONFIG_SCHED_EXT=y forbidden — sched_tac enforced');
			next;
		}

		# 007：LSM 注册必须使用 security_hook_list
		if ($c_src && $s =~ /\b(?:security_hook_heads|register_security|mod_reg_security)\b/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-007',
				'LSM registration must use security_hook_list');
			next;
		}

		# 001/006：printk
		if ($c_src && $s =~ /\bprintk\s*\(/) {
			my $id = ($enc->[$i] =~ /^(?:airy_|stc_)/)
				? 'AIRY-CHECKPATCH-006'
				: 'AIRY-CHECKPATCH-001';
			push_vio(\@vio, $file, $lin, $id,
				'use pr_*() instead of printk()');
			next;
		}

		# 003：共享状态访问必须使用 READ_ONCE/WRITE_ONCE
		if ($c_src && $s =~ /\bairy_agent_state\b/
			&& $s !~ /\benum\s+airy_agent_state\b/) {
			my $objectish = $s =~ /(?:->|\.)\s*airy_agent_state\b/
				|| $s =~ /\bairy_agent_state\s*(?:=|\+=|-=|\|=|&=|\+\+|--|\[)/;
			if ($objectish && $s !~ /\b(?:READ_ONCE|WRITE_ONCE)\s*\(/) {
				push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-003',
					'airy_agent_state access must use READ_ONCE/WRITE_ONCE');
				next;
			}
		}

		# 004：airy_ipc_send 返回值必须被检查
		if ($c_src && $s =~ /^\s*(?:\(\s*void\s*\)\s*)?airy_ipc_send\s*\(.*\)\s*;\s*$/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-004',
				'airy_ipc_send() return value must be checked');
			next;
		}

		# 005：airy_cap_check 必须显式处理 -EPERM
		if ($c_src && $s =~ /\bairy_cap_check\s*\(/) {
			push_vio(\@vio, $file, $lin, 'AIRY-CHECKPATCH-005',
				'airy_cap_check() call must handle -EPERM explicitly');
			next;
		}
	}

	return @vio;
}

sub push_vio {
	my ($vio, $file, $line, $id, $msg) = @_;
	push @$vio, {
		file => $file,
		line => $line,
		id   => $id,
		sev  => $SEVERITY{$id},
		msg  => $msg,
	};
}
