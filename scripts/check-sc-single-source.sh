#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# check-sc-single-source.sh — [SC] Single-Source Verification (OS-IRON-014)
#
# Verifies that the 10 [SC] shared-contract header files exist ONLY in
# their single physical host directory (include/uapi/linux/airymax/).
# Detects forbidden physical copies elsewhere in the tree.
#
# Usage: scripts/check-sc-single-source.sh [kernel_source_root]
# Exit:  0 = pass, 1 = violations found

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KSRC="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SC_HOST="include/uapi/linux/airymax"

# The 10 [SC] headers that must have exactly one physical host
SC_HEADERS=(
    "error.h"
    "ipc.h"
    "sched.h"
    "syscalls.h"
    "uapi_compat.h"
    "lsm_types.h"
    "security_types.h"
    "memory_types.h"
    "cognition_types.h"
    "log_types.h"
)

# Directories to exclude from the search (build artifacts, .git, etc.)
EXCLUDE_DIRS=(
    "-path" "${KSRC}/.git" "-prune" "-o"
    "-path" "${KSRC}/Documentation" "-prune" "-o"
    "-path" "*/built-in.a" "-prune" "-o"
    "-path" "*/.tmp_*" "-prune" "-o"
)

violations=0
missing=0

echo "[check-sc] Verifying [SC] single-source principle (OS-IRON-014)..."
echo "[check-sc] Kernel source root: ${KSRC}"
echo "[check-sc] Expected host:      ${SC_HOST}/"
echo ""

for hdr in "${SC_HEADERS[@]}"; do
    host_file="${KSRC}/${SC_HOST}/${hdr}"

    # Check 1: file must exist in the host directory
    if [[ ! -f "${host_file}" ]]; then
        echo "  FAIL: ${hdr} missing from host ${SC_HOST}/"
        missing=$((missing + 1))
        violations=$((violations + 1))
        continue
    fi

    # Check 2: search for copies elsewhere in the tree
    # Find all files with the same name, excluding the host directory.
    # For each candidate, verify it contains Airymax-specific markers
    # (SPHARX / _UAPI_AIRYMAX_ / AIRY_) to distinguish from Linux
    # upstream files that happen to share the same basename
    # (e.g. include/linux/sched.h, include/uapi/linux/ipc.h).
    copies=""
    while IFS= read -r candidate; do
        [[ -z "${candidate}" ]] && continue
        # Skip files that do not contain Airymax markers
        if grep -qE 'SPHARX|_UAPI_AIRYMAX_|AIRYMAX|airy_' "${candidate}" 2>/dev/null; then
            copies="${copies}${candidate}\n"
        fi
    done < <(find "${KSRC}" \
        "${EXCLUDE_DIRS[@]}" \
        -name "${hdr}" \
        -not -path "${KSRC}/${SC_HOST}/*" \
        -type f \
        -print 2>/dev/null || true)

    if [[ -n "${copies}" ]]; then
        echo "  FAIL: ${hdr} has Airymax copies outside ${SC_HOST}/:"
        echo -e "${copies}" | sed 's/^/        /'
        violations=$((violations + 1))
    else
        echo "  OK:   ${hdr} — single-source in ${SC_HOST}/"
    fi
done

echo ""
if [[ ${violations} -eq 0 ]]; then
    echo "[check-sc] PASS: All 10 [SC] headers are single-source."
    exit 0
else
    echo "[check-sc] FAIL: ${violations} violation(s) found."
    if [[ ${missing} -gt 0 ]]; then
        echo "[check-sc]   ${missing} header(s) missing from host."
    fi
    exit 1
fi
