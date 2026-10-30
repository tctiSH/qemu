#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Runs the TCG tests for each guest in build/ under one backend of the hybrid.
#   ci-check-tcg.sh on|off|rcg|rcg-plain
# on: TCTI, off: the JIT, rcg: TCTI with RCG, rcg-plain: the same with
# barriers and plain loads and stores in place of LDAPR and STLR, as on
# hosts without LRCPC or LSE2 (rcg expects a host with both, as every Apple
# M-series chip has).
set -euo pipefail

targets="x86_64 aarch64"
order=
case $1 in
# RCG has gadgets for x86_64 guests only.
rcg) accel=tcti=on,rcg=on targets=x86_64 order=ordered ;;
rcg-plain) accel=tcti=on,rcg=on,tcti-ordered=off targets=x86_64 order=plain ;;
*) accel=tcti=$1 ;;
esac
build=$(cd build && pwd)
wrappers=$(mktemp -d)
status=0

for target in $targets; do
  wrapper=$wrappers/qemu-system-$target
  # The RCG tests also pass if RCG takes nothing, so with RCG they trace
  # each gadget it takes, and each jumps gadget TCTI swaps in. The kernel is
  # the last argument.
  cat >"$wrapper" <<EOF
#!/bin/sh
trace=
for kernel; do :; done
case "$order:\${kernel##*/}" in
?*:rcg-insns|?*:rcg-faults)
  trace="-trace rcg_insn -trace rcg_jumps -D $wrappers/trace.\$\$" ;;
esac
exec $build/qemu-system-$target -accel tcg,$accel \$trace "\$@"
EOF
  chmod +x "$wrapper"
  make -C "$build" "run-tcg-tests-$target-softmmu" QEMU="$wrapper" || status=1
done

# Between them, the RCG tests must take every gadget for the memory order.
if [ -n "$order" ]; then
  nm "$build/qemu-system-x86_64" >"$wrappers/nm"
  python3 target/i386/tcg/rcg-gen.py --coverage "$order" "$wrappers/nm" \
    "$wrappers"/trace.* || status=1
fi

exit $status
