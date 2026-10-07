#!/bin/sh
# ci/expect-fail.sh — the negative-fixture harness.
#
# A control proves itself only by going RED on a planted defect. Every gating CI job runs its
# own tool against a fixture under ci/fixtures/negative/ BEFORE the real scan, through this
# wrapper, on EVERY pipeline. Two assertions, both required:
#   1. the command exits NON-ZERO  — a control that passes a planted defect is dormant;
#   2. its output names the EXPECTED finding — a command that fails for another reason (tool
#      not installed, bad flag, missing file) is NOT a catch. This is the PSScriptAnalyzer
#      fail-open seen from the other side: there a dead tool looked green, here a dead
#      tool must not look like a working one.
#
#   usage: sh ci/expect-fail.sh '<marker: grep basic regex>' <command> [args...]
#
# POSIX sh only (busybox ash in the alpine images, dash in the debian ones); no bashisms.
set -u

marker="${1:?usage: expect-fail.sh <marker> <command> [args...]}"
shift

out="$("$@" 2>&1)"
rc=$?
printf '%s\n' "$out" | tail -n 15

if [ "$rc" -eq 0 ]; then
  echo "SELFTEST FAILED: '$*' PASSED a planted defect - the control is dormant" >&2
  exit 1
fi
if ! printf '%s\n' "$out" | grep -q -e "$marker"; then
  echo "SELFTEST FAILED: '$*' exited $rc but never reported '$marker' - it failed for another reason (tool missing?)" >&2
  exit 1
fi
echo "SELFTEST OK: planted defect caught (exit $rc, reported '$marker')"
