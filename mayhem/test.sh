#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the tests that mayhem/build.sh built: the known-answer self-test (it checks the
# list parsers in src/conf.c and the DNS response parser in src/dns_snoop.c against asserted values)
# and upstream's own CTest `review_fixes` (test/test_review_fixes.c).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/build/tests/selftest"
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER — mayhem/build.sh did not build the self-test" >&2
  emit_ctrf minunit 0 1 0
  exit 1
fi

out="$("$RUNNER" 2>&1)"; rc=$?
printf '%s\n' "$out"

summary="$(printf '%s\n' "$out" | sed -n 's/^SELFTEST passed=\([0-9]*\) failed=\([0-9]*\)$/\1 \2/p' | tail -n1)"
if [ -z "$summary" ]; then
  echo "self-test printed no SELFTEST summary line (exit status $rc)" >&2
  emit_ctrf minunit 0 1 0
  exit 1
fi
read -r passed failed <<<"$summary"
# a successful run executes at least this many assertions
if [ "$passed" -lt 50 ]; then
  failed=$(( failed + 1 ))
fi
[ "$rc" -eq 0 ] || failed=$(( failed + 1 ))

# Upstream's CTest `review_fixes`: prints `FAIL file:line: ...` per failed check and exits non-zero
# when any failed; it prints nothing per passing check, so its check count is the number of EXPECT_*
# call sites in its source (none sits in a loop).
REVIEW="$SRC/build/tests/test_review_fixes"
if [ ! -x "$REVIEW" ]; then
  echo "missing $REVIEW — mayhem/build.sh did not build upstream's review_fixes test" >&2
  emit_ctrf minunit "$passed" $(( failed + 1 )) 0
  exit 1
fi
rout="$("$REVIEW" 2>&1)"; rrc=$?
printf '%s\n' "$rout"
rchecks="$(grep -cE '^[[:space:]]*EXPECT_' "$SRC/test/test_review_fixes.c")"
rfailed="$(printf '%s\n' "$rout" | grep -c '^FAIL ')"
[ "$rrc" -eq 0 ] || rfailed=$(( rfailed + 1 ))
if [ "$rrc" -eq 0 ] && ! printf '%s\n' "$rout" | grep -qx 'review-fix tests passed'; then
  echo "review_fixes exited 0 without its 'review-fix tests passed' line" >&2
  rfailed=$(( rfailed + 1 ))
fi
rpassed=$(( rchecks > rfailed ? rchecks - rfailed : 0 ))
echo "review_fixes: checks=$rchecks failed=$rfailed exit=$rrc"

emit_ctrf minunit $(( passed + rpassed )) $(( failed + rfailed )) 0
