#!/usr/bin/env bash
#
# mayhem/test.sh — RUN FRR's own unit tests (built by mayhem/build.sh in mayhem/build-test, normal flags).
# Behavioral oracle: the bgpd capability and MP-attribute tests print per-case results that pytest checks
# line by line (parsed/not parsed, negotiated AFI/SAFI), and test_stream diffs against a golden .refout; a
# program that exits 0 without producing the expected output fails. Plus one direct assertion on the
# capability program's own failure count.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
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
    "$tool" "$tests" "$passed" "$failed" "$skipped" "$pending" "$other"
  [ "$failed" -eq 0 ]
}

BT="$SRC/mayhem/build-test/tests"
T="$SRC/tests"
for p in bgpd/test_capability bgpd/test_mp_attr lib/test_stream; do
  [ -x "$BT/$p" ] || { echo "missing test program $BT/$p (mayhem/build.sh should have built it)" >&2; emit_ctrf "frr-unit" 0 1; exit 1; }
done

cd "$BT"
out=$(PYTHONPATH="$T/helpers/python" python3 -m pytest -p no:cacheprovider -q \
  "$T/bgpd/test_capability.py" "$T/bgpd/test_mp_attr.py" "$T/lib/test_stream.py" 2>&1)
echo "$out" | tail -15
passed=$(echo "$out" | grep -Eo '[0-9]+ passed' | tail -1 | cut -d' ' -f1)
failed=$(echo "$out" | grep -Eo '[0-9]+ failed' | tail -1 | cut -d' ' -f1)
passed=${passed:-0}; failed=${failed:-0}
[ "$passed" -gt 0 ] || failed=$((failed + 1))

# The capability program ends with "failures: <N>" over all its cases (MP, ORF, GR, AS4, role, dynamic
# capability messages); require it to have run them and found none.
cap=$(cd bgpd && ./test_capability 2>/dev/null)
if [ "$(echo "$cap" | grep -c '^OK')" -ge 40 ] && [ "$(echo "$cap" | tail -1)" = "failures: 0" ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1)); echo "test_capability: unexpected result: $(echo "$cap" | tail -1)" >&2
fi

emit_ctrf "frr-unit" "$passed" "$failed"
