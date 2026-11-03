#!/usr/bin/env bash
#
# mayhem/test.sh — RUN FRR's own unit tests (built by mayhem/build.sh in mayhem/build-test, normal flags).
# Behavioral oracle: tests compare program output against golden .refout files (stream, ttable, graph,
# network_address, isis_spf) or print per-case results that pytest checks; a program that exits 0 without
# producing the expected output fails. Plus one direct assertion on the IS-IS TLV vector run.
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
for p in lib/test_stream lib/test_ttable lib/test_graph lib/test_network_address lib/test_prefix2str \
         lib/test_printfrr isisd/test_isis_spf isisd/test_isis_vertex_queue isisd/test_fuzz_isis_tlv; do
  [ -x "$BT/$p" ] || { echo "missing test program $BT/$p (mayhem/build.sh should have built it)" >&2; emit_ctrf "frr-unit" 0 1; exit 1; }
done

cd "$BT"
out=$(PYTHONPATH="$T/helpers/python" python3 -m pytest -p no:cacheprovider -q \
  "$T/lib/test_stream.py" "$T/lib/test_ttable.py" "$T/lib/test_graph.py" "$T/lib/test_network_address.py" \
  "$T/lib/test_prefix2str.py" "$T/lib/test_printfrr.py" "$T/isisd/test_isis_spf.py" \
  "$T/isisd/test_isis_vertex_queue.py" "$T/isisd/test_fuzz_isis_tlv.py" 2>&1)
echo "$out" | tail -15
passed=$(echo "$out" | grep -Eo '[0-9]+ passed' | tail -1 | cut -d' ' -f1)
failed=$(echo "$out" | grep -Eo '[0-9]+ failed' | tail -1 | cut -d' ' -f1)
passed=${passed:-0}; failed=${failed:-0}
[ "$passed" -gt 0 ] || failed=$((failed + 1))

# The TLV vector program reports "<N> of <N> tests passed." / "0 of <N> tests failed." for its embedded
# vectors; require the full set, all passing.
vec=$(./isisd/test_fuzz_isis_tlv 2>/dev/null)
n_ok=$(echo "$vec" | sed -n 's/^\([0-9]\+\) of [0-9]\+ tests passed\.$/\1/p')
n_bad=$(echo "$vec" | sed -n 's/^\([0-9]\+\) of [0-9]\+ tests failed\.$/\1/p')
if [ "${n_ok:-0}" -ge 400 ] && [ "${n_bad:-1}" -eq 0 ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1)); echo "IS-IS TLV vectors: passed=${n_ok:-?} failed=${n_bad:-?}" >&2
fi

emit_ctrf "frr-unit" "$passed" "$failed"
