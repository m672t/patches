#!/usr/bin/env bash
# Runs the four required scenarios against the demo target and checks the expected exit codes.
cd "$(dirname "$0")/../.." || exit 1
declare -A EXPECT=( [correct]=0 [incomplete]=10 [regression]=20 [newissue]=10 )
rc=0
for s in correct incomplete regression newissue; do
  python3 -m patchguard validate -c examples/demo/config.json --patched-path "$s" \
      -o "/tmp/patchguard_$s.json" --quiet
  got=$?
  [[ $got -eq ${EXPECT[$s]} ]] && st=OK || { st=MISMATCH; rc=1; }
  printf '%-12s expected=%-3s got=%-3s %s\n' "$s" "${EXPECT[$s]}" "$got" "$st"
done
exit $rc
