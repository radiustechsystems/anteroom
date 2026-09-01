#!/bin/sh
# Samples container CPU while a peak run is in progress, and reports the maximum
# each container reached. `make peak` starts this beside k6 and reads it after.
#
# The point: when k6 drops iterations the summary cannot tell whether the gate
# ran out of CPU or k6 did. This can. docker stats measures over a second, so
# a sample takes about that long; the loop is as fast as that allows.
#
#   peak-cpu.sh <logfile>            sample until killed
#   peak-cpu.sh --report <logfile>   print the maximum CPU per container
set -eu

if [ "${1:-}" = "--report" ]; then
  log="${2:?logfile}"
  [ -s "$log" ] || { echo "cpu: no samples in $log"; exit 0; }
  echo "cpu: peak per container over the run (docker stats, % of one core; 200% is two cores)"
  awk -F'\t' '$1 !~ /^#/ { v=$2; sub(/%/, "", v); if (v+0 > max[$1]) max[$1]=v+0; mem[$1]=$3 }
    END { for (n in max) printf "  %-32s %7.1f%%   mem %s\n", n, max[n], mem[n] }' "$log" | sort
  exit 0
fi

log="${1:?logfile}"
: > "$log"
trap 'exit 0' TERM INT   # a normal exit, so the calling shell has no death-by-signal to report
while :; do
  printf '# %s\n' "$(date +%H:%M:%S)" >> "$log"
  docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' \
    $(docker ps -q --filter name=arbench-) >> "$log" 2>/dev/null || sleep 1
done
