#!/usr/bin/env bash
# atlas-safe op (RM2071) — instantané charge / mémoire / process. Read-only, SANS sudo
# (uptime/free/ps/vmstat sont tous non privilégiés). Bundle figé (0 arg).
set -uo pipefail
sec() { printf '\n=== %s ===\n' "$1"; }

sec "uptime / charge"
uptime

sec "mémoire / swap"
free -h

sec "top 10 process par RAM"
ps -eo pid,user,pcpu,pmem,rss,comm --sort=-pmem 2>/dev/null | head -11

sec "top 10 process par CPU"
ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -11

sec "vmstat (2 échantillons)"
vmstat 1 2 2>/dev/null | tail -3 || echo "(vmstat absent)"
