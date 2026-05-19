#!/usr/bin/env bash
# scrub-commit-history — verify commit hygiene across history
#
# Walks commit history and checks each commit for unresolved work-item
# markers in messages (TODO, FIXME, WIP, fixup!, squash!).
#
# Subsequent commits in the scrubber sequence add:
# - Full nix flake check verification with EXPECT-FAIL support
# - --everything mode for all branches
# - Gitignore monotonicity checking
# - Quick pre-check optimization with --parallel batching
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scrub-commit-history [options] [REVSET]...

Sequential ordering (default: --reverse):
  --forward      first to last (CI: verify whole history)
  --reverse      last to first (development: find recent breakage)
  --bisect       midpoint first (rewriting: find breakage fast)

Options:
  -r REVSET           jj revset to scrub (repeatable, same as positional)
  -h, --help          show this help

Range defaults: all commits reachable from @
EOF
  exit 1
}

order=reverse
revsets=()

while [ $# -gt 0 ]; do
  case "$1" in
  --forward) order=forward ;;
  --reverse) order=reverse ;;
  --bisect) order=bisect ;;
  -r)
    shift
    revsets+=("$1")
    ;;
  -h | --help) usage ;;
  *) revsets+=("$1") ;;
  esac
  shift
done

# Resolve revsets to git commit IDs via jj
if [ ${#revsets[@]} -gt 0 ]; then
  jj_args=(log --ignore-working-copy --no-graph -T 'commit_id ++ "\n"')
  for rs in "${revsets[@]}"; do
    jj_args+=(-r "$rs")
  done
  mapfile -t linear < <(jj "${jj_args[@]}" 2>/dev/null | grep -vE '^$|^0{40}$')
else
  # Default: all commits reachable from working copy
  mapfile -t linear < <(jj log --ignore-working-copy --no-graph -r '::@' -T 'commit_id ++ "\n"' 2>/dev/null | grep -vE '^$|^0{40}$')
fi

total=${#linear[@]}
if [ "$total" -eq 0 ]; then
  echo "No commits in range."
  exit 0
fi

# Build index ordering for traversal
# The linear array is in topo order; we reorder indices for the chosen strategy
case "$order" in
forward)
  ordered=()
  for ((i = 0; i < total; i++)); do ordered+=("$i"); done
  ;;
reverse)
  ordered=()
  for ((i = total - 1; i >= 0; i--)); do ordered+=("$i"); done
  ;;
bisect)
  # BFS on midpoints — finds failures in O(log n) for sparse breakage
  ordered=()
  queue=("0 $((total - 1))")
  while [ ${#queue[@]} -gt 0 ]; do
    pair=${queue[0]}
    queue=("${queue[@]:1}")
    lo=${pair%% *}
    hi=${pair##* }
    if [ "$lo" -gt "$hi" ]; then continue; fi
    mid=$(((lo + hi) / 2))
    ordered+=("$mid")
    if [ "$lo" -lt "$mid" ]; then queue+=("$lo $((mid - 1))"); fi
    if [ "$mid" -lt "$hi" ]; then queue+=("$((mid + 1)) $hi"); fi
  done
  ;;
esac

# Format a commit for display, preferring jj's change ID
fmt_commit() {
  jj log --ignore-working-copy --no-graph -r "$1" \
    -T 'change_id.shortest() ++ " " ++ commit_id.shortest() ++ " " ++ description.first_line()' \
    2>/dev/null || git log -1 --format='%h %s' "$1"
}

# Check each commit message for unresolved work-item markers
msg_failed=()
echo "Checking commit messages..."
for idx in "${ordered[@]}"; do
  hash=${linear[$idx]}
  if git log -1 --format='%B' "$hash" | grep -qE '^\s*(TODO|FIXME|WIP)\b|\bfixup!\b|\bsquash!\b'; then
    echo "  ✗ $(fmt_commit "$hash")"
    msg_failed+=("$hash")
  fi
done
if [ "${#msg_failed[@]}" -gt 0 ]; then
  echo "${#msg_failed[@]} commit(s) have unresolved work items"
else
  echo "  all clean"
fi

# Summary
if [ "${#msg_failed[@]}" -eq 0 ]; then
  echo "All $total commits passed."
else
  echo
  echo "${#msg_failed[@]} failure(s):"
  for h in "${msg_failed[@]}"; do
    echo "  message: $(fmt_commit "$h")"
  done
  exit 1
fi
