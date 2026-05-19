#!/usr/bin/env bash
# scrub-commit-history — verify commit hygiene across history
#
# Walks commit history and checks each commit for unresolved work-item
# markers in messages and optionally runs nix flake check on each.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scrub-commit-history [options] [-r REVSET]... [REVSET]...

Sequential ordering (default: --reverse):
  --forward      first to last (CI: verify whole history)
  --reverse      last to first (development: find recent breakage)
  --bisect       midpoint first (rewriting: find breakage fast)

Options:
  -r REVSET           jj revset to scrub (repeatable, same as positional)
  --everything        scrub all branches, not just HEAD
  --no-flake-checks   skip flake build checks (message-only mode)
  -h, --help          show this help

Range defaults: all commits reachable from @ (or all branches with --everything)
EOF
  exit 1
}

order=reverse
run_flake_checks=true
revsets=()
everything=false

while [ $# -gt 0 ]; do
  case "$1" in
  --forward) order=forward ;;
  --reverse) order=reverse ;;
  --bisect) order=bisect ;;
  --everything) everything=true ;;
  --no-flake-checks) run_flake_checks=false ;;
  -r)
    shift
    revsets+=("$1")
    ;;
  -h | --help) usage ;;
  *) revsets+=("$1") ;;
  esac
  shift
done

repo_root=$(git rev-parse --show-toplevel)
system=$(nix eval --offline --raw --impure --expr builtins.currentSystem)

# Resolve revsets to git commit IDs via jj
if [ ${#revsets[@]} -gt 0 ]; then
  jj_args=(log --ignore-working-copy --no-graph -T 'commit_id ++ "\n"')
  for rs in "${revsets[@]}"; do
    jj_args+=(-r "$rs")
  done
  mapfile -t linear < <(jj "${jj_args[@]}" 2>/dev/null | grep -vE '^$|^0{40}$')
elif [ "$everything" = true ]; then
  mapfile -t linear < <(jj log --ignore-working-copy --no-graph -r 'all() ~ root()' -T 'commit_id ++ "\n"' 2>/dev/null | grep -vE '^$|^0{40}$')
else
  mapfile -t linear < <(jj log --ignore-working-copy --no-graph -r '::@' -T 'commit_id ++ "\n"' 2>/dev/null | grep -vE '^$|^0{40}$')
fi
total=${#linear[@]}
if [ "$total" -eq 0 ]; then
  echo "No commits in range."
  exit 0
fi

# Build index ordering for traversal
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

# Phase 1: check commit messages for unresolved work-item markers
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

# Phase 1b: gitignore monotonicity check
gitignore_failed=()
tip_hash=${linear[$((total - 1))]}
if git cat-file -e "$tip_hash:.gitignore" 2>/dev/null; then
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  git show "$tip_hash:.gitignore" >"$tmpdir/.gitignore"
  git init -q "$tmpdir/repo"
  cp "$tmpdir/.gitignore" "$tmpdir/repo/.gitignore"

  echo "Checking gitignore monotonicity..."
  for idx in "${ordered[@]}"; do
    hash=${linear[$idx]}
    leaked=$(git ls-tree -r --name-only "$hash" 2>/dev/null |
      git -C "$tmpdir/repo" check-ignore --stdin 2>/dev/null || true)
    if [ -n "$leaked" ]; then
      first=$(echo "$leaked" | head -1)
      count=$(echo "$leaked" | wc -l)
      echo "  ✗ $(fmt_commit "$hash") — $count file(s) leaked, e.g. $first"
      gitignore_failed+=("$hash")
    fi
  done
  if [ "${#gitignore_failed[@]}" -eq 0 ]; then
    echo "  all clean"
  else
    echo "${#gitignore_failed[@]} commit(s) have gitignore leaks"
  fi
fi

# Phase 2: nix flake check on each commit (skipped with --no-flake-checks)
build_failed=()
if [ "$run_flake_checks" = true ]; then
  echo "Verifying $total commits ($order)..."
  for idx in "${ordered[@]}"; do
    hash=${linear[$idx]}

    # Skip commits without a flake
    if ! git cat-file -e "$hash:flake.nix" 2>/dev/null; then
      echo "  - $(fmt_commit "$hash") (no flake.nix)"
      continue
    fi

    flakeref="git+file://$repo_root?rev=$hash"

    # EXPECT-FAIL: verify the named check fails
    expect_fail=$(git log -1 --format='%B' "$hash" | grep -oP '(?<=\[EXPECT-FAIL: )[^\]]+' || true)
    if [ -n "$expect_fail" ]; then
      named_target="$flakeref#checks.$system.$expect_fail"
      if nix build --no-update-lock-file "$named_target" --no-link 2>/dev/null; then
        echo "  ✗ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail unexpectedly passed)"
        build_failed+=("$hash")
      else
        echo "  ✓ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail correctly fails)"
      fi
      continue
    fi

    # Full flake check
    if nix flake check --no-update-lock-file "$flakeref" 2>/dev/null; then
      echo "  ✓ $(fmt_commit "$hash")"
    else
      echo "  ✗ $(fmt_commit "$hash")"
      build_failed+=("$hash")
    fi
  done
fi

# Summary
failures=("${msg_failed[@]}" "${gitignore_failed[@]}" "${build_failed[@]}")
if [ "${#failures[@]}" -eq 0 ]; then
  echo "All $total commits passed."
else
  echo
  echo "${#failures[@]} failure(s):"
  for h in "${build_failed[@]}"; do
    echo "  build: $(fmt_commit "$h")"
  done
  for h in "${msg_failed[@]}"; do
    echo "  message: $(fmt_commit "$h")"
  done
  for h in "${gitignore_failed[@]}"; do
    echo "  gitignore: $(fmt_commit "$h")"
  done
  exit 1
fi
