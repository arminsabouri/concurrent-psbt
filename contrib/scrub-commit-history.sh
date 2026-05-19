#!/usr/bin/env bash
# scrub-commit-history — verify commit hygiene across history
#
# Walks commit history and checks each commit for unresolved work-item
# markers in messages and optionally runs nix flake check on each.
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: ${0##/*} [options] [-r REVSET]... [REVSET]...

Sequential ordering (default: --reverse):
  --forward      first to last (CI: verify whole history)
  --reverse      last to first (development: find recent breakage)
  --bisect       midpoint first (rewriting: find breakage fast)

Options:
  -r REVSET           jj revset to scrub (repeatable, same as positional)
  --everything        scrub all branches, not just HEAD
  --check NAME        flake check for fast pre-check (default: quick)
  --parallel          batch builds for parallel execution
  -L                  print build logs
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
check_name=quick
mode=sequential
nix_build_args=()
stderr_redirect=/dev/null

while [ $# -gt 0 ]; do
  case "$1" in
  --forward) order=forward ;;
  --reverse) order=reverse ;;
  --bisect) order=bisect ;;
  --everything) everything=true ;;
  --parallel) mode=parallel ;;
  --check)
    shift
    check_name="$1"
    ;;
  -L)
    nix_build_args+=("-L")
    stderr_redirect="/dev/stderr"
    ;;
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

# Select build command: use nom (nix-output-monitor) when on a tty, else nix build
if [ -t 1 ] && command -v nom >/dev/null 2>&1; then
  build_cmd=(nom build)
else
  build_cmd=(nix build)
fi

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
    -T 'change_id.shortest(7) ++ " " ++ commit_id.shortest(7) ++ " " ++ description.first_line()' \
    2>/dev/null || git log -1 --format='%h %s' "$1"
}

# Format a rerun hint for a failed commit using jj change ID
fmt_rerun_hint() {
  local change_id
  change_id=$(jj log --ignore-working-copy --no-graph -r "$1" \
    -T 'change_id.shortest(7)' 2>/dev/null || true)
  if [ -n "$change_id" ]; then
    echo "    rerun: nix run .#scrub-commit-history -- -r $change_id"
  fi
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

# Phase 1c: quick pre-check (fast feedback optimization)
if [ "$run_flake_checks" = true ]; then
  if [ "$mode" = parallel ]; then
    quick_targets=()
    for idx in "${ordered[@]}"; do
      hash=${linear[$idx]}
      git log -1 --format='%B' "$hash" | grep -qP '\[EXPECT-FAIL: [^\]]+\]' && continue
      git cat-file -e "$hash:flake.nix" 2>/dev/null || continue
      flakeref="git+file://$repo_root?rev=$hash"
      target="$flakeref#checks.$system.$check_name"
      if nix eval --no-update-lock-file "$target" --apply 'x: true' >/dev/null 2>/dev/null; then
        quick_targets+=("$target")
      fi
    done
    if [ ${#quick_targets[@]} -gt 0 ]; then
      echo "Quick pre-check: building ${#quick_targets[@]} $check_name targets in parallel..."
      if "${build_cmd[@]}" --no-update-lock-file "${nix_build_args[@]}" "${quick_targets[@]}" --no-link; then
        echo "  ✓ quick pre-check passed"
      else
        echo "  ✗ quick pre-check had failures, checking sequentially..."
        mode=sequential
      fi
    fi
  fi
  if [ "$mode" = sequential ]; then
    echo "Quick pre-check: running $check_name checks ($order)..."
    for idx in "${ordered[@]}"; do
      hash=${linear[$idx]}
      git log -1 --format='%B' "$hash" | grep -qP '\[EXPECT-FAIL: [^\]]+\]' && continue
      git cat-file -e "$hash:flake.nix" 2>/dev/null || continue
      flakeref="git+file://$repo_root?rev=$hash"
      target="$flakeref#checks.$system.$check_name"
      if nix eval --no-update-lock-file "$target" --apply 'x: true' >/dev/null 2>/dev/null; then
        if ! nix build --no-update-lock-file "${nix_build_args[@]}" "$target" --no-link 2>"$stderr_redirect"; then
          echo "  ✗ $(fmt_commit "$hash") ($check_name failed)"
        fi
      fi
    done
  fi
fi

# Phase 2: full flake checks (skipped with --no-flake-checks)
build_failed=()
if [ "$run_flake_checks" = true ]; then
  if [ "$mode" = parallel ]; then
    echo "Full flake check: collecting targets for parallel build..."
    flake_targets=()
    expect_fail_indices=()
    skip_indices=()
    no_checks_indices=()
    for idx in "${ordered[@]}"; do
      hash=${linear[$idx]}
      if ! git cat-file -e "$hash:flake.nix" 2>/dev/null; then
        skip_indices+=("$idx")
        continue
      fi
      if git log -1 --format='%B' "$hash" | grep -qP '\[EXPECT-FAIL: [^\]]+\]'; then
        expect_fail_indices+=("$idx")
        continue
      fi
      flakeref="git+file://$repo_root?rev=$hash"
      n_before=${#flake_targets[@]}
      while IFS= read -r attr; do
        flake_targets+=("$flakeref#checks.$system.$attr")
      done < <(nix eval --no-update-lock-file "$flakeref#checks.$system" --apply 'cs: builtins.concatStringsSep "\n" (builtins.attrNames cs)' --raw 2>/dev/null || true)
      if [ ${#flake_targets[@]} -eq "$n_before" ]; then
        no_checks_indices+=("$idx")
      fi
    done
    for idx in "${skip_indices[@]}"; do
      echo "  - $(fmt_commit "${linear[$idx]}") (no flake.nix)"
    done
    if [ ${#flake_targets[@]} -gt 0 ]; then
      n_commits=$((${#ordered[@]} - ${#skip_indices[@]} - ${#expect_fail_indices[@]} - ${#no_checks_indices[@]}))
      echo "Full flake check: building ${#flake_targets[@]} targets across $n_commits commits..."
      if "${build_cmd[@]}" --no-update-lock-file "${nix_build_args[@]}" "${flake_targets[@]}" --no-link; then
        echo "  ✓ all flake checks passed"
      else
        echo "  ✗ parallel flake check had failures, falling back to sequential..."
        mode=sequential
      fi
    fi
    # EXPECT-FAIL always checked individually
    for idx in "${expect_fail_indices[@]}"; do
      hash=${linear[$idx]}
      flakeref="git+file://$repo_root?rev=$hash"
      expect_fail=$(git log -1 --format='%B' "$hash" | grep -oP '(?<=\[EXPECT-FAIL: )[^\]]+' || true)
      named_target="$flakeref#checks.$system.$expect_fail"
      if nix build --no-update-lock-file "${nix_build_args[@]}" "$named_target" --no-link 2>"$stderr_redirect"; then
        echo "  ✗ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail unexpectedly passed)"
        build_failed+=("$hash")
      else
        echo "  ✓ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail correctly fails)"
      fi
    done
    # Commits with no check attrs — verify flake evaluates
    for idx in "${no_checks_indices[@]}"; do
      hash=${linear[$idx]}
      flakeref="git+file://$repo_root?rev=$hash"
      if nix flake check --no-update-lock-file "${nix_build_args[@]}" "$flakeref" 2>"$stderr_redirect"; then
        echo "  ✓ $(fmt_commit "$hash") (flake check only)"
      else
        echo "  ✗ $(fmt_commit "$hash")"
        build_failed+=("$hash")
      fi
    done
  fi

  if [ "$mode" = sequential ]; then
    echo "Full flake check: verifying $total commits ($order)..."
    for idx in "${ordered[@]}"; do
      hash=${linear[$idx]}
      if ! git cat-file -e "$hash:flake.nix" 2>/dev/null; then
        echo "  - $(fmt_commit "$hash") (no flake.nix)"
        continue
      fi
      flakeref="git+file://$repo_root?rev=$hash"
      expect_fail=$(git log -1 --format='%B' "$hash" | grep -oP '(?<=\[EXPECT-FAIL: )[^\]]+' || true)
      if [ -n "$expect_fail" ]; then
        named_target="$flakeref#checks.$system.$expect_fail"
        if nix build --no-update-lock-file "${nix_build_args[@]}" "$named_target" --no-link 2>"$stderr_redirect"; then
          echo "  ✗ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail unexpectedly passed)"
          build_failed+=("$hash")
        else
          echo "  ✓ $(fmt_commit "$hash") (EXPECT-FAIL: $expect_fail correctly fails)"
        fi
        continue
      fi
      if nix flake check --no-update-lock-file "${nix_build_args[@]}" "$flakeref" 2>"$stderr_redirect"; then
        echo "  ✓ $(fmt_commit "$hash")"
      else
        echo "  ✗ $(fmt_commit "$hash")"
        build_failed+=("$hash")
      fi
    done
  fi
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
    fmt_rerun_hint "$h"
  done
  for h in "${msg_failed[@]}"; do
    echo "  message: $(fmt_commit "$h")"
  done
  for h in "${gitignore_failed[@]}"; do
    echo "  gitignore: $(fmt_commit "$h")"
  done
  exit 1
fi
