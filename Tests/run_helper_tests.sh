#!/bin/zsh
set -euo pipefail

project_root=${0:A:h:h}
temporary_directory=$(mktemp -d)
trap 'rm -rf "${temporary_directory}"' EXIT
binary="${temporary_directory}/jailbreaklab-helper"

clang -std=c11 -Wall -Wextra -Werror "${project_root}/Helper/main.c" -o "${binary}"

if "${binary}" --operation invalid --root-mode auto --groups jailbreak-markers --dry-run >/dev/null 2>&1; then
  print -u2 "invalid operation was accepted"
  exit 1
fi

if "${binary}" --operation probe --root-mode auto --groups arbitrary-group --dry-run >/dev/null 2>&1; then
  print -u2 "invalid group was accepted"
  exit 1
fi

probe_output=$("${binary}" --operation probe --root-mode rootful --groups remote-shell --dry-run)
print -r -- "${probe_output}" | grep -q '"path":"/bin/bash"'
print -r -- "${probe_output}" | grep -Eq '"status":"(already_present|absent|failed)"'

apply_output=$("${binary}" --operation apply --root-mode rootful --groups remote-shell --dry-run)
print -r -- "${apply_output}" | grep -q '"status":"probe_only"'

if "${binary}" --operation apply --root-mode rootful --groups jailbreak-markers --live >/dev/null 2>&1; then
  print -u2 "unauthorized live operation was accepted"
  exit 1
fi

print "helper tests passed"
