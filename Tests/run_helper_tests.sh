#!/bin/zsh
set -euo pipefail

project_root=${0:A:h:h}
temporary_directory=$(mktemp -d)
trap 'rm -rf "${temporary_directory}"' EXIT
binary="${temporary_directory}/jailbreaklab-helper"
filesystem_tests="${temporary_directory}/helper-filesystem-tests"

clang -std=c11 -Wall -Wextra -Werror "${project_root}/Helper/main.c" -o "${binary}"
clang -std=c11 -Wall -Wextra -Werror "${project_root}/Tests/helper_filesystem_tests.c" -o "${filesystem_tests}"
"${filesystem_tests}"

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

all_groups="jailbreak-markers,package-managers,injection-frameworks,bypass-tools,remote-shell"
apply_output=$("${binary}" --operation apply --root-mode rootful --groups "${all_groups}" --dry-run)
[[ $(print -r -- "${apply_output}" | grep -c '^{') -eq 73 ]]
if print -r -- "${apply_output}" | grep -q '"status":"probe_only"'; then
  print -u2 "a catalog path was not configured for creation"
  exit 1
fi
print -r -- "${apply_output}" | grep -q '"path":"/usr/sbin/frida-server"'

if "${binary}" --operation apply --root-mode rootful --groups jailbreak-markers --live >/dev/null 2>&1; then
  print -u2 "unauthorized live operation was accepted"
  exit 1
fi

print "helper tests passed"
