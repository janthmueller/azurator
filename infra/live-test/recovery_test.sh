#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
TEST_ROOT="$(mktemp -d -t azurator-live-test-recovery-test.XXXXXXXX)"
readonly TEST_ROOT
readonly TEST_BIN="$TEST_ROOT/bin"
readonly DRIVER="$SCRIPT_DIR/recovery_test_driver.sh"
readonly RECOVERY_SCRIPT="$SCRIPT_DIR/recovery.sh"
readonly SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"
readonly OPERATION_ID="57c7fa92-2899-4c2f-9d30-2fc915be5f6c"
readonly STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.Storage/storageAccounts/stazuratortest"
readonly DISABLED_STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.Storage/storageAccounts/stazuratordisabled"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}

fail() {
  printf 'Recovery harness test failed: %s\n' "$1" >&2
  exit 1
}

new_case() {
  local name="$1"
  local root="$TEST_ROOT/$name"
  mkdir -p "$root/tmp"
  printf '%s\n' "$root"
}

run_recovery() {
  local mode="$1"
  local root="$2"
  FAKE_MODE="$mode" \
    FAKE_ROOT="$root" \
    FAKE_LOG="$root/calls.log" \
    TMPDIR="$root/tmp" \
    AZURATOR_LIVE_TEST_BASH="${BASH}" \
    AZURATOR_LIVE_TEST_AZ="$TEST_BIN/az" \
    AZURATOR_LIVE_TEST_JQ="$(command -v jq)" \
    AZURATOR_LIVE_TEST_AZURATOR="$TEST_BIN/azurator" \
    AZURATOR_LIVE_TEST_LIFECYCLE="$TEST_BIN/lifecycle" \
    "$BASH" "$RECOVERY_SCRIPT"
}

assert_no_secret_output() {
  local root="$1"
  if grep -E 'storage-secret|recovery-fingerprint|key_state_salt' \
    "$root/output.log" "$root/calls.log"; then
    fail "secret or private recovery material reached output or the command log"
  fi
}

assert_empty_tmp() {
  local root="$1"
  if find "$root/tmp" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    fail "the workflow retained its local watcher workspace"
  fi
}

create_driver_wrapper() {
  local program="$1"
  {
    printf '#!%s\n' "$BASH"
    printf 'export FAKE_PROGRAM=%q\n' "$program"
    printf 'exec %q %q "$@"\n' "$BASH" "$DRIVER"
  } >"$TEST_BIN/$program"
  chmod 755 "$TEST_BIN/$program"
}

trap cleanup EXIT

mkdir -p "$TEST_BIN"
create_driver_wrapper az
create_driver_wrapper azurator
create_driver_wrapper lifecycle

success_root="$(new_case success)"
if ! run_recovery success "$success_root" >"$success_root/output.log" 2>&1; then
  sed -n '1,240p' "$success_root/output.log" >&2
  fail "the successful workflow returned an error"
fi
[[ ! -e "$success_root/group-exists" ]] || fail "the successful workflow retained the fixture"
[[ ! -e "$success_root/operation-pending" ]] || fail "the successful resume retained its operation"
assert_empty_tmp "$success_root"
assert_no_secret_output "$success_root"
grep -Fq "azurator auth status --subscription $SUBSCRIPTION_ID" "$success_root/calls.log" \
  || fail "authentication scope was not preflighted"
grep -Fq "azurator operation list --json" "$success_root/calls.log" \
  || fail "the watcher did not use the safe operation catalog"
grep -Fq "azurator operation show $OPERATION_ID --json" "$success_root/calls.log" \
  || fail "the watcher did not validate the exact safe operation projection"
grep -Fq "azurator rotate --resume $OPERATION_ID" "$success_root/calls.log" \
  || fail "the retained operation was not resumed"
grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --select $STORAGE_ACCOUNT_ID#key1" \
  "$success_root/calls.log" \
  || fail "the recovery workflow did not select the tagged rotation Storage Account"
if grep -Fq "$DISABLED_STORAGE_ACCOUNT_ID#" "$success_root/calls.log"; then
  fail "the recovery workflow selected the key-authentication-disabled Storage Account"
fi
grep -Fq "azurator plan" "$success_root/calls.log" \
  || fail "post-resume Azure binding inspection was not exercised"
grep -Fq "App Service settings contain the current Storage key1" "$success_root/output.log" \
  || fail "post-resume App Service binding verification was not reported"
if grep -Eq '(^| )(--yes|-y)( |$)' "$success_root/calls.log"; then
  fail "the recovery workflow bypassed an Azurator confirmation"
fi
grep -Fq "Retained checkpoint after controlled interruption" "$success_root/output.log" \
  || fail "the controlled interruption was not reported"
grep -Fq "Live recovery test completed" "$success_root/output.log" \
  || fail "the completed recovery workflow was not reported"

valid_root="$(new_case preexisting-valid)"
if run_recovery preexisting-valid "$valid_root" >"$valid_root/output.log" 2>&1; then
  fail "a pre-existing retained operation did not block the isolated workflow"
fi
[[ ! -e "$valid_root/group-exists" ]] || fail "the pre-existing operation check happened after deployment"
assert_empty_tmp "$valid_root"
assert_no_secret_output "$valid_root"
if grep -Fq "lifecycle up" "$valid_root/calls.log"; then
  fail "a pre-existing retained operation reached fixture deployment"
fi

invalid_root="$(new_case preexisting-invalid)"
if run_recovery preexisting-invalid "$invalid_root" >"$invalid_root/output.log" 2>&1; then
  fail "an invalid retained operation did not block the isolated workflow"
fi
[[ ! -e "$invalid_root/group-exists" ]] || fail "the invalid operation check happened after deployment"
assert_empty_tmp "$invalid_root"
assert_no_secret_output "$invalid_root"

missed_root="$(new_case checkpoint-missed)"
if run_recovery checkpoint-missed "$missed_root" >"$missed_root/output.log" 2>&1; then
  fail "a missed checkpoint was reported as a successful recovery exercise"
fi
[[ ! -e "$missed_root/group-exists" ]] \
  || fail "a cleanly missed checkpoint retained the disposable fixture"
assert_empty_tmp "$missed_root"
assert_no_secret_output "$missed_root"
grep -Fq "cancelled before mutation or completed before interception" "$missed_root/output.log" \
  || fail "the checkpoint race was not reported without guessing its outcome"
grep -Fq "lifecycle down" "$missed_root/calls.log" \
  || fail "a missed checkpoint with no retained operation skipped safe teardown"

resume_cancel_root="$(new_case resume-cancel)"
if run_recovery resume-cancel "$resume_cancel_root" >"$resume_cancel_root/output.log" 2>&1; then
  fail "a cancelled resume returned a completed recovery exercise"
fi
[[ -e "$resume_cancel_root/group-exists" ]] || fail "a cancelled resume did not retain the fixture"
[[ -e "$resume_cancel_root/operation-pending" ]] || fail "a cancelled resume did not retain recovery state"
assert_empty_tmp "$resume_cancel_root"
assert_no_secret_output "$resume_cancel_root"
grep -Fq "resume did not complete" "$resume_cancel_root/output.log" \
  || fail "the cancelled resume did not explain its retained state"
if grep -Fq "lifecycle down" "$resume_cancel_root/calls.log"; then
  fail "a cancelled resume deleted the fixture needed for recovery"
fi

printf 'Guided live-test recovery harness checks passed.\n'
