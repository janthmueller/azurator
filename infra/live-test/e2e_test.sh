#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
TEST_ROOT="$(mktemp -d -t azurator-live-test-e2e-test.XXXXXXXX)"
readonly TEST_ROOT
readonly TEST_BIN="$TEST_ROOT/bin"
readonly DRIVER="$SCRIPT_DIR/e2e_test_driver.sh"
readonly E2E_SCRIPT="$SCRIPT_DIR/e2e.sh"
readonly SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"
readonly FOUNDRY_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.CognitiveServices/accounts/ai-azurator-test"
readonly STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.Storage/storageAccounts/stazuratortest"
readonly DISABLED_STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.Storage/storageAccounts/stazuratordisabled"
readonly OPENAI_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.CognitiveServices/accounts/aoai-azurator-test"
readonly DISABLED_FOUNDRY_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/rg-azurator-live-test/providers/Microsoft.CognitiveServices/accounts/ai-azurator-disabled"
readonly SCOPE_FILE="$TEST_ROOT/live-test.env"
readonly WRONG_SCOPE_FILE="$TEST_ROOT/wrong-live-test.env"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}

fail() {
  printf 'E2E harness test failed: %s\n' "$1" >&2
  exit 1
}

new_case() {
  local name="$1"
  local root="$TEST_ROOT/$name"
  mkdir -p "$root/tmp"
  printf '%s\n' "$root"
}

run_e2e() {
  local mode="$1"
  local root="$2"
  local scope_file="$SCOPE_FILE"
  shift 2
  if [[ "$mode" == "scope-mismatch" ]]; then
    scope_file="$WRONG_SCOPE_FILE"
  fi
  FAKE_MODE="$mode" \
    FAKE_ROOT="$root" \
    FAKE_LOG="$root/calls.log" \
    TMPDIR="$root/tmp" \
    AZURATOR_LIVE_TEST_BASH="${BASH}" \
    AZURATOR_LIVE_TEST_AZ="$TEST_BIN/az" \
    AZURATOR_LIVE_TEST_AGE_KEYGEN="$(command -v age-keygen)" \
    AZURATOR_LIVE_TEST_JQ="$(command -v jq)" \
    AZURATOR_LIVE_TEST_SOPS="$(command -v sops)" \
    AZURATOR_LIVE_TEST_AZURATOR="$TEST_BIN/azurator" \
    AZURATOR_LIVE_TEST_LIFECYCLE="$TEST_BIN/lifecycle" \
    AZURATOR_LIVE_TEST_SCOPE_FILE="$scope_file" \
    "$BASH" "$E2E_SCRIPT" "$@"
}

assert_no_secret_output() {
  local root="$1"
  if grep -E 'storage-secret|openai-secret|foundry-secret' "$root/output.log" "$root/calls.log"; then
    fail "a fake key value reached output or the command log"
  fi
}

assert_empty_tmp() {
  local root="$1"
  if find "$root/tmp" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    fail "a completed or cancelled workflow retained its private workspace"
  fi
}

assert_retained_sops_workspace() {
  local workspace="$1"
  local encrypted="$workspace/managed.enc.env"
  local identity="$workspace/age-identity.txt"
  [[ "$(stat -c '%a' "$workspace")" == "700" ]] \
    || fail "the retained E2E workspace was not private"
  [[ -f "$encrypted" && ! -L "$encrypted" ]] \
    || fail "the retained workspace lost its managed SOPS file"
  [[ "$(stat -c '%a' "$encrypted")" == "600" ]] \
    || fail "the retained managed SOPS file was not private"
  [[ -f "$identity" && ! -L "$identity" ]] \
    || fail "the retained workspace lost its disposable age identity"
  [[ "$(stat -c '%a' "$identity")" == "600" ]] \
    || fail "the retained disposable age identity was not private"
  [[ ! -e "$workspace/export.env" ]] \
    || fail "the retained workspace still contained the plaintext export"
  if grep -E 'storage-secret|openai-secret' "$encrypted"; then
    fail "a fake key value was present in the retained SOPS ciphertext"
  fi
  SOPS_AGE_KEY_FILE="$identity" sops decrypt \
    --input-type dotenv \
    --output-type json \
    "$encrypted" \
      | jq -e '
        .AZURATOR_STORAGE_STAZURATORTEST_KEY1 == .AZURATOR_STORAGE_LOCAL_ALIAS
        and .AZURATOR_STORAGE_STAZURATORTEST_KEY2 == .AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS
        and .AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1 == .AZURATOR_OPENAI_LOCAL_ALIAS
        and .AZURATOR_UNRELATED == "preserve-me"
        and .AZURATOR_EMPTY == ""
      ' >/dev/null \
    || fail "the retained SOPS file lost its exact grouped-alias contract"
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
printf 'AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=%s\n' "$SUBSCRIPTION_ID" >"$SCOPE_FILE"
printf 'AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=%s\n' \
  "22222222-2222-2222-2222-222222222222" >"$WRONG_SCOPE_FILE"
create_driver_wrapper az
create_driver_wrapper azurator
create_driver_wrapper lifecycle

scope_mismatch_root="$(new_case scope-mismatch)"
if run_e2e scope-mismatch "$scope_mismatch_root" \
  >"$scope_mismatch_root/output.log" 2>&1; then
  fail "a live-test subscription outside the local allowlist returned success"
fi
[[ ! -e "$scope_mismatch_root/group-exists" ]] \
  || fail "a subscription outside the local allowlist reached fixture deployment"
assert_empty_tmp "$scope_mismatch_root"
assert_no_secret_output "$scope_mismatch_root"
grep -Fq "is not allowed by the local live-test subscription allowlist" \
  "$scope_mismatch_root/output.log" \
  || fail "the subscription allowlist mismatch did not fail with a fixed explanation"
if grep -Eq '^(azurator|lifecycle) ' "$scope_mismatch_root/calls.log"; then
  fail "a subscription allowlist mismatch reached Azurator or the fixture lifecycle"
fi

success_root="$(new_case success)"
run_e2e success "$success_root" >"$success_root/output.log" 2>&1
[[ ! -e "$success_root/group-exists" ]] || fail "the successful workflow retained the fixture"
assert_empty_tmp "$success_root"
assert_no_secret_output "$success_root"
grep -Fq "azurator auth status --subscription $SUBSCRIPTION_ID" "$success_root/calls.log" \
  || fail "authentication scope was not preflighted"
grep -Fq "azurator export" "$success_root/calls.log" || fail "export was not exercised"
grep -Fq "azurator export --subscription $SUBSCRIPTION_ID --select $STORAGE_ACCOUNT_ID#key1 --select $STORAGE_ACCOUNT_ID#key2 --select $OPENAI_ACCOUNT_ID#Key1 --sops-out" \
  "$success_root/calls.log" \
  || fail "managed export did not select both Storage slots and Azure OpenAI Key1"
grep -Eq "^azurator match --subscription $SUBSCRIPTION_ID --sops-file .* --key-map-out .*/azurator\.keys\.json$" \
  "$success_root/calls.log" \
  || fail "the reusable key map was not created from the managed SOPS file"
grep -Eq "^azurator export --subscription $SUBSCRIPTION_ID --key-map .*/azurator\.keys\.json --sops-out .*/recreated\.enc\.env$" \
  "$success_root/calls.log" \
  || fail "the reusable key map did not drive a new SOPS export"
[[ "$(grep -Fc -- '--sops-out' "$success_root/calls.log")" -eq 2 ]] \
  || fail "the selected and key-map exports did not each create one SOPS file"
[[ "$(grep -Fc -- ' --out ' "$success_root/calls.log")" -eq 1 ]] \
  || fail "plaintext export was used beyond the temporary skipped-binding snapshot"
grep -Fq "azurator discover --subscription $SUBSCRIPTION_ID --json" "$success_root/calls.log" \
  || fail "structured discovery was not exercised"
grep -Fq "azurator plan --subscription $SUBSCRIPTION_ID --select $FOUNDRY_ACCOUNT_ID#Key1 --skip-azure-bindings --json" \
  "$success_root/calls.log" \
  || fail "the structured skipped-binding plan was not exercised"
grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --select $FOUNDRY_ACCOUNT_ID#Key1 --skip-azure-bindings" \
  "$success_root/calls.log" \
  || fail "the direct skipped-binding rotation was not exercised"
grep -Fq "azurator match --subscription $SUBSCRIPTION_ID --env-file" "$success_root/calls.log" \
  || fail "the pre-rotation snapshot was not checked after skipped-binding rotation"
[[ "$(grep -Fc -- '--env-file' "$success_root/calls.log")" -eq 1 ]] \
  || fail "plaintext dotenv was used beyond the temporary skipped-binding snapshot"
[[ "$(grep -Fc -- 'azurator match --subscription' "$success_root/calls.log")" -eq 4 ]] \
  || fail "the workflow did not run one snapshot match and three SOPS matches"
[[ "$(grep -Fc -- '--sops-file' "$success_root/calls.log")" -eq 5 ]] \
  || fail "the workflow did not run key-map match, structured match, plan, rotation, and final match"
grep -Fq "azurator plan --subscription $SUBSCRIPTION_ID --sops-file" "$success_root/calls.log" \
  || fail "the structured SOPS plan was not exercised"
grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" "$success_root/calls.log" \
  || fail "managed SOPS rotation was not exercised"
[[ "$(grep -Fc -- '--skip-azure-bindings' "$success_root/calls.log")" -eq 3 ]] \
  || fail "the successful workflow did not use the skip flag for exactly plan, rotation, and verification"
grep -Fq "azurator rotate" "$success_root/calls.log" || fail "rotation was not exercised"
grep -Fq "azurator match" "$success_root/calls.log" || fail "final matching was not exercised"
if grep -Eq '(^| )(--yes|-y)( |$)' "$success_root/calls.log"; then
  fail "the guided workflow bypassed an Azurator confirmation"
fi
if grep -Fq "$DISABLED_STORAGE_ACCOUNT_ID#" "$success_root/calls.log"; then
  fail "the guided workflow selected the key-authentication-disabled Storage Account"
fi
if grep -Fq "$DISABLED_FOUNDRY_ACCOUNT_ID#" "$success_root/calls.log"; then
  fail "the guided workflow selected the key-authentication-disabled Foundry account"
fi
grep -Fq "Verified both final Storage slots and Azure OpenAI Key1 across six SOPS assignments" \
  "$success_root/output.log" \
  || fail "the successful workflow did not report its exact verification boundary"
grep -Fq "Verified enabled and disabled key-authentication resources" "$success_root/output.log" \
  || fail "the successful workflow did not verify the provider key-authentication matrix"
grep -Fq "Verified that direct skipped-binding rotation changed only the selected fixture key" \
  "$success_root/output.log" \
  || fail "the successful workflow did not report verified skipped-binding rotation"
grep -Fq "Verified the reusable key map and recreated exactly six encrypted Azure assignments" \
  "$success_root/output.log" \
  || fail "the successful workflow did not report verified key-map recreation"

reuse_root="$(new_case reuse-fixture)"
: >"$reuse_root/group-exists"
run_e2e success "$reuse_root" --reuse-fixture >"$reuse_root/output.log" 2>&1
[[ ! -e "$reuse_root/group-exists" ]] || fail "the reused workflow retained the fixture"
assert_empty_tmp "$reuse_root"
assert_no_secret_output "$reuse_root"
grep -Fq "Reusing the complete existing tagged fixture; deployment was not invoked." \
  "$reuse_root/output.log" \
  || fail "the existing fixture was not explicitly reported as reused"
if grep -Fq "lifecycle up" "$reuse_root/calls.log"; then
  fail "fixture reuse invoked deployment"
fi
grep -Fq "azurator operation list --json" "$reuse_root/calls.log" \
  || fail "fixture reuse did not require an empty local operation catalog"

unsafe_reuse_root="$(new_case unsafe-reuse-group)"
: >"$unsafe_reuse_root/group-exists"
if run_e2e unsafe-reuse-group "$unsafe_reuse_root" --reuse-fixture \
  >"$unsafe_reuse_root/output.log" 2>&1; then
  fail "an incorrectly owned resource group was reused"
fi
[[ -e "$unsafe_reuse_root/group-exists" ]] \
  || fail "unsafe fixture reuse deleted the untrusted resource group"
assert_empty_tmp "$unsafe_reuse_root"
assert_no_secret_output "$unsafe_reuse_root"
grep -Fq "did not satisfy the exact Azurator fixture identity" \
  "$unsafe_reuse_root/output.log" \
  || fail "unsafe fixture reuse did not fail closed on group identity"
if grep -Fq "azurator discover" "$unsafe_reuse_root/calls.log"; then
  fail "unsafe fixture reuse reached product discovery"
fi

operation_reuse_root="$(new_case reuse-operation-present)"
: >"$operation_reuse_root/group-exists"
if run_e2e reuse-operation-present "$operation_reuse_root" --reuse-fixture \
  >"$operation_reuse_root/output.log" 2>&1; then
  fail "fixture reuse with a retained operation returned success"
fi
[[ -e "$operation_reuse_root/group-exists" ]] \
  || fail "blocked fixture reuse deleted the diagnostic resource group"
assert_empty_tmp "$operation_reuse_root"
assert_no_secret_output "$operation_reuse_root"
grep -Fq "recovery operation blocks fixture reuse" \
  "$operation_reuse_root/output.log" \
  || fail "fixture reuse did not fail closed on retained operation state"
if grep -Fq "azurator discover" "$operation_reuse_root/calls.log"; then
  fail "fixture reuse with recovery state reached product discovery"
fi

bad_skip_plan_root="$(new_case bad-skip-plan)"
if run_e2e bad-skip-plan "$bad_skip_plan_root" >"$bad_skip_plan_root/output.log" 2>&1; then
  fail "an invalid skipped-binding plan returned success"
fi
[[ -e "$bad_skip_plan_root/group-exists" ]] \
  || fail "the invalid skipped-binding plan did not retain its diagnostic fixture"
assert_empty_tmp "$bad_skip_plan_root"
assert_no_secret_output "$bad_skip_plan_root"
grep -Fq "did not satisfy the skipped Azure-binding inspection contract" \
  "$bad_skip_plan_root/output.log" \
  || fail "the invalid skipped-binding plan did not fail closed"
if grep -Fq "azurator export" "$bad_skip_plan_root/calls.log"; then
  fail "an invalid skipped-binding plan reached key export"
fi
if grep -Fq "azurator rotate" "$bad_skip_plan_root/calls.log"; then
  fail "an invalid skipped-binding plan reached rotation"
fi

skip_cancel_root="$(new_case skip-rotate-cancel)"
run_e2e skip-rotate-cancel "$skip_cancel_root" >"$skip_cancel_root/output.log" 2>&1
[[ ! -e "$skip_cancel_root/group-exists" ]] \
  || fail "the cancelled skipped-binding rotation retained the fixture"
assert_empty_tmp "$skip_cancel_root"
assert_no_secret_output "$skip_cancel_root"
grep -Fq "Skipped-binding rotation was cancelled; the Foundry host Key1 was unchanged." \
  "$skip_cancel_root/output.log" \
  || fail "skipped-binding rotation cancellation was not proven from the old-key snapshot"
if grep -Fq "storageAccounts/stazuratortest#key1" "$skip_cancel_root/calls.log"; then
  fail "a cancelled skipped-binding rotation continued into managed export"
fi

skip_failure_root="$(new_case skip-rotate-fail)"
if run_e2e skip-rotate-fail "$skip_failure_root" >"$skip_failure_root/output.log" 2>&1; then
  fail "a failed skipped-binding rotation returned success"
fi
[[ -e "$skip_failure_root/group-exists" ]] \
  || fail "the failed skipped-binding rotation did not retain its diagnostic fixture"
assert_empty_tmp "$skip_failure_root"
assert_no_secret_output "$skip_failure_root"
if grep -Fq "storageAccounts/stazuratortest#key1" "$skip_failure_root/calls.log"; then
  fail "a failed skipped-binding rotation continued into managed export"
fi

bad_key_map_root="$(new_case bad-key-map)"
if run_e2e bad-key-map "$bad_key_map_root" >"$bad_key_map_root/output.log" 2>&1; then
  fail "an invalid reusable key map returned success"
fi
[[ -e "$bad_key_map_root/group-exists" ]] \
  || fail "the invalid key map did not retain its diagnostic fixture"
assert_empty_tmp "$bad_key_map_root"
assert_no_secret_output "$bad_key_map_root"
grep -Fq "reusable key map did not preserve the exact matched selectors and slots" \
  "$bad_key_map_root/output.log" \
  || fail "the invalid reusable key map did not fail closed"
if grep -Fq "azurator export --subscription $SUBSCRIPTION_ID --key-map" \
  "$bad_key_map_root/calls.log"; then
  fail "an invalid reusable key map reached map-driven export"
fi
if grep -Fq "azurator plan --subscription $SUBSCRIPTION_ID --sops-file" \
  "$bad_key_map_root/calls.log"; then
  fail "an invalid reusable key map reached managed planning"
fi
if grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" \
  "$bad_key_map_root/calls.log"; then
  fail "an invalid reusable key map reached managed rotation"
fi

bad_key_map_export_root="$(new_case bad-key-map-export)"
if run_e2e bad-key-map-export "$bad_key_map_export_root" \
  >"$bad_key_map_export_root/output.log" 2>&1; then
  fail "an invalid map-driven SOPS export returned success"
fi
[[ -e "$bad_key_map_export_root/group-exists" ]] \
  || fail "the invalid map-driven export did not retain its diagnostic fixture"
assert_empty_tmp "$bad_key_map_export_root"
assert_no_secret_output "$bad_key_map_export_root"
grep -Fq "key-map SOPS export did not preserve its exact alias-only contract" \
  "$bad_key_map_export_root/output.log" \
  || fail "the invalid map-driven SOPS export did not fail closed"
grep -Fq "azurator export --subscription $SUBSCRIPTION_ID --key-map" \
  "$bad_key_map_export_root/calls.log" \
  || fail "the invalid map-driven SOPS export did not reach its verification boundary"
if grep -Fq "azurator plan --subscription $SUBSCRIPTION_ID --sops-file" \
  "$bad_key_map_export_root/calls.log"; then
  fail "an invalid map-driven SOPS export reached managed planning"
fi
if grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" \
  "$bad_key_map_export_root/calls.log"; then
  fail "an invalid map-driven SOPS export reached managed rotation"
fi

bad_sops_match_root="$(new_case bad-sops-match)"
if run_e2e bad-sops-match "$bad_sops_match_root" >"$bad_sops_match_root/output.log" 2>&1; then
  fail "an invalid SOPS match report returned success"
fi
[[ -e "$bad_sops_match_root/group-exists" ]] \
  || fail "the invalid SOPS match report did not retain its diagnostic fixture"
assert_empty_tmp "$bad_sops_match_root"
assert_no_secret_output "$bad_sops_match_root"
grep -Fq "SOPS matching did not confirm the exact aliases" "$bad_sops_match_root/output.log" \
  || fail "the invalid SOPS match report did not fail closed"
if grep -Fq "azurator plan --subscription $SUBSCRIPTION_ID --sops-file" "$bad_sops_match_root/calls.log"; then
  fail "an invalid SOPS match report reached managed planning"
fi

bad_sops_plan_root="$(new_case bad-sops-plan)"
if run_e2e bad-sops-plan "$bad_sops_plan_root" >"$bad_sops_plan_root/output.log" 2>&1; then
  fail "an invalid SOPS plan returned success"
fi
[[ -e "$bad_sops_plan_root/group-exists" ]] \
  || fail "the invalid SOPS plan did not retain its diagnostic fixture"
assert_empty_tmp "$bad_sops_plan_root"
assert_no_secret_output "$bad_sops_plan_root"
grep -Fq "did not satisfy the exact mixed one-slot and two-slot bridge contract" \
  "$bad_sops_plan_root/output.log" \
  || fail "the invalid SOPS plan did not fail closed"
if grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" \
  "$bad_sops_plan_root/calls.log"; then
  fail "an invalid SOPS plan reached managed rotation"
fi

missing_restore_root="$(new_case missing-slot-restore)"
if run_e2e missing-slot-restore "$missing_restore_root" >"$missing_restore_root/output.log" 2>&1; then
  fail "a two-slot plan without final bridge-slot restoration returned success"
fi
[[ -e "$missing_restore_root/group-exists" ]] \
  || fail "the missing-restoration plan did not retain its diagnostic fixture"
assert_empty_tmp "$missing_restore_root"
assert_no_secret_output "$missing_restore_root"
grep -Fq "did not satisfy the exact mixed one-slot and two-slot bridge contract" \
  "$missing_restore_root/output.log" \
  || fail "the missing-restoration plan did not fail closed"
if grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" \
  "$missing_restore_root/calls.log"; then
  fail "a two-slot plan without final bridge-slot restoration reached rotation"
fi

misordered_restore_root="$(new_case misordered-slot-restore)"
if run_e2e misordered-slot-restore "$misordered_restore_root" \
  >"$misordered_restore_root/output.log" 2>&1; then
  fail "a two-slot plan with misordered bridge-slot restoration returned success"
fi
[[ -e "$misordered_restore_root/group-exists" ]] \
  || fail "the misordered-restoration plan did not retain its diagnostic fixture"
assert_empty_tmp "$misordered_restore_root"
assert_no_secret_output "$misordered_restore_root"
grep -Fq "did not satisfy the exact mixed one-slot and two-slot bridge contract" \
  "$misordered_restore_root/output.log" \
  || fail "the misordered-restoration plan did not fail closed"
if grep -Fq "azurator rotate --subscription $SUBSCRIPTION_ID --sops-file" \
  "$misordered_restore_root/calls.log"; then
  fail "a two-slot plan with misordered bridge-slot restoration reached rotation"
fi

same_inode_root="$(new_case same-inode-update)"
run_e2e same-inode-update "$same_inode_root" >"$same_inode_root/output.log" 2>&1
[[ ! -e "$same_inode_root/group-exists" ]] \
  || fail "the same-inode update workflow retained the fixture"
assert_empty_tmp "$same_inode_root"
assert_no_secret_output "$same_inode_root"
grep -Fq "azurator match" "$same_inode_root/calls.log" \
  || fail "a changed file with a reused inode was mistaken for rotation cancellation"
grep -Fq "Live end-to-end test completed" "$same_inode_root/output.log" \
  || fail "the same-inode update did not complete the E2E verification path"

cancel_root="$(new_case cancel)"
run_e2e rotate-cancel "$cancel_root" >"$cancel_root/output.log" 2>&1
[[ ! -e "$cancel_root/group-exists" ]] || fail "the cancelled workflow retained the fixture"
assert_empty_tmp "$cancel_root"
assert_no_secret_output "$cancel_root"
grep -Fq "Rotation was cancelled; the managed SOPS file was unchanged." "$cancel_root/output.log" \
  || fail "rotation cancellation was not distinguished from success"

failure_root="$(new_case failure)"
if run_e2e rotate-fail "$failure_root" >"$failure_root/output.log" 2>&1; then
  fail "a failed rotation returned success"
fi
[[ -e "$failure_root/group-exists" ]] || fail "the failed workflow did not retain the fixture"
assert_no_secret_output "$failure_root"
mapfile -t retained_workspaces < <(
  find "$failure_root/tmp" -mindepth 1 -maxdepth 1 -type d -name 'azurator-live-test-e2e.*' -print
)
[[ "${#retained_workspaces[@]}" -eq 1 ]] || fail "the failed rotation did not retain exactly one workspace"
assert_retained_sops_workspace "${retained_workspaces[0]}"
grep -Fq "Preserved private E2E workspace" "$failure_root/output.log" \
  || fail "the failed workflow did not explain retained recovery input"
if grep -Fq "lifecycle down" "$failure_root/calls.log"; then
  fail "the failed workflow deleted its diagnostic fixture"
fi

corrupt_root="$(new_case corrupt-unrelated)"
if run_e2e corrupt-unrelated "$corrupt_root" >"$corrupt_root/output.log" 2>&1; then
  fail "a rotation that changed an unrelated SOPS value returned success"
fi
[[ -e "$corrupt_root/group-exists" ]] \
  || fail "the corrupted SOPS rotation did not retain its diagnostic fixture"
assert_no_secret_output "$corrupt_root"
mapfile -t corrupt_workspaces < <(
  find "$corrupt_root/tmp" -mindepth 1 -maxdepth 1 -type d -name 'azurator-live-test-e2e.*' -print
)
[[ "${#corrupt_workspaces[@]}" -eq 1 ]] \
  || fail "the corrupted SOPS rotation did not retain exactly one workspace"
grep -Fq "did not preserve its exact alias and unrelated-value contract" \
  "$corrupt_root/output.log" \
  || fail "an unrelated SOPS value change did not fail final verification"
if grep -Fq "lifecycle down" "$corrupt_root/calls.log"; then
  fail "the corrupted SOPS rotation deleted its diagnostic fixture"
fi

inventory_root="$(new_case bad-inventory)"
if run_e2e bad-inventory "$inventory_root" >"$inventory_root/output.log" 2>&1; then
  fail "an incomplete fixture inventory returned success"
fi
[[ -e "$inventory_root/group-exists" ]] || fail "the invalid fixture was unexpectedly deleted"
assert_no_secret_output "$inventory_root"
grep -Fq "exactly one tagged Azure OpenAI account" "$inventory_root/output.log" \
  || fail "the fixture inventory did not fail closed with a fixed message"
if grep -Fq "azurator export" "$inventory_root/calls.log"; then
  fail "an incomplete fixture reached key export"
fi

disabled_storage_root="$(new_case missing-disabled-storage)"
if run_e2e missing-disabled-storage "$disabled_storage_root" \
  >"$disabled_storage_root/output.log" 2>&1; then
  fail "a fixture without the disabled Storage variant returned success"
fi
[[ -e "$disabled_storage_root/group-exists" ]] \
  || fail "the incomplete Storage matrix did not retain its diagnostic fixture"
assert_empty_tmp "$disabled_storage_root"
assert_no_secret_output "$disabled_storage_root"
grep -Fq "exactly one tagged key-authentication-disabled Storage Account" \
  "$disabled_storage_root/output.log" \
  || fail "the missing disabled Storage variant did not fail closed"
if grep -Fq "azurator discover" "$disabled_storage_root/calls.log"; then
  fail "an incomplete Storage fixture reached product discovery"
fi

disabled_foundry_root="$(new_case missing-disabled-foundry)"
if run_e2e missing-disabled-foundry "$disabled_foundry_root" \
  >"$disabled_foundry_root/output.log" 2>&1; then
  fail "a fixture without the disabled Foundry variant returned success"
fi
[[ -e "$disabled_foundry_root/group-exists" ]] \
  || fail "the incomplete Foundry matrix did not retain its diagnostic fixture"
assert_empty_tmp "$disabled_foundry_root"
assert_no_secret_output "$disabled_foundry_root"
grep -Fq "exactly one tagged key-authentication-disabled Foundry account" \
  "$disabled_foundry_root/output.log" \
  || fail "the missing disabled Foundry variant did not fail closed"
if grep -Fq "azurator discover" "$disabled_foundry_root/calls.log"; then
  fail "an incomplete Foundry fixture reached product discovery"
fi

app_service_root="$(new_case missing-app-service)"
if run_e2e missing-app-service "$app_service_root" \
  >"$app_service_root/output.log" 2>&1; then
  fail "a fixture without the App Service binding app returned success"
fi
[[ -e "$app_service_root/group-exists" ]] \
  || fail "the incomplete App Service fixture did not retain its diagnostic fixture"
assert_empty_tmp "$app_service_root"
assert_no_secret_output "$app_service_root"
grep -Fq "exactly one tagged App Service settings app" \
  "$app_service_root/output.log" \
  || fail "the missing App Service fixture variant did not fail closed"
if grep -Fq "azurator discover" "$app_service_root/calls.log"; then
  fail "an incomplete App Service fixture reached product discovery"
fi

storage_discovery_root="$(new_case bad-storage-discovery)"
if run_e2e bad-storage-discovery "$storage_discovery_root" \
  >"$storage_discovery_root/output.log" 2>&1; then
  fail "an incorrect Storage key-authentication discovery state returned success"
fi
[[ -e "$storage_discovery_root/group-exists" ]] \
  || fail "the incorrect Storage discovery state did not retain its diagnostic fixture"
assert_empty_tmp "$storage_discovery_root"
assert_no_secret_output "$storage_discovery_root"
grep -Fq "did not confirm the complete enabled/disabled fixture key-authentication matrix" \
  "$storage_discovery_root/output.log" \
  || fail "the incorrect Storage discovery state did not fail closed"
if grep -Fq "azurator export" "$storage_discovery_root/calls.log"; then
  fail "an incorrect Storage discovery state reached key export"
fi

foundry_discovery_root="$(new_case bad-foundry-discovery)"
if run_e2e bad-foundry-discovery "$foundry_discovery_root" \
  >"$foundry_discovery_root/output.log" 2>&1; then
  fail "an incorrect Foundry key-authentication discovery state returned success"
fi
[[ -e "$foundry_discovery_root/group-exists" ]] \
  || fail "the incorrect Foundry discovery state did not retain its diagnostic fixture"
assert_empty_tmp "$foundry_discovery_root"
assert_no_secret_output "$foundry_discovery_root"
grep -Fq "did not confirm the complete enabled/disabled fixture key-authentication matrix" \
  "$foundry_discovery_root/output.log" \
  || fail "the incorrect Foundry discovery state did not fail closed"
if grep -Fq "azurator export" "$foundry_discovery_root/calls.log"; then
  fail "an incorrect Foundry discovery state reached key export"
fi

printf 'Guided live-test E2E harness checks passed.\n'
