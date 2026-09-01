#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly RESOURCE_GROUP_NAME="rg-azurator-live-test"
readonly EXPECTED_FIXTURE_TAG="live-test"
readonly EXPECTED_OWNER_TAG="azurator-repository"
readonly STORAGE_RESOURCE_TYPE="microsoft.storage/storageaccounts"
readonly ROTATION_STORAGE_ROLE="rotation-storage"
readonly APP_SERVICE_RESOURCE_TYPE="microsoft.web/sites"
readonly APP_SERVICE_SETTINGS_ROLE="app-service-settings"
readonly WATCH_INTERVAL_SECONDS="0.20"
readonly MAX_PENDING_POLLS=600

readonly BASH_BIN="${AZURATOR_LIVE_TEST_BASH:?AZURATOR_LIVE_TEST_BASH is required}"
readonly AZ_BIN="${AZURATOR_LIVE_TEST_AZ:?AZURATOR_LIVE_TEST_AZ is required}"
readonly JQ_BIN="${AZURATOR_LIVE_TEST_JQ:?AZURATOR_LIVE_TEST_JQ is required}"
readonly AZURATOR_BIN="${AZURATOR_LIVE_TEST_AZURATOR:?AZURATOR_LIVE_TEST_AZURATOR is required}"
readonly LIFECYCLE_SCRIPT="${AZURATOR_LIVE_TEST_LIFECYCLE:?AZURATOR_LIVE_TEST_LIFECYCLE is required}"

RECOVERY_WORKSPACE=""
WATCHER_PID=""
FIXTURE_CREATED=false
WORKFLOW_COMPLETED=false

usage() {
  printf 'Usage: %s\n' "${0##*/}" >&2
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

require_executable() {
  [[ -x "$1" ]] || fail "$2 is unavailable"
}

require_runtime() {
  require_executable "$BASH_BIN" "Bash"
  require_executable "$AZ_BIN" "Azure CLI"
  require_executable "$JQ_BIN" "jq"
  require_executable "$AZURATOR_BIN" "Azurator"
  [[ -f "$LIFECYCLE_SCRIPT" && ! -L "$LIFECYCLE_SCRIPT" ]] \
    || fail "the reviewed live-test lifecycle script is unavailable"
}

run_lifecycle() {
  "$BASH_BIN" "$LIFECYCLE_SCRIPT" "$1"
}

remove_workspace() {
  local workspace="$RECOVERY_WORKSPACE"
  [[ -n "$workspace" ]] || return 0
  if [[ ! -d "$workspace" || -L "$workspace" ]]; then
    printf 'Warning: refusing to remove an unexpected recovery-test workspace: %s\n' "$workspace" >&2
    return 1
  fi
  rm -rf -- "$workspace"
  RECOVERY_WORKSPACE=""
}

stop_watcher() {
  local watcher_pid="$WATCHER_PID"
  [[ -n "$watcher_pid" ]] || return 0
  if kill -0 "$watcher_pid" 2>/dev/null; then
    kill -TERM "$watcher_pid" 2>/dev/null || true
  fi
  wait "$watcher_pid" 2>/dev/null || true
  WATCHER_PID=""
}

handle_exit() {
  local status=$?
  trap - EXIT

  stop_watcher
  if [[ -n "$RECOVERY_WORKSPACE" ]] && ! remove_workspace; then
    status=1
  fi

  if [[ "$status" -ne 0 && "$FIXTURE_CREATED" == true && "$WORKFLOW_COMPLETED" != true ]]; then
    printf '%s\n' \
      "The tagged $RESOURCE_GROUP_NAME fixture remains for recovery or diagnosis." \
      "Inspect local state with 'azurator operation list' before deciding whether to resume." \
      "After recovery, remove the fixture with 'nix run .#live-test-down'." >&2
  fi

  exit "$status"
}

load_account_scope() {
  local account_json
  account_json="$("$AZ_BIN" account show --only-show-errors --output json)"
  SUBSCRIPTION_ID="$("$JQ_BIN" -er '.id | select(type == "string")' <<<"$account_json")"
  AZURE_ENVIRONMENT="$("$JQ_BIN" -er '.environmentName | select(type == "string")' <<<"$account_json")"

  [[ "$SUBSCRIPTION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || fail "Azure CLI returned an invalid subscription ID"
  [[ "$AZURE_ENVIRONMENT" == "AzureCloud" ]] \
    || fail "the reviewed live-test recovery workflow supports Azure public cloud only"
}

fixture_exists() {
  "$AZ_BIN" group exists \
    --name "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --only-show-errors
}

load_fixture_resource_ids() {
  local resources_json
  resources_json="$(
    "$AZ_BIN" resource list \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --output json \
      --only-show-errors
  )"

  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! STORAGE_ACCOUNT_ID="$(
    "$JQ_BIN" -er \
      --arg resource_type "$STORAGE_RESOURCE_TYPE" \
      --arg role "$ROTATION_STORAGE_ROLE" \
      --arg fixture "$EXPECTED_FIXTURE_TAG" \
      --arg owner "$EXPECTED_OWNER_TAG" \
      '
        [
          .[]
          | select((.type | ascii_downcase) == ($resource_type | ascii_downcase))
          | select(.tags["azurator-fixture"] == $fixture)
          | select(.tags["azurator-owner"] == $owner)
          | select(.tags["azurator-live-test-role"] == $role)
          | .id
        ]
        | if length == 1 and (.[0] | type) == "string" and (.[0] | length) > 0
          then .[0]
          else error("expected exactly one tagged fixture resource")
          end
      ' <<<"$resources_json" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged rotation Storage Account"
  fi

  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! APP_SERVICE_ID="$(
    "$JQ_BIN" -er \
      --arg resource_type "$APP_SERVICE_RESOURCE_TYPE" \
      --arg role "$APP_SERVICE_SETTINGS_ROLE" \
      --arg fixture "$EXPECTED_FIXTURE_TAG" \
      --arg owner "$EXPECTED_OWNER_TAG" \
      '
        [
          .[]
          | select((.type | ascii_downcase) == ($resource_type | ascii_downcase))
          | select(.tags["azurator-fixture"] == $fixture)
          | select(.tags["azurator-owner"] == $owner)
          | select(.tags["azurator-live-test-role"] == $role)
          | .id
        ]
        | if length == 1 and (.[0] | type) == "string" and (.[0] | length) > 0
          then .[0]
          else error("expected exactly one tagged fixture resource")
          end
      ' <<<"$resources_json" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged App Service settings app"
  fi
}

load_operation_report() {
  "$AZURATOR_BIN" operation list --json
}

validate_operation_report_shape() {
  local report_json="$1"
  "$JQ_BIN" -e \
    '
      .schema_version == "1"
      and (.operations | type) == "array"
      and (.invalid_operation_ids | type) == "array"
    ' >/dev/null 2>&1 <<<"$report_json"
}

require_empty_operation_catalog() {
  local report_json
  if ! report_json="$(load_operation_report)"; then
    fail "the local retained-operation catalog could not be inspected safely"
  fi
  if ! validate_operation_report_shape "$report_json"; then
    fail "Azurator returned an unexpected retained-operation projection"
  fi
  if ! "$JQ_BIN" -e \
    '(.operations | length) == 0 and (.invalid_operation_ids | length) == 0' \
    >/dev/null 2>&1 <<<"$report_json"; then
    fail "the controlled recovery exercise requires an empty valid retained-operation catalog"
  fi
}

write_watcher_result() {
  local result_file="$1"
  shift
  printf '%s\n' "$@" >"$result_file"
}

interrupt_rotation() {
  local rotation_pid="$1"
  kill -INT "$rotation_pid" 2>/dev/null
}

watch_for_pending_checkpoint() {
  local pid_file="$1"
  local result_file="$2"
  local rotation_pid=""
  local report_json show_json operation_id status step_state
  local pending_polls=0

  while [[ -z "$rotation_pid" ]]; do
    if [[ -f "$pid_file" ]]; then
      IFS= read -r rotation_pid <"$pid_file"
      if [[ ! "$rotation_pid" =~ ^[1-9][0-9]*$ ]]; then
        write_watcher_result "$result_file" "watcher-error" \
          "the foreground rotation process identity was invalid"
        return 1
      fi
      break
    fi
    sleep "$WATCH_INTERVAL_SECONDS"
  done

  while kill -0 "$rotation_pid" 2>/dev/null; do
    if ! report_json="$(load_operation_report 2>/dev/null)"; then
      interrupt_rotation "$rotation_pid" || true
      write_watcher_result "$result_file" "watcher-error" \
        "the retained-operation catalog became unreadable"
      return 1
    fi
    if ! validate_operation_report_shape "$report_json"; then
      interrupt_rotation "$rotation_pid" || true
      write_watcher_result "$result_file" "watcher-error" \
        "the retained-operation projection changed shape"
      return 1
    fi
    if ! "$JQ_BIN" -e '(.invalid_operation_ids | length) == 0' \
      >/dev/null 2>&1 <<<"$report_json"; then
      interrupt_rotation "$rotation_pid" || true
      write_watcher_result "$result_file" "watcher-error" \
        "an invalid retained-operation entry appeared"
      return 1
    fi

    case "$("$JQ_BIN" -r '.operations | length' <<<"$report_json")" in
      0)
        sleep "$WATCH_INTERVAL_SECONDS"
        continue
        ;;
      1)
        operation_id="$("$JQ_BIN" -er '.operations[0].operation_id' <<<"$report_json")"
        ;;
      *)
        interrupt_rotation "$rotation_pid" || true
        write_watcher_result "$result_file" "watcher-error" \
          "more than one retained operation appeared during the isolated exercise"
        return 1
        ;;
    esac

    if ! show_json="$("$AZURATOR_BIN" operation show "$operation_id" --json 2>/dev/null)"; then
      write_watcher_result "$result_file" "checkpoint-missed" "$operation_id"
      return 1
    fi
    # jq variables, not shell variables, are intentionally expanded here.
    # shellcheck disable=SC2016
    if ! "$JQ_BIN" -e \
      --arg operation_id "$operation_id" \
      '
        .schema_version == "1"
        and .operation_id == $operation_id
        and (.status == "running" or .status == "failed" or .status == "completed")
        and (
          .current_step == null
          or .current_step.state == "next"
          or .current_step.state == "pending"
        )
      ' >/dev/null 2>&1 <<<"$show_json"; then
      interrupt_rotation "$rotation_pid" || true
      write_watcher_result "$result_file" "watcher-error" \
        "the retained operation did not satisfy the safe projection contract"
      return 1
    fi

    status="$("$JQ_BIN" -r '.status' <<<"$show_json")"
    step_state="$("$JQ_BIN" -r '.current_step.state // "none"' <<<"$show_json")"
    if [[ "$status" == "running" && "$step_state" == "pending" ]]; then
      if interrupt_rotation "$rotation_pid"; then
        write_watcher_result "$result_file" "interrupted" "$operation_id"
        return
      fi
      write_watcher_result "$result_file" "checkpoint-missed" "$operation_id"
      return 1
    fi
    if [[ "$status" != "running" ]]; then
      write_watcher_result "$result_file" "checkpoint-missed" "$operation_id"
      return 1
    fi

    ((pending_polls += 1))
    if ((pending_polls >= MAX_PENDING_POLLS)); then
      interrupt_rotation "$rotation_pid" || true
      write_watcher_result "$result_file" "watcher-error" \
        "no pending checkpoint became observable within the bounded interval"
      return 1
    fi
    sleep "$WATCH_INTERVAL_SECONDS"
  done

  write_watcher_result "$result_file" "rotation-exited"
  return 1
}

validate_interrupted_operation() {
  local operation_id="$1"
  local show_json
  if ! show_json="$("$AZURATOR_BIN" operation show "$operation_id" --json)"; then
    fail "the interrupted operation was not retained as a valid local recovery entry"
  fi
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg operation_id "$operation_id" \
    '
      .schema_version == "1"
      and .operation_id == $operation_id
      and .status == "running"
      and .current_step.state == "pending"
    ' >/dev/null 2>&1 <<<"$show_json"; then
    fail "the retained entry did not represent the controlled pending interruption"
  fi
}

require_operation_removed() {
  local operation_id="$1"
  local report_json
  if ! report_json="$(load_operation_report)"; then
    fail "the local retained-operation catalog could not be inspected after resume"
  fi
  if ! validate_operation_report_shape "$report_json"; then
    fail "Azurator returned an unexpected retained-operation projection after resume"
  fi
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if "$JQ_BIN" -e \
    --arg operation_id "$operation_id" \
    '.operations[]? | select(.operation_id == $operation_id)' \
    >/dev/null 2>&1 <<<"$report_json"; then
    "$AZURATOR_BIN" operation show "$operation_id" || true
    fail "resume did not complete and remove the controlled recovery operation"
  fi
  if ! "$JQ_BIN" -e \
    '(.operations | length) == 0 and (.invalid_operation_ids | length) == 0' \
    >/dev/null 2>&1 <<<"$report_json"; then
    fail "unexpected retained-operation state remained after the controlled resume"
  fi
}

validate_final_plan() {
  local plan_json="$1"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg app_service_id "$APP_SERVICE_ID" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      .schema_version == "1"
      and .source_format == "direct-selection"
      and .azure_binding_inspection == "enabled"
      and (.state == "ready" or .state == "confirmation-required")
      and (.scheduled_slots | length) == 1
      and (
        [
          .scheduled_slots[]
          | select((.resource_id | same_id($storage_id)) and .key_slot == "key1")
        ]
        | length == 1
      )
      and (
        [
          .bindings[]
          | select(.provider == "azure-foundry-connections")
          | select(.location == "azure")
          | select(.management == "update-and-verify")
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
        ]
        | length == 1
      )
      and (
        [
          .bindings[]
          | select(.provider == "azure-app-service-settings")
          | select(.location == "azure")
          | select(.management == "update-and-verify")
          | select(.scope_id | same_id($app_service_id))
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
          | select(.selectors == ["AZURATOR_STORAGE_ALIAS", "AZURATOR_STORAGE_KEY"])
        ]
        | length == 1
      )
    ' >/dev/null 2>&1 <<<"$plan_json"; then
    fail "post-resume inspection did not confirm the expected Storage key1 Azure bindings"
  fi
}

run_controlled_rotation() {
  local pid_file="$RECOVERY_WORKSPACE/rotation.pid"
  local result_file="$RECOVERY_WORKSPACE/watcher.result"
  local rotation_status watcher_status result_kind operation_id
  local -a watcher_result=()

  watch_for_pending_checkpoint "$pid_file" "$result_file" &
  WATCHER_PID=$!

  set +e
  (
    printf '%s\n' "$BASHPID" >"$pid_file"
    exec "$AZURATOR_BIN" rotate \
      --subscription "$SUBSCRIPTION_ID" \
      --select "$STORAGE_ACCOUNT_ID#key1"
  )
  rotation_status=$?
  wait "$WATCHER_PID"
  watcher_status=$?
  set -e
  WATCHER_PID=""

  [[ -f "$result_file" ]] \
    || fail "the checkpoint watcher exited without a bounded result"
  mapfile -t watcher_result <"$result_file"
  result_kind="${watcher_result[0]:-watcher-error}"
  operation_id="${watcher_result[1]:-}"

  if [[ "$result_kind" != "interrupted" && "$rotation_status" -eq 0 ]]; then
    require_empty_operation_catalog
    printf '%s\n' \
      'No pending recovery checkpoint remained after the foreground rotation returned.' \
      'The rotation was either cancelled before mutation or completed before interception;' \
      'the controlled recovery exercise therefore did not succeed.'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    fail "the controlled recovery checkpoint was not exercised"
  fi
  if [[ "$result_kind" != "interrupted" || "$watcher_status" -ne 0 ]]; then
    fail "${watcher_result[1]:-the controlled checkpoint watcher did not interrupt a pending step}"
  fi
  [[ "$rotation_status" -ne 0 ]] \
    || fail "the foreground rotation did not stop after the controlled interrupt"
  [[ "$operation_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] \
    || fail "the checkpoint watcher returned an invalid operation ID"

  validate_interrupted_operation "$operation_id"
  printf '\nRetained checkpoint after controlled interruption\n'
  "$AZURATOR_BIN" operation show "$operation_id"

  printf '\nResume the exact retained operation\n'
  "$AZURATOR_BIN" rotate --resume "$operation_id"
  require_operation_removed "$operation_id"
}

main() {
  local exists final_plan_json

  [[ $# -eq 0 ]] || {
    usage
    exit 2
  }
  require_runtime
  require_empty_operation_catalog
  load_account_scope

  printf '%s\n' \
    'Guided Azurator live recovery test' \
    "Subscription: $SUBSCRIPTION_ID" \
    'This development workflow deploys the tagged fixture, displays and confirms one Storage' \
    'key1 rotation, sends SIGINT only after Azurator exposes a pending recovery checkpoint,' \
    'then displays and confirms the normal resume path before verifying stored configuration.' \
    'It does not inject a product failure, print a key value, invoke a workload, or run in CI.'

  "$AZURATOR_BIN" auth status --subscription "$SUBSCRIPTION_ID"
  run_lifecycle up

  exists="$(fixture_exists)"
  [[ "$exists" == "true" || "$exists" == "false" ]] \
    || fail "Azure CLI returned an invalid resource-group existence result"
  if [[ "$exists" == "false" ]]; then
    printf 'Fixture deployment was cancelled; no recovery test was run.\n'
    WORKFLOW_COMPLETED=true
    return
  fi
  FIXTURE_CREATED=true
  load_fixture_resource_ids

  RECOVERY_WORKSPACE="$(mktemp -d -t azurator-live-test-recovery.XXXXXXXX)"
  chmod 700 "$RECOVERY_WORKSPACE"

  printf '\nStep 1/4: metadata-only discovery\n'
  "$AZURATOR_BIN" discover --subscription "$SUBSCRIPTION_ID"

  printf '\nStep 2/4: controlled interruption of a confirmed Storage key1 rotation\n'
  run_controlled_rotation

  printf '\nStep 3/4: post-resume key and Azure binding inspection\n'
  final_plan_json="$(
    "$AZURATOR_BIN" plan \
      --subscription "$SUBSCRIPTION_ID" \
      --select "$STORAGE_ACCOUNT_ID#key1" \
      --json
  )"
  validate_final_plan "$final_plan_json"
  final_plan_json=""
  printf '%s\n' \
    'Verified that the resumed operation completed and the reviewed Foundry connection and' \
    'App Service settings contain the current Storage key1. No workload was invoked.'

  printf '\nStep 4/4: tagged fixture teardown\n'
  remove_workspace
  run_lifecycle down
  WORKFLOW_COMPLETED=true
  printf 'Live recovery test completed and the tagged fixture was removed.\n'
}

trap handle_exit EXIT
main "$@"
