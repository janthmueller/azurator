#!/usr/bin/env bash

set -euo pipefail

readonly PROGRAM="${FAKE_PROGRAM:-${0##*/}}"
readonly MODE="${FAKE_MODE:-success}"
readonly TEST_ROOT="${FAKE_ROOT:?FAKE_ROOT is required}"
readonly CALL_LOG="${FAKE_LOG:?FAKE_LOG is required}"
readonly SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"
readonly RESOURCE_GROUP_NAME="rg-azurator-live-test"
readonly STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Storage/storageAccounts/stazuratortest"
readonly DISABLED_STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Storage/storageAccounts/stazuratordisabled"
readonly APP_SERVICE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Web/sites/app-azurator-test"
readonly OPERATION_ID="57c7fa92-2899-4c2f-9d30-2fc915be5f6c"
readonly OPERATION_MARKER="$TEST_ROOT/operation-pending"

{
  printf '%s' "$PROGRAM"
  printf ' %q' "$@"
  printf '\n'
} >>"$CALL_LOG"

has_option() {
  local expected="$1"
  shift
  while (($# > 0)); do
    [[ "$1" == "$expected" ]] && return
    shift
  done
  return 1
}

option_value() {
  local option="$1"
  shift
  while (($# > 0)); do
    if [[ "$1" == "$option" ]]; then
      shift
      (($# > 0)) || return 1
      printf '%s\n' "$1"
      return
    fi
    shift
  done
  return 1
}

operation_summary() {
  printf '%s\n' \
    "{" \
    "  \"schema_version\": \"1\"," \
    "  \"operation_id\": \"$OPERATION_ID\"," \
    "  \"status\": \"running\"," \
    "  \"started_at\": \"2000-01-01T10:00:00Z\"," \
    "  \"updated_at\": \"2000-01-01T10:00:01Z\"," \
    "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
    "  \"subscription_name\": \"Example Subscription\"," \
    "  \"completed_steps\": 0," \
    "  \"total_steps\": 5," \
    "  \"current_step\": {" \
    "    \"state\": \"pending\"," \
    "    \"sequence\": 1," \
    "    \"action\": \"update-consumer\"," \
    "    \"phase\": \"bridge\"," \
    "    \"resource_name\": \"stazuratortest\"," \
    "    \"key_slot\": \"key2\"," \
    "    \"consumer_name\": \"storage-connection\"," \
    "    \"consumer_scope_name\": \"azurator-live-test-project\"" \
    "  }," \
    "  \"error_code\": null," \
    "  \"resources\": [" \
    "    {\"name\":\"stazuratortest\",\"provider\":\"azure-storage\",\"kind\":\"StorageV2\",\"key_slots\":[\"key1\"]}" \
    "  ]," \
    "  \"resume_command\": \"azurator rotate --resume $OPERATION_ID\"" \
    "}"
}

operation_list() {
  if [[ "$MODE" == "preexisting-invalid" ]]; then
    printf '{"schema_version":"1","operations":[],"invalid_operation_ids":["%s"]}\n' "$OPERATION_ID"
    return
  fi
  if [[ "$MODE" == "preexisting-valid" || -e "$OPERATION_MARKER" ]]; then
    printf '{"schema_version":"1","operations":['
    operation_summary
    printf '],"invalid_operation_ids":[]}\n'
    return
  fi
  printf '{"schema_version":"1","operations":[],"invalid_operation_ids":[]}\n'
}

run_lifecycle() {
  [[ $# -eq 1 ]] || exit 2
  case "$1" in
    up)
      : >"$TEST_ROOT/group-exists"
      printf 'Fake tagged fixture created.\n'
      ;;
    down)
      rm -f -- "$TEST_ROOT/group-exists"
      printf 'Fake tagged fixture deleted.\n'
      ;;
    *)
      exit 2
      ;;
  esac
}

run_az() {
  if [[ "${1:-}" == "account" && "${2:-}" == "show" ]]; then
    printf '{"id":"%s","environmentName":"AzureCloud"}\n' "$SUBSCRIPTION_ID"
    return
  fi
  if [[ "${1:-}" == "group" && "${2:-}" == "exists" ]]; then
    if [[ -e "$TEST_ROOT/group-exists" ]]; then
      printf 'true\n'
    else
      printf 'false\n'
    fi
    return
  fi
  if [[ "${1:-}" == "resource" && "${2:-}" == "list" ]]; then
    printf '%s\n' \
      "[" \
      "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
      "  {\"id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-storage\"}}," \
      "  {\"id\":\"$APP_SERVICE_ID\",\"type\":\"Microsoft.Web/sites\",\"kind\":\"app,linux\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"app-service-settings\"}}" \
      "]"
    return
  fi
  exit 2
}

wait_for_interrupt() {
  on_interrupt() {
    printf 'Fake controlled rotation interrupted with recovery state retained.\n' >&2
    exit 130
  }
  trap on_interrupt INT
  while :; do
    sleep 0.05
  done
}

run_azurator() {
  local command="${1:-}"
  local operation_id
  case "$command" in
    auth)
      printf 'Fake Azurator authentication is ready.\n'
      ;;
    discover)
      printf 'Fake metadata-only inventory contains the tagged rotation Storage Account.\n'
      ;;
    operation)
      case "${2:-}" in
        list)
          operation_list
          ;;
        show)
          operation_id="${3:-}"
          [[ "$operation_id" == "$OPERATION_ID" && -e "$OPERATION_MARKER" ]] || exit 1
          if has_option --json "$@"; then
            operation_summary
          else
            printf 'Fake safe pending operation projection for %s.\n' "$OPERATION_ID"
          fi
          ;;
        *)
          exit 2
          ;;
      esac
      ;;
    rotate)
      if has_option --resume "$@"; then
        operation_id="$(option_value --resume "$@")"
        [[ "$operation_id" == "$OPERATION_ID" && -e "$OPERATION_MARKER" ]] || exit 1
        if [[ "$MODE" == "resume-cancel" ]]; then
          printf 'Fake resume cancelled; operation retained.\n'
          return
        fi
        if [[ "$MODE" == "resume-fail" ]]; then
          printf 'Fake secret-free resume failure.\n' >&2
          return 42
        fi
        rm -f -- "$OPERATION_MARKER"
        printf 'Fake resumed rotation completed and recovery state was removed.\n'
        return
      fi
      if [[ "$MODE" == "rotate-cancel" || "$MODE" == "checkpoint-missed" ]]; then
        printf 'Fake initial rotation returned without retained state.\n'
        return
      fi
      : >"$OPERATION_MARKER"
      wait_for_interrupt
      ;;
    plan)
      printf '%s\n' \
        "{" \
        "  \"schema_version\": \"1\"," \
        "  \"source_format\": \"direct-selection\"," \
        "  \"azure_binding_inspection\": \"enabled\"," \
        "  \"state\": \"confirmation-required\"," \
        "  \"scheduled_slots\": [" \
        "    {\"resource_id\":\"$STORAGE_ACCOUNT_ID\",\"key_slot\":\"key1\",\"input_selectors\":[]}" \
        "  ]," \
      "  \"bindings\": [" \
      "    {\"provider\":\"azure-foundry-connections\",\"location\":\"azure\",\"management\":\"update-and-verify\",\"key_resource_id\":\"$STORAGE_ACCOUNT_ID\",\"key_slot\":\"key1\"}," \
      "    {\"provider\":\"azure-app-service-settings\",\"location\":\"azure\",\"management\":\"update-and-verify\",\"scope_id\":\"$APP_SERVICE_ID\",\"key_resource_id\":\"$STORAGE_ACCOUNT_ID\",\"key_slot\":\"key1\",\"selectors\":[\"AZURATOR_STORAGE_ALIAS\",\"AZURATOR_STORAGE_CONNECTION\",\"AZURATOR_STORAGE_KEY\"]}" \
        "  ]" \
        "}"
      ;;
    *)
      exit 2
      ;;
  esac
}

case "$PROGRAM" in
  lifecycle)
    run_lifecycle "$@"
    ;;
  az)
    run_az "$@"
    ;;
  azurator)
    run_azurator "$@"
    ;;
  *)
    exit 2
    ;;
esac
