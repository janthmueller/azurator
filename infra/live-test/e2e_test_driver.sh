#!/usr/bin/env bash

set -euo pipefail

readonly PROGRAM="${FAKE_PROGRAM:-${0##*/}}"
readonly MODE="${FAKE_MODE:-success}"
readonly TEST_ROOT="${FAKE_ROOT:?FAKE_ROOT is required}"
readonly CALL_LOG="${FAKE_LOG:?FAKE_LOG is required}"
readonly JQ_BIN="${AZURATOR_LIVE_TEST_JQ:?AZURATOR_LIVE_TEST_JQ is required}"
readonly SOPS_BIN="${AZURATOR_LIVE_TEST_SOPS:?AZURATOR_LIVE_TEST_SOPS is required}"
readonly SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"
readonly RESOURCE_GROUP_NAME="rg-azurator-live-test"
readonly STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Storage/storageAccounts/stazuratortest"
readonly DISABLED_STORAGE_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Storage/storageAccounts/stazuratordisabled"
readonly FOUNDRY_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.CognitiveServices/accounts/ai-azurator-test"
readonly DISABLED_FOUNDRY_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.CognitiveServices/accounts/ai-azurator-disabled"
readonly OPENAI_ACCOUNT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.CognitiveServices/accounts/aoai-azurator-test"
readonly APP_SERVICE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Web/sites/app-azurator-test"
readonly APP_SERVICE_PLAN_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME/providers/Microsoft.Web/serverFarms/plan-azurator-test"
readonly FOUNDRY_PROJECT_ID="$FOUNDRY_ACCOUNT_ID/projects/project-azurator-test"

{
  printf '%s' "$PROGRAM"
  printf ' %q' "$@"
  printf '\n'
} >>"$CALL_LOG"

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

option_values() {
  local option="$1"
  shift
  while (($# > 0)); do
    if [[ "$1" == "$option" ]]; then
      shift
      (($# > 0)) || return 1
      printf '%s\n' "$1"
    fi
    shift
  done
}

has_option() {
  local expected="$1"
  shift
  while (($# > 0)); do
    [[ "$1" == "$expected" ]] && return
    shift
  done
  return 1
}

render_managed_env() {
  local suffix="$1"
  printf "AZURATOR_STORAGE_STAZURATORTEST_KEY1='storage-secret-%s'\n" "$suffix"
  printf "AZURATOR_STORAGE_STAZURATORTEST_KEY2='storage-secret-secondary-%s'\n" "$suffix"
  printf "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1='openai-secret-%s'\n" "$suffix"
}

render_mapped_env() {
  local suffix="$1"
  render_managed_env "$suffix"
  printf "AZURATOR_STORAGE_LOCAL_ALIAS='storage-secret-%s'\n" "$suffix"
  printf "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS='storage-secret-secondary-%s'\n" "$suffix"
  if [[ "$MODE" != "bad-key-map-export" ]]; then
    printf "AZURATOR_OPENAI_LOCAL_ALIAS='openai-secret-%s'\n" "$suffix"
  fi
}

sops_selector_path() {
  # jq variable, not a shell variable, is intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -cn --arg selector "$1" '[$selector]'
}

set_sops_value() {
  local destination="$1"
  local selector="$2"
  local json_value="$3"
  local selector_path
  selector_path="$(sops_selector_path "$selector")"
  printf '%s' "$json_value" \
    | "$SOPS_BIN" set \
      --input-type dotenv \
      --output-type dotenv \
      --value-stdin \
      "$destination" \
      "$selector_path" \
      >/dev/null
}

update_managed_sops() {
  local destination="$1"
  local suffix="$2"
  local preserve_inode="$3"
  local target="$destination"
  local temporary=""
  if [[ "$preserve_inode" == true ]]; then
    temporary="$(mktemp "${destination%/*}/.fake-managed-sops.XXXXXXXX")"
    cp -- "$destination" "$temporary"
    chmod 600 "$temporary"
    target="$temporary"
  fi

  set_sops_value "$target" "AZURATOR_STORAGE_STAZURATORTEST_KEY1" "\"storage-secret-$suffix\""
  set_sops_value "$target" "AZURATOR_STORAGE_LOCAL_ALIAS" "\"storage-secret-$suffix\""
  set_sops_value \
    "$target" "AZURATOR_STORAGE_STAZURATORTEST_KEY2" "\"storage-secret-secondary-$suffix\""
  set_sops_value \
    "$target" "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS" "\"storage-secret-secondary-$suffix\""
  set_sops_value "$target" "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1" "\"openai-secret-$suffix\""
  set_sops_value "$target" "AZURATOR_OPENAI_LOCAL_ALIAS" "\"openai-secret-$suffix\""
  if [[ "$MODE" == "corrupt-unrelated" ]]; then
    set_sops_value "$target" "AZURATOR_UNRELATED" '"changed"'
  fi

  if [[ -n "$temporary" ]]; then
    cp -- "$temporary" "$destination"
    rm -f -- "$temporary"
  fi
  chmod 600 "$destination"
}

write_foundry_snapshot() {
  local destination="$1"
  local temporary
  temporary="$(mktemp "${destination%/*}/.fake-foundry-snapshot.XXXXXXXX")"
  chmod 600 "$temporary"
  printf "AZURATOR_COGNITIVE_AI_AZURATOR_TEST_KEY1='foundry-secret-before'\n" >"$temporary"
  mv -f -- "$temporary" "$destination"
}

run_lifecycle() {
  [[ $# -eq 1 ]] || exit 2
  case "$1" in
    up)
      if [[ "$MODE" != "deploy-cancel" ]]; then
        : >"$TEST_ROOT/group-exists"
        printf 'Fake tagged fixture created.\n'
      fi
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
  if [[ "${1:-}" == "group" && "${2:-}" == "show" ]]; then
    if [[ "$MODE" == "unsafe-reuse-group" ]]; then
      printf '{"id":"/subscriptions/%s/resourceGroups/%s","tags":{"azurator-fixture":"live-test","azurator-owner":"unexpected-owner"}}\n' \
        "$SUBSCRIPTION_ID" "$RESOURCE_GROUP_NAME"
    else
      printf '{"id":"/subscriptions/%s/resourceGroups/%s","tags":{"azurator-fixture":"live-test","azurator-owner":"azurator-repository"}}\n' \
        "$SUBSCRIPTION_ID" "$RESOURCE_GROUP_NAME"
    fi
    return
  fi
  if [[ "${1:-}" == "resource" && "${2:-}" == "list" ]]; then
    if [[ "$MODE" == "bad-inventory" ]]; then
      printf '%s\n' \
        "[" \
        "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
        "  {\"id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-storage\"}}," \
        "  {\"id\":\"$FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"foundry-project-host\"}}," \
        "  {\"id\":\"$DISABLED_FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-foundry\"}}" \
        "]"
      return
    fi
    if [[ "$MODE" == "missing-disabled-storage" ]]; then
      printf '%s\n' \
        "[" \
        "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
        "  {\"id\":\"$OPENAI_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"OpenAI\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-openai\"}}," \
        "  {\"id\":\"$FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"foundry-project-host\"}}," \
        "  {\"id\":\"$DISABLED_FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-foundry\"}}" \
        "]"
      return
    fi
    if [[ "$MODE" == "missing-disabled-foundry" ]]; then
      printf '%s\n' \
        "[" \
        "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
        "  {\"id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-storage\"}}," \
        "  {\"id\":\"$OPENAI_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"OpenAI\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-openai\"}}," \
        "  {\"id\":\"$FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"foundry-project-host\"}}" \
        "]"
      return
    fi
    if [[ "$MODE" == "missing-app-service" ]]; then
      printf '%s\n' \
        "[" \
        "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
        "  {\"id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-storage\"}}," \
        "  {\"id\":\"$OPENAI_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"OpenAI\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-openai\"}}," \
        "  {\"id\":\"$FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"foundry-project-host\"}}," \
        "  {\"id\":\"$DISABLED_FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-foundry\"}}" \
        "]"
      return
    fi
    printf '%s\n' \
      "[" \
      "  {\"id\":\"$STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-storage\"}}," \
      "  {\"id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-storage\"}}," \
      "  {\"id\":\"$OPENAI_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"OpenAI\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"rotation-openai\"}}," \
      "  {\"id\":\"$FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"foundry-project-host\"}}," \
      "  {\"id\":\"$DISABLED_FOUNDRY_ACCOUNT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"disabled-foundry\"}}," \
      "  {\"id\":\"$APP_SERVICE_PLAN_ID\",\"type\":\"Microsoft.Web/serverFarms\",\"kind\":\"linux\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"app-service-settings\"}}," \
      "  {\"id\":\"$FOUNDRY_PROJECT_ID\",\"type\":\"Microsoft.CognitiveServices/accounts/projects\",\"kind\":\"\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\"}}," \
      "  {\"id\":\"$APP_SERVICE_ID\",\"type\":\"Microsoft.Web/sites\",\"kind\":\"app,linux\",\"tags\":{\"azurator-fixture\":\"live-test\",\"azurator-owner\":\"azurator-repository\",\"azurator-live-test-role\":\"app-service-settings\"}}" \
      "]"
    return
  fi
  if [[ "${1:-}" == "webapp" && "${2:-}" == "config" && "${3:-}" == "appsettings" && "${4:-}" == "list" ]]; then
    printf '1\n'
    return
  fi
  exit 2
}

write_sops_match_report() {
  local sops_path="$1"
  if [[ "$MODE" == "bad-sops-match" ]]; then
    printf '{"schema_version":"1","subscription_id":"%s","azure_binding_inspection":"enabled","providers":[],"input_selectors":[],"skipped_empty_selectors":[],"matches":[],"binding_inspections":[],"bindings":[],"warnings":[]}\n' \
      "$SUBSCRIPTION_ID"
    return
  fi
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -n \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg foundry_id "$FOUNDRY_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg app_service_id "$APP_SERVICE_ID" \
    --arg sops_path "$sops_path" \
    '
      {
        schema_version: "1",
        subscription_id: $subscription_id,
        azure_binding_inspection: "enabled",
        providers: [
          {name: "azure-storage"},
          {name: "azure-cognitive-services"},
          {name: "azure-foundry-connections"},
          {name: "azure-app-service-settings"},
          {name: "local-sops-dotenv-file"}
        ],
        input_selectors: [
          "AZURATOR_STORAGE_STAZURATORTEST_KEY1",
          "AZURATOR_STORAGE_STAZURATORTEST_KEY2",
          "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1",
          "AZURATOR_STORAGE_LOCAL_ALIAS",
          "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS",
          "AZURATOR_OPENAI_LOCAL_ALIAS",
          "AZURATOR_UNRELATED"
        ],
        skipped_empty_selectors: ["AZURATOR_EMPTY"],
        matches: [
          {input_selector: "AZURATOR_STORAGE_STAZURATORTEST_KEY1", resource_id: $storage_id, key_slot: "key1"},
          {input_selector: "AZURATOR_STORAGE_LOCAL_ALIAS", resource_id: $storage_id, key_slot: "key1"},
          {input_selector: "AZURATOR_STORAGE_STAZURATORTEST_KEY2", resource_id: $storage_id, key_slot: "key2"},
          {input_selector: "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS", resource_id: $storage_id, key_slot: "key2"},
          {input_selector: "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1", resource_id: $openai_id, key_slot: "Key1"},
          {input_selector: "AZURATOR_OPENAI_LOCAL_ALIAS", resource_id: $openai_id, key_slot: "Key1"}
        ],
        binding_inspections: [
          {provider: "azure-foundry-connections", location: "azure", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
          {provider: "azure-foundry-connections", location: "azure", resource_id: $openai_id, status: "inspected", scopes_inspected: 1},
          {provider: "azure-app-service-settings", location: "azure", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
          {provider: "azure-app-service-settings", location: "azure", resource_id: $openai_id, status: "inspected", scopes_inspected: 1},
          {provider: "local-sops-dotenv-file", location: "local", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
          {provider: "local-sops-dotenv-file", location: "local", resource_id: $openai_id, status: "inspected", scopes_inspected: 1}
        ],
        bindings: [
          {binding_id: "storage-foundry", provider: "azure-foundry-connections", location: "azure", management: "update-and-verify", key_resource_id: $storage_id, key_slot: "key1"},
          {binding_id: "openai-foundry", provider: "azure-foundry-connections", location: "azure", management: "update-and-verify", key_resource_id: $openai_id, key_slot: "Key1"},
          {binding_id: "storage-app", provider: "azure-app-service-settings", location: "azure", management: "update-and-verify", scope_id: $app_service_id, key_resource_id: $storage_id, key_slot: "key1", selectors: ["AZURATOR_STORAGE_ALIAS", "AZURATOR_STORAGE_CONNECTION", "AZURATOR_STORAGE_KEY"]},
          {binding_id: "openai-app", provider: "azure-app-service-settings", location: "azure", management: "update-and-verify", scope_id: $app_service_id, key_resource_id: $openai_id, key_slot: "Key1", selectors: ["AZURATOR_OPENAI_KEY"]},
          {binding_id: "storage-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $storage_id, key_slot: "key1", selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY1", "AZURATOR_STORAGE_LOCAL_ALIAS"]},
          {binding_id: "storage-secondary-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $storage_id, key_slot: "key2", selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY2", "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS"]},
          {binding_id: "openai-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $openai_id, key_slot: "Key1", selectors: ["AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1", "AZURATOR_OPENAI_LOCAL_ALIAS"]}
        ],
        warnings: [
          {code: "sops-file-managed-update", impact: "advisory", category: "persistence", provider: "local-sops-dotenv-file"}
        ]
      }
    '
}

write_key_map() {
  local destination="$1"
  local schema_version="1"
  local temporary
  if [[ "$MODE" == "bad-key-map" ]]; then
    schema_version="unexpected"
  fi
  temporary="$(mktemp "${destination%/*}/.fake-key-map.XXXXXXXX")"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -n \
    --arg schema_version "$schema_version" \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    '
      {
        schema_version: $schema_version,
        subscription_id: $subscription_id,
        mappings: [
          {selector: "AZURATOR_STORAGE_STAZURATORTEST_KEY1", key_resource_id: $storage_id, key_slot: "key1"},
          {selector: "AZURATOR_STORAGE_STAZURATORTEST_KEY2", key_resource_id: $storage_id, key_slot: "key2"},
          {selector: "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1", key_resource_id: $openai_id, key_slot: "Key1"},
          {selector: "AZURATOR_STORAGE_LOCAL_ALIAS", key_resource_id: $storage_id, key_slot: "key1"},
          {selector: "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS", key_resource_id: $storage_id, key_slot: "key2"},
          {selector: "AZURATOR_OPENAI_LOCAL_ALIAS", key_resource_id: $openai_id, key_slot: "Key1"}
        ]
      }
    ' >"$temporary"
  chmod 600 "$temporary"
  mv -f -- "$temporary" "$destination"
}

write_sops_plan() {
  local sops_path="$1"
  local omit_restore=false
  local misorder_restore=false
  if [[ "$MODE" == "bad-sops-plan" ]]; then
    printf '{"schema_version":"1","subscription_id":"%s","source_format":"sops-dotenv-file","source_path":"%s","steps":[],"warnings":[]}\n' \
      "$SUBSCRIPTION_ID" "$sops_path"
    return
  fi
  if [[ "$MODE" == "missing-slot-restore" ]]; then
    omit_restore=true
  fi
  if [[ "$MODE" == "misordered-slot-restore" ]]; then
    misorder_restore=true
  fi
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -n \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg app_service_id "$APP_SERVICE_ID" \
    --arg sops_path "$sops_path" \
    --argjson omit_restore "$omit_restore" \
    --argjson misorder_restore "$misorder_restore" \
    '
      def transitions($resource_id; $slot; $phase; $binding_ids):
        [
          $binding_ids[] as $binding_id
          | {action: "update-binding", phase: $phase, resource_id: $resource_id, key_slot: $slot, binding_id: $binding_id},
            {action: "verify-binding", phase: $phase, resource_id: $resource_id, key_slot: $slot, binding_id: $binding_id}
        ];
      def one_slot_steps($resource_id; $selected_slot; $bridge_slot; $binding_ids):
        transitions($resource_id; $bridge_slot; "bridge"; $binding_ids)
        + [{action: "regenerate-key", phase: "rotate", resource_id: $resource_id, key_slot: $selected_slot, binding_id: null}]
        + transitions($resource_id; $selected_slot; "finalize"; $binding_ids);
      def two_slot_steps(
        $resource_id;
        $primary_slot;
        $bridge_slot;
        $primary_binding_ids;
        $bridge_binding_ids;
        $all_binding_ids
      ):
        (
          transitions($resource_id; $bridge_slot; "bridge"; $primary_binding_ids)
          + [{action: "regenerate-key", phase: "rotate", resource_id: $resource_id, key_slot: $primary_slot, binding_id: null}]
          + transitions(
              $resource_id;
              $primary_slot;
              "finalize";
              $all_binding_ids
            )
          + [{action: "regenerate-key", phase: "rotate", resource_id: $resource_id, key_slot: $bridge_slot, binding_id: null}]
        ) as $before_restore
        | transitions(
            $resource_id;
            $bridge_slot;
            "finalize";
            $bridge_binding_ids
          ) as $restore
        | if $omit_restore
          then $before_restore
          elif $misorder_restore
          then $before_restore + ($restore | reverse)
          else $before_restore + $restore
          end;

      [
        {binding_id: "openai-app", provider: "azure-app-service-settings", location: "azure", management: "update-and-verify", scope_id: $app_service_id, key_resource_id: $openai_id, key_slot: "Key1", selectors: ["AZURATOR_OPENAI_KEY"]},
        {binding_id: "storage-app", provider: "azure-app-service-settings", location: "azure", management: "update-and-verify", scope_id: $app_service_id, key_resource_id: $storage_id, key_slot: "key1", selectors: ["AZURATOR_STORAGE_ALIAS", "AZURATOR_STORAGE_CONNECTION", "AZURATOR_STORAGE_KEY"]},
        {binding_id: "openai-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $openai_id, key_slot: "Key1", selectors: ["AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1", "AZURATOR_OPENAI_LOCAL_ALIAS"]},
        {binding_id: "storage-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $storage_id, key_slot: "key1", selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY1", "AZURATOR_STORAGE_LOCAL_ALIAS"]},
        {binding_id: "storage-secondary-sops", binding_type: "local/sops-dotenv-file", provider: "local-sops-dotenv-file", location: "local", management: "update-and-verify", scope_id: $sops_path, key_resource_id: $storage_id, key_slot: "key2", selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY2", "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS"]},
        {binding_id: "openai-foundry", provider: "azure-foundry-connections", location: "azure", management: "update-and-verify", key_resource_id: $openai_id, key_slot: "Key1"},
        {binding_id: "storage-foundry", provider: "azure-foundry-connections", location: "azure", management: "update-and-verify", key_resource_id: $storage_id, key_slot: "key1"}
      ] as $bindings
      | (
          one_slot_steps($openai_id; "Key1"; "Key2"; ["openai-app", "openai-sops", "openai-foundry"])
          + two_slot_steps(
            $storage_id;
            "key1";
            "key2";
            ["storage-app", "storage-sops", "storage-foundry"];
            ["storage-secondary-sops"];
            ["storage-app", "storage-sops", "storage-secondary-sops", "storage-foundry"]
          )
          | to_entries
          | map(.value + {sequence: (.key + 1)})
        ) as $steps
      | {
          schema_version: "1",
          subscription_id: $subscription_id,
          source_format: "sops-dotenv-file",
          source_path: $sops_path,
          source_selectors: [
            "AZURATOR_STORAGE_STAZURATORTEST_KEY1",
            "AZURATOR_STORAGE_STAZURATORTEST_KEY2",
            "AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1",
            "AZURATOR_STORAGE_LOCAL_ALIAS",
            "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS",
            "AZURATOR_OPENAI_LOCAL_ALIAS",
            "AZURATOR_UNRELATED"
          ],
          skipped_empty_selectors: ["AZURATOR_EMPTY"],
          azure_binding_inspection: "enabled",
          providers: [
            {name: "azure-storage"},
            {name: "azure-cognitive-services"},
            {name: "azure-foundry-connections"},
            {name: "azure-app-service-settings"},
            {name: "local-sops-dotenv-file"}
          ],
          resources: [
            {resource_id: $openai_id, provider: "azure-cognitive-services"},
            {resource_id: $storage_id, provider: "azure-storage"}
          ],
          scheduled_slots: [
            {resource_id: $openai_id, key_slot: "Key1", input_selectors: ["AZURATOR_COGNITIVE_AOAI_AZURATOR_TEST_KEY1", "AZURATOR_OPENAI_LOCAL_ALIAS"]},
            {resource_id: $storage_id, key_slot: "key1", input_selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY1", "AZURATOR_STORAGE_LOCAL_ALIAS"]},
            {resource_id: $storage_id, key_slot: "key2", input_selectors: ["AZURATOR_STORAGE_STAZURATORTEST_KEY2", "AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS"]}
          ],
          binding_inspections: [
            {provider: "azure-foundry-connections", location: "azure", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
            {provider: "azure-foundry-connections", location: "azure", resource_id: $openai_id, status: "inspected", scopes_inspected: 1},
            {provider: "azure-app-service-settings", location: "azure", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
            {provider: "azure-app-service-settings", location: "azure", resource_id: $openai_id, status: "inspected", scopes_inspected: 1},
            {provider: "local-sops-dotenv-file", location: "local", resource_id: $storage_id, status: "inspected", scopes_inspected: 1},
            {provider: "local-sops-dotenv-file", location: "local", resource_id: $openai_id, status: "inspected", scopes_inspected: 1}
          ],
          bindings: $bindings,
          steps: $steps,
          state: "confirmation-required",
          warnings: [
            {code: "sops-file-managed-update", impact: "advisory", category: "persistence", provider: "local-sops-dotenv-file"}
          ]
        }
    '
}

run_azurator() {
  local command="${1:-}"
  local ciphertext_temp destination disabled_foundry_auth disabled_foundry_available
  local disabled_storage_auth disabled_storage_available key_map managed_env selection
  local -a selections
  case "$command" in
    operation)
      [[ "${2:-}" == "list" ]] || exit 2
      if [[ "$MODE" == "reuse-operation-present" ]]; then
        printf '{"schema_version":"1","operations":[{"operation_id":"11111111-1111-1111-1111-111111111111"}],"invalid_operation_ids":[]}\n'
      else
        printf '{"schema_version":"1","operations":[],"invalid_operation_ids":[]}\n'
      fi
      ;;
    auth)
      printf 'Fake Azurator authentication is ready.\n'
      ;;
    discover)
      if ! has_option --json "$@"; then
        printf 'Fake metadata-only inventory contains the fixture resources.\n'
        return
      fi
      disabled_storage_auth="disabled"
      disabled_storage_available="false"
      disabled_foundry_auth="disabled"
      disabled_foundry_available="false"
      if [[ "$MODE" == "bad-storage-discovery" ]]; then
        disabled_storage_auth="enabled"
        disabled_storage_available="true"
      fi
      if [[ "$MODE" == "bad-foundry-discovery" ]]; then
        disabled_foundry_auth="enabled"
        disabled_foundry_available="true"
      fi
      printf '%s\n' \
        "{" \
        "  \"schema_version\": \"1\"," \
        "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
        "  \"resources\": [" \
        "    {\"resource_id\":\"$STORAGE_ACCOUNT_ID\",\"resource_type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"provider\":\"azure-storage\",\"key_authentication\":\"enabled\",\"key_slots\":[{\"name\":\"key1\",\"values_retrievable\":true,\"rotatable\":true},{\"name\":\"key2\",\"values_retrievable\":true,\"rotatable\":true}]}," \
        "    {\"resource_id\":\"$DISABLED_STORAGE_ACCOUNT_ID\",\"resource_type\":\"Microsoft.Storage/storageAccounts\",\"kind\":\"StorageV2\",\"provider\":\"azure-storage\",\"key_authentication\":\"$disabled_storage_auth\",\"key_slots\":[{\"name\":\"key1\",\"values_retrievable\":$disabled_storage_available,\"rotatable\":$disabled_storage_available},{\"name\":\"key2\",\"values_retrievable\":$disabled_storage_available,\"rotatable\":$disabled_storage_available}]}," \
        "    {\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"resource_type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"provider\":\"azure-cognitive-services\",\"key_authentication\":\"enabled\",\"key_slots\":[{\"name\":\"Key1\",\"values_retrievable\":true,\"rotatable\":true},{\"name\":\"Key2\",\"values_retrievable\":true,\"rotatable\":true}]}," \
        "    {\"resource_id\":\"$DISABLED_FOUNDRY_ACCOUNT_ID\",\"resource_type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"AIServices\",\"provider\":\"azure-cognitive-services\",\"key_authentication\":\"$disabled_foundry_auth\",\"key_slots\":[{\"name\":\"Key1\",\"values_retrievable\":$disabled_foundry_available,\"rotatable\":$disabled_foundry_available},{\"name\":\"Key2\",\"values_retrievable\":$disabled_foundry_available,\"rotatable\":$disabled_foundry_available}]}," \
        "    {\"resource_id\":\"$OPENAI_ACCOUNT_ID\",\"resource_type\":\"Microsoft.CognitiveServices/accounts\",\"kind\":\"OpenAI\",\"provider\":\"azure-cognitive-services\",\"key_authentication\":\"enabled\",\"key_slots\":[{\"name\":\"Key1\",\"values_retrievable\":true,\"rotatable\":true},{\"name\":\"Key2\",\"values_retrievable\":true,\"rotatable\":true}]}" \
        "  ]" \
        "}"
      ;;
    plan)
      if has_option --skip-azure-bindings "$@"; then
        selection="$(option_value --select "$@")"
        [[ "$selection" == "$FOUNDRY_ACCOUNT_ID#Key1" ]] || exit 2
        if [[ "$MODE" == "bad-skip-plan" ]]; then
          printf '%s\n' \
            "{" \
            "  \"schema_version\": \"1\"," \
            "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
            "  \"source_format\": \"direct-selection\"," \
            "  \"azure_binding_inspection\": \"enabled\"," \
            "  \"resources\": []," \
            "  \"scheduled_slots\": []," \
            "  \"binding_inspections\": []," \
            "  \"bindings\": []," \
            "  \"providers\": []," \
            "  \"steps\": []," \
            "  \"state\": \"ready\"," \
            "  \"warnings\": []" \
            "}"
          return
        fi
        printf '%s\n' \
          "{" \
          "  \"schema_version\": \"1\"," \
          "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
          "  \"source_format\": \"direct-selection\"," \
          "  \"azure_binding_inspection\": \"skipped\"," \
          "  \"resources\": [{\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"provider\":\"azure-cognitive-services\"}]," \
          "  \"scheduled_slots\": [{\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"key_slot\":\"Key1\",\"input_selectors\":[]}]," \
          "  \"binding_inspections\": []," \
          "  \"bindings\": []," \
          "  \"providers\": [{\"name\":\"azure-cognitive-services\"}]," \
          "  \"steps\": [{\"sequence\":1,\"action\":\"regenerate-key\",\"phase\":\"rotate\",\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"key_slot\":\"Key1\",\"binding_id\":null}]," \
          "  \"state\": \"confirmation-required\"," \
          "  \"warnings\": [{\"code\":\"azure-binding-inspection-skipped\",\"impact\":\"confirmation\",\"category\":\"credential-binding\"}]" \
          "}"
        return
      fi
      managed_env="$(option_value --sops-file "$@")"
      has_option --json "$@" || exit 2
      write_sops_plan "$managed_env"
      ;;
    export)
      if [[ "$MODE" == "export-cancel" ]]; then
        printf 'Fake export cancelled.\n'
        return
      fi
      mapfile -t selections < <(option_values --select "$@")
      if has_option --key-map "$@"; then
        key_map="$(option_value --key-map "$@")"
        destination="$(option_value --sops-out "$@")"
        [[ -f "$key_map" && ! -L "$key_map" ]] || exit 2
        ciphertext_temp="$(mktemp "${destination%/*}/.fake-sops.XXXXXXXX")"
        render_mapped_env "before" \
          | "$SOPS_BIN" encrypt \
            --filename-override "$destination" \
            --input-type dotenv \
            --output-type dotenv \
            >"$ciphertext_temp"
        mv -f -- "$ciphertext_temp" "$destination"
        chmod 600 "$destination"
      elif [[ "${#selections[@]}" -eq 1 && "${selections[0]}" == "$FOUNDRY_ACCOUNT_ID#Key1" ]]; then
        destination="$(option_value --out "$@")"
        write_foundry_snapshot "$destination"
      else
        destination="$(option_value --sops-out "$@")"
        [[ "${#selections[@]}" -eq 3 ]] || exit 2
        [[ "${selections[0]}" == "$STORAGE_ACCOUNT_ID#key1" ]] || exit 2
        [[ "${selections[1]}" == "$STORAGE_ACCOUNT_ID#key2" ]] || exit 2
        [[ "${selections[2]}" == "$OPENAI_ACCOUNT_ID#Key1" ]] || exit 2
        ciphertext_temp="$(mktemp "${destination%/*}/.fake-sops.XXXXXXXX")"
        render_managed_env "before" \
          | "$SOPS_BIN" encrypt \
            --filename-override "$destination" \
            --input-type dotenv \
            --output-type dotenv \
            >"$ciphertext_temp"
        mv -f -- "$ciphertext_temp" "$destination"
        chmod 600 "$destination"
      fi
      printf 'Fake private dotenv export created.\n'
      ;;
    rotate)
      if has_option --skip-azure-bindings "$@"; then
        selection="$(option_value --select "$@")"
        [[ "$selection" == "$FOUNDRY_ACCOUNT_ID#Key1" ]] || exit 2
        if [[ "$MODE" == "skip-rotate-cancel" ]]; then
          printf 'Fake skipped-binding rotation cancelled.\n'
          return
        fi
        if [[ "$MODE" == "skip-rotate-fail" ]]; then
          printf 'Fake secret-free skipped-binding rotation failure.\n' >&2
          return 42
        fi
        : >"$TEST_ROOT/skip-key-rotated"
        printf 'Fake skipped-binding rotation completed.\n'
        return
      fi
      managed_env="$(option_value --sops-file "$@")"
      if [[ "$MODE" == "rotate-cancel" ]]; then
        printf 'Fake rotation cancelled.\n'
        return
      fi
      if [[ "$MODE" == "same-inode-update" ]]; then
        update_managed_sops "$managed_env" "after" true
      else
        update_managed_sops "$managed_env" "after" false
      fi
      if [[ "$MODE" == "rotate-fail" ]]; then
        printf 'Fake secret-free rotation failure.\n' >&2
        return 42
      fi
      printf 'Fake rotation completed.\n'
      ;;
    match)
      if has_option --skip-azure-bindings "$@"; then
        if [[ -e "$TEST_ROOT/skip-key-rotated" ]]; then
          printf '%s\n' \
            "{" \
            "  \"schema_version\": \"1\"," \
            "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
            "  \"azure_binding_inspection\": \"skipped\"," \
            "  \"providers\": [{\"name\":\"azure-cognitive-services\"},{\"name\":\"local-dotenv-file\"}]," \
            "  \"matches\": []," \
            "  \"binding_inspections\": []," \
            "  \"bindings\": []" \
            "}"
        else
          printf '%s\n' \
            "{" \
            "  \"schema_version\": \"1\"," \
            "  \"subscription_id\": \"$SUBSCRIPTION_ID\"," \
            "  \"azure_binding_inspection\": \"skipped\"," \
            "  \"providers\": [{\"name\":\"azure-cognitive-services\"},{\"name\":\"local-dotenv-file\"}]," \
            "  \"matches\": [{\"input_selector\":\"FOUNDRY\",\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"key_slot\":\"Key1\"}]," \
            "  \"binding_inspections\": [{\"provider\":\"local-dotenv-file\",\"location\":\"local\",\"resource_id\":\"$FOUNDRY_ACCOUNT_ID\"}]," \
            "  \"bindings\": [{\"provider\":\"local-dotenv-file\",\"location\":\"local\",\"management\":\"update-and-verify\",\"key_resource_id\":\"$FOUNDRY_ACCOUNT_ID\",\"key_slot\":\"Key1\"}]" \
            "}"
        fi
        return
      fi
      managed_env="$(option_value --sops-file "$@")"
      if has_option --key-map-out "$@"; then
        destination="$(option_value --key-map-out "$@")"
        write_key_map "$destination"
        printf 'Fake reusable key map created.\n'
        return
      fi
      write_sops_match_report "$managed_env"
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
