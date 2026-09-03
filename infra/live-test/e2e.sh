#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# The shared guard is checked separately.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scope.sh"

readonly RESOURCE_GROUP_NAME="rg-azurator-live-test"
readonly EXPECTED_FIXTURE_TAG="live-test"
readonly EXPECTED_OWNER_TAG="azurator-repository"
readonly STORAGE_RESOURCE_TYPE="microsoft.storage/storageaccounts"
readonly COGNITIVE_RESOURCE_TYPE="microsoft.cognitiveservices/accounts"
readonly APP_SERVICE_RESOURCE_TYPE="microsoft.web/sites"
readonly ROTATION_STORAGE_ROLE="rotation-storage"
readonly DISABLED_STORAGE_ROLE="disabled-storage"
readonly FOUNDRY_PROJECT_HOST_ROLE="foundry-project-host"
readonly DISABLED_FOUNDRY_ROLE="disabled-foundry"
readonly ROTATION_OPENAI_ROLE="rotation-openai"
readonly APP_SERVICE_SETTINGS_ROLE="app-service-settings"

readonly BASH_BIN="${AZURATOR_LIVE_TEST_BASH:?AZURATOR_LIVE_TEST_BASH is required}"
readonly AZ_BIN="${AZURATOR_LIVE_TEST_AZ:?AZURATOR_LIVE_TEST_AZ is required}"
readonly AGE_KEYGEN_BIN="${AZURATOR_LIVE_TEST_AGE_KEYGEN:?AZURATOR_LIVE_TEST_AGE_KEYGEN is required}"
readonly JQ_BIN="${AZURATOR_LIVE_TEST_JQ:?AZURATOR_LIVE_TEST_JQ is required}"
readonly SOPS_BIN="${AZURATOR_LIVE_TEST_SOPS:?AZURATOR_LIVE_TEST_SOPS is required}"
readonly AZURATOR_BIN="${AZURATOR_LIVE_TEST_AZURATOR:?AZURATOR_LIVE_TEST_AZURATOR is required}"
readonly LIFECYCLE_SCRIPT="${AZURATOR_LIVE_TEST_LIFECYCLE:?AZURATOR_LIVE_TEST_LIFECYCLE is required}"

readonly STORAGE_LOCAL_ALIAS="AZURATOR_STORAGE_LOCAL_ALIAS"
readonly STORAGE_SECONDARY_LOCAL_ALIAS="AZURATOR_STORAGE_SECONDARY_LOCAL_ALIAS"
readonly OPENAI_LOCAL_ALIAS="AZURATOR_OPENAI_LOCAL_ALIAS"
readonly UNRELATED_LOCAL_SELECTOR="AZURATOR_UNRELATED"
readonly EMPTY_LOCAL_SELECTOR="AZURATOR_EMPTY"

E2E_WORKSPACE=""
FIXTURE_CREATED=false
ROTATION_ATTEMPTED=false
ROTATION_VERIFIED=false
WORKFLOW_COMPLETED=false

usage() {
  printf 'Usage: %s [--reuse-fixture]\n' "${0##*/}" >&2
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

require_executable() {
  [[ -x "$1" ]] || fail "$2 is unavailable"
}

require_runtime() {
  local sops_version
  require_executable "$BASH_BIN" "Bash"
  require_executable "$AZ_BIN" "Azure CLI"
  require_executable "$AGE_KEYGEN_BIN" "age-keygen"
  require_executable "$JQ_BIN" "jq"
  require_executable "$SOPS_BIN" "SOPS"
  require_executable "$AZURATOR_BIN" "Azurator"
  [[ -f "$LIFECYCLE_SCRIPT" && ! -L "$LIFECYCLE_SCRIPT" ]] \
    || fail "the reviewed live-test lifecycle script is unavailable"
  if ! sops_version="$("$SOPS_BIN" --disable-version-check --version 2>/dev/null)"; then
    fail "SOPS version detection failed"
  fi
  [[ "$sops_version" =~ ^sops\ 3\.13\.[0-9]+$ ]] \
    || fail "the reviewed live-test workflow requires SOPS 3.13.x"
}

run_lifecycle() {
  "$BASH_BIN" "$LIFECYCLE_SCRIPT" "$1"
}

sops_selector_path() {
  # jq variable, not a shell variable, is intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -cn --arg selector "$1" '[$selector]'
}

copy_sops_assignment() {
  local source_selector="$1"
  local destination_selector="$2"
  local path="$3"
  local source_path destination_path
  source_path="$(sops_selector_path "$source_selector")"
  destination_path="$(sops_selector_path "$destination_selector")"
  "$SOPS_BIN" decrypt \
    --input-type dotenv \
    --output-type json \
    --extract "$source_path" \
    "$path" \
    | "$JQ_BIN" -Rs . \
    | "$SOPS_BIN" set \
      --input-type dotenv \
      --output-type dotenv \
      --value-stdin \
      "$path" \
      "$destination_path" \
      >/dev/null
}

set_public_sops_assignment() {
  local selector="$1"
  local json_value="$2"
  local path="$3"
  local selector_path
  selector_path="$(sops_selector_path "$selector")"
  printf '%s' "$json_value" \
    | "$SOPS_BIN" set \
      --input-type dotenv \
      --output-type dotenv \
      --value-stdin \
      "$path" \
      "$selector_path" \
      >/dev/null
}

validate_sops_document() {
  local path="$1"
  local storage_selector="$2"
  local storage_secondary_selector="$3"
  local openai_selector="$4"
  local status_json
  status_json="$("$SOPS_BIN" filestatus --input-type dotenv "$path")"
  "$JQ_BIN" -e '. == {"encrypted": true}' >/dev/null <<<"$status_json" \
    || fail "the managed file did not satisfy the SOPS-encrypted dotenv contract"

  # jq receives decrypted values only through the pipe and emits nothing.
  # shellcheck disable=SC2016
  if ! "$SOPS_BIN" decrypt --input-type dotenv --output-type json "$path" \
    | "$JQ_BIN" -e \
      --arg storage "$storage_selector" \
      --arg storage_alias "$STORAGE_LOCAL_ALIAS" \
      --arg storage_secondary "$storage_secondary_selector" \
      --arg storage_secondary_alias "$STORAGE_SECONDARY_LOCAL_ALIAS" \
      --arg openai "$openai_selector" \
      --arg openai_alias "$OPENAI_LOCAL_ALIAS" \
      --arg unrelated "$UNRELATED_LOCAL_SELECTOR" \
      --arg empty "$EMPTY_LOCAL_SELECTOR" \
      '
        (keys | sort) == (
          [
            $storage,
            $storage_alias,
            $storage_secondary,
            $storage_secondary_alias,
            $openai,
            $openai_alias,
            $unrelated,
            $empty
          ]
          | sort
        )
        and (.[$storage] | type == "string" and length > 0)
        and .[$storage_alias] == .[$storage]
        and (.[$storage_secondary] | type == "string" and length > 0)
        and .[$storage_secondary_alias] == .[$storage_secondary]
        and (.[$openai] | type == "string" and length > 0)
        and .[$openai_alias] == .[$openai]
        and .[$unrelated] == "preserve-me"
        and .[$empty] == ""
      ' >/dev/null; then
    fail "the managed SOPS dotenv file did not preserve its exact alias and unrelated-value contract"
  fi
}

validate_key_map() {
  local path="$1"
  local storage_selector="$2"
  local storage_secondary_selector="$3"
  local openai_selector="$4"

  [[ -f "$path" && ! -L "$path" && "$(stat -c '%a' "$path")" == "600" ]] \
    || fail "the reusable key map did not satisfy the private regular-file contract"

  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg storage "$storage_selector" \
    --arg storage_alias "$STORAGE_LOCAL_ALIAS" \
    --arg storage_secondary "$storage_secondary_selector" \
    --arg storage_secondary_alias "$STORAGE_SECONDARY_LOCAL_ALIAS" \
    --arg openai "$openai_selector" \
    --arg openai_alias "$OPENAI_LOCAL_ALIAS" \
    '
      (keys | sort) == ["mappings", "schema_version", "subscription_id"]
      and .schema_version == "1"
      and .subscription_id == $subscription_id
      and (.mappings | sort_by(.selector)) == (
        [
          {selector: $storage, key_resource_id: $storage_id, key_slot: "key1"},
          {selector: $storage_secondary, key_resource_id: $storage_id, key_slot: "key2"},
          {selector: $openai, key_resource_id: $openai_id, key_slot: "Key1"},
          {selector: $storage_alias, key_resource_id: $storage_id, key_slot: "key1"},
          {selector: $storage_secondary_alias, key_resource_id: $storage_id, key_slot: "key2"},
          {selector: $openai_alias, key_resource_id: $openai_id, key_slot: "Key1"}
        ]
        | sort_by(.selector)
      )
    ' "$path" >/dev/null; then
    fail "the reusable key map did not preserve the exact matched selectors and slots"
  fi
}

validate_mapped_sops_document() {
  local path="$1"
  local storage_selector="$2"
  local storage_secondary_selector="$3"
  local openai_selector="$4"
  local status_json
  status_json="$("$SOPS_BIN" filestatus --input-type dotenv "$path")"
  "$JQ_BIN" -e '. == {"encrypted": true}' >/dev/null <<<"$status_json" \
    || fail "the key-map export did not satisfy the SOPS-encrypted dotenv contract"

  # jq receives decrypted values only through the pipe and emits nothing.
  # shellcheck disable=SC2016
  if ! "$SOPS_BIN" decrypt --input-type dotenv --output-type json "$path" \
    | "$JQ_BIN" -e \
      --arg storage "$storage_selector" \
      --arg storage_alias "$STORAGE_LOCAL_ALIAS" \
      --arg storage_secondary "$storage_secondary_selector" \
      --arg storage_secondary_alias "$STORAGE_SECONDARY_LOCAL_ALIAS" \
      --arg openai "$openai_selector" \
      --arg openai_alias "$OPENAI_LOCAL_ALIAS" \
      '
        (keys | sort) == (
          [
            $storage,
            $storage_alias,
            $storage_secondary,
            $storage_secondary_alias,
            $openai,
            $openai_alias
          ]
          | sort
        )
        and (.[$storage] | type == "string" and length > 0)
        and .[$storage_alias] == .[$storage]
        and (.[$storage_secondary] | type == "string" and length > 0)
        and .[$storage_secondary_alias] == .[$storage_secondary]
        and (.[$openai] | type == "string" and length > 0)
        and .[$openai_alias] == .[$openai]
      ' >/dev/null; then
    fail "the key-map SOPS export did not preserve its exact alias-only contract"
  fi
}

remove_workspace() {
  local workspace="$E2E_WORKSPACE"
  [[ -n "$workspace" ]] || return
  if [[ ! -d "$workspace" || -L "$workspace" ]]; then
    printf 'Warning: refusing to remove an unexpected E2E workspace path: %s\n' "$workspace" >&2
    return 1
  fi
  rm -rf -- "$workspace"
  E2E_WORKSPACE=""
}

handle_exit() {
  local status=$?
  trap - EXIT

  if [[ -n "$E2E_WORKSPACE" ]]; then
    if [[ "$ROTATION_ATTEMPTED" == true && "$ROTATION_VERIFIED" != true ]]; then
      printf '\nPreserved private E2E workspace after the incomplete rotation:\n  %s\n' "$E2E_WORKSPACE" >&2
      printf '%s\n' \
        'It contains the managed SOPS file and its private test identity that a retained operation may require.' \
        "Inspect recovery state with 'azurator operation list' before deleting it." >&2
    elif ! remove_workspace; then
      status=1
    fi
  fi

  if [[ "$status" -ne 0 && "$FIXTURE_CREATED" == true && "$WORKFLOW_COMPLETED" != true ]]; then
    printf '%s\n' \
      "The tagged $RESOURCE_GROUP_NAME fixture remains for diagnosis." \
      "When recovery is complete, remove it with 'nix run .#live-test-down'." >&2
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
  require_live_test_subscription_allowed "$SUBSCRIPTION_ID" || exit 1
  [[ "$AZURE_ENVIRONMENT" == "AzureCloud" ]] \
    || fail "the reviewed live-test workflow supports Azure public cloud only"
}

fixture_exists() {
  "$AZ_BIN" group exists \
    --name "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --only-show-errors
}

validate_reusable_fixture_group() {
  local expected_id group_json
  group_json="$(
    "$AZ_BIN" group show \
      --name "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --output json \
      --only-show-errors
  )"
  expected_id="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -e \
    --arg expected_id "${expected_id,,}" \
    --arg fixture "$EXPECTED_FIXTURE_TAG" \
    --arg owner "$EXPECTED_OWNER_TAG" \
    '
      (.id | ascii_downcase) == $expected_id
      and .tags["azurator-fixture"] == $fixture
      and .tags["azurator-owner"] == $owner
    ' >/dev/null <<<"$group_json" \
    || fail "the existing resource group did not satisfy the exact Azurator fixture identity"
}

validate_empty_operation_catalog() {
  local catalog_json
  catalog_json="$("$AZURATOR_BIN" operation list --json)"
  "$JQ_BIN" -e '
    .schema_version == "1"
    and .operations == []
    and .invalid_operation_ids == []
  ' >/dev/null <<<"$catalog_json" \
    || fail "an existing or invalid local recovery operation blocks fixture reuse"
}

select_fixture_resource_id() {
  local resources_json="$1"
  local resource_type="$2"
  local kind="$3"
  local role="$4"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -er \
    --arg resource_type "$resource_type" \
    --arg kind "$kind" \
    --arg role "$role" \
    --arg fixture "$EXPECTED_FIXTURE_TAG" \
    --arg owner "$EXPECTED_OWNER_TAG" \
    '
      [
        .[]
        | select((.type | ascii_downcase) == ($resource_type | ascii_downcase))
        | select(
            $kind == ""
            or (((.kind // "") | ascii_downcase) == ($kind | ascii_downcase))
          )
        | select(.tags["azurator-live-test-role"] == $role)
        | select(.tags["azurator-fixture"] == $fixture)
        | select(.tags["azurator-owner"] == $owner)
        | .id
      ]
      | if length == 1 and (.[0] | type) == "string" and (.[0] | length) > 0
        then .[0]
        else error("expected exactly one tagged fixture resource")
        end
    ' <<<"$resources_json"
}

load_fixture_resources() {
  local resources_json
  resources_json="$(
    "$AZ_BIN" resource list \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --output json \
      --only-show-errors
  )"

  if ! STORAGE_ACCOUNT_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$STORAGE_RESOURCE_TYPE" "" "$ROTATION_STORAGE_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged rotation Storage Account"
  fi
  STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_ID##*/}"
  [[ "$STORAGE_ACCOUNT_NAME" =~ ^[a-z0-9]{3,24}$ ]] \
    || fail "the tagged rotation Storage Account had an invalid name"
  if ! DISABLED_STORAGE_ACCOUNT_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$STORAGE_RESOURCE_TYPE" "" "$DISABLED_STORAGE_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged key-authentication-disabled Storage Account"
  fi
  if ! OPENAI_ACCOUNT_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$COGNITIVE_RESOURCE_TYPE" "OpenAI" "$ROTATION_OPENAI_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged Azure OpenAI account"
  fi
  if ! FOUNDRY_ACCOUNT_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$COGNITIVE_RESOURCE_TYPE" "AIServices" "$FOUNDRY_PROJECT_HOST_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged key-authentication-enabled Foundry account"
  fi
  if ! DISABLED_FOUNDRY_ACCOUNT_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$COGNITIVE_RESOURCE_TYPE" "AIServices" "$DISABLED_FOUNDRY_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged key-authentication-disabled Foundry account"
  fi
  if ! APP_SERVICE_ID="$(
    select_fixture_resource_id \
      "$resources_json" "$APP_SERVICE_RESOURCE_TYPE" "" "$APP_SERVICE_SETTINGS_ROLE" 2>/dev/null
  )"; then
    fail "the fixture did not contain exactly one tagged App Service settings app"
  fi
  APP_SERVICE_NAME="${APP_SERVICE_ID##*/}"
  [[ "$APP_SERVICE_NAME" =~ ^[A-Za-z0-9-]+$ ]] \
    || fail "the tagged App Service app had an invalid name"

  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg group_name "$RESOURCE_GROUP_NAME" \
    --arg fixture "$EXPECTED_FIXTURE_TAG" \
    --arg owner "$EXPECTED_OWNER_TAG" \
    --arg foundry_id "$FOUNDRY_ACCOUNT_ID" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      def exact_type_role($type; $role):
        [
          .[]
          | select((.type | ascii_downcase) == ($type | ascii_downcase))
          | select(.tags["azurator-live-test-role"] == $role)
        ]
        | length == 1;

      length == 8
      and all(
        .[];
        (.id | ascii_downcase | startswith(
          "/subscriptions/" + ($subscription_id | ascii_downcase)
          + "/resourcegroups/" + ($group_name | ascii_downcase) + "/providers/"
        ))
        and .tags["azurator-fixture"] == $fixture
        and .tags["azurator-owner"] == $owner
      )
      and exact_type_role("Microsoft.Storage/storageAccounts"; "rotation-storage")
      and exact_type_role("Microsoft.Storage/storageAccounts"; "disabled-storage")
      and exact_type_role("Microsoft.CognitiveServices/accounts"; "foundry-project-host")
      and exact_type_role("Microsoft.CognitiveServices/accounts"; "disabled-foundry")
      and exact_type_role("Microsoft.CognitiveServices/accounts"; "rotation-openai")
      and exact_type_role("Microsoft.Web/serverFarms"; "app-service-settings")
      and exact_type_role("Microsoft.Web/sites"; "app-service-settings")
      and (
        [
          .[]
          | select(
              (.type | ascii_downcase)
              == "microsoft.cognitiveservices/accounts/projects"
            )
          | select(.id | ascii_downcase | startswith(($foundry_id | ascii_downcase) + "/projects/"))
          | select((.tags["azurator-live-test-role"] // null) == null)
        ]
        | length == 1
      )
    ' >/dev/null <<<"$resources_json" \
    || fail "the fixture did not satisfy the exact tagged eight-resource matrix"
}

validate_discovery_report() {
  local report_json="$1"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg disabled_storage_id "$DISABLED_STORAGE_ACCOUNT_ID" \
    --arg foundry_id "$FOUNDRY_ACCOUNT_ID" \
    --arg disabled_foundry_id "$DISABLED_FOUNDRY_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg storage_type "$STORAGE_RESOURCE_TYPE" \
    --arg cognitive_type "$COGNITIVE_RESOURCE_TYPE" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      def exact_resource($id; $resource_type; $kind; $provider; $key_authentication):
        ([.resources[] | select(.resource_id | same_id($id))] | length == 1)
        and (
          [
            .resources[]
            | select(.resource_id | same_id($id))
            | select((.resource_type | ascii_downcase) == ($resource_type | ascii_downcase))
            | select(((.kind // "") | ascii_downcase) == ($kind | ascii_downcase))
            | select(.provider == $provider)
            | select(.key_authentication == $key_authentication)
          ]
          | length == 1
        );
      def exact_slot($id; $slot; $available):
        [
          .resources[]
          | select(.resource_id | same_id($id))
          | .key_slots[]
          | select(.name == $slot)
          | select(.values_retrievable == $available)
          | select(.rotatable == $available)
        ]
        | length == 1;
      def exact_pair($id; $first; $second; $available):
        ([.resources[] | select(.resource_id | same_id($id)) | .key_slots[]] | length == 2)
        and exact_slot($id; $first; $available)
        and exact_slot($id; $second; $available);

      .schema_version == "1"
      and .subscription_id == $subscription_id
      and (.resources | type) == "array"
      and exact_resource($storage_id; $storage_type; "StorageV2"; "azure-storage"; "enabled")
      and exact_pair($storage_id; "key1"; "key2"; true)
      and exact_resource($disabled_storage_id; $storage_type; "StorageV2"; "azure-storage"; "disabled")
      and exact_pair($disabled_storage_id; "key1"; "key2"; false)
      and exact_resource($foundry_id; $cognitive_type; "AIServices"; "azure-cognitive-services"; "enabled")
      and exact_pair($foundry_id; "Key1"; "Key2"; true)
      and exact_resource(
        $disabled_foundry_id;
        $cognitive_type;
        "AIServices";
        "azure-cognitive-services";
        "disabled"
      )
      and exact_pair($disabled_foundry_id; "Key1"; "Key2"; false)
      and exact_resource($openai_id; $cognitive_type; "OpenAI"; "azure-cognitive-services"; "enabled")
      and exact_pair($openai_id; "Key1"; "Key2"; true)
    ' >/dev/null 2>&1 <<<"$report_json"; then
    fail "metadata discovery did not confirm the complete enabled/disabled fixture key-authentication matrix"
  fi
}

validate_skipped_binding_plan() {
  local report_json="$1"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg foundry_id "$FOUNDRY_ACCOUNT_ID" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));

      .schema_version == "1"
      and .subscription_id == $subscription_id
      and .source_format == "direct-selection"
      and .azure_binding_inspection == "skipped"
      and (.resources | length) == 1
      and (.resources[0].resource_id | same_id($foundry_id))
      and .resources[0].provider == "azure-cognitive-services"
      and (.scheduled_slots | length) == 1
      and (.scheduled_slots[0].resource_id | same_id($foundry_id))
      and .scheduled_slots[0].key_slot == "Key1"
      and .scheduled_slots[0].input_selectors == []
      and .binding_inspections == []
      and .bindings == []
      and ([.providers[] | select(.name == "azure-foundry-connections")] | length) == 0
      and ([.providers[] | select(.name == "azure-app-service-settings")] | length) == 0
      and (.steps | length) == 1
      and .steps[0].action == "regenerate-key"
      and .steps[0].phase == "rotate"
      and (.steps[0].resource_id | same_id($foundry_id))
      and .steps[0].key_slot == "Key1"
      and .steps[0].binding_id == null
      and .state == "confirmation-required"
      and (
        [
          .warnings[]
          | select(.code == "azure-binding-inspection-skipped")
          | select(.impact == "confirmation")
          | select(.category == "credential-binding")
        ]
        | length == 1
      )
    ' >/dev/null 2>&1 <<<"$report_json"; then
    fail "the direct plan did not satisfy the skipped Azure-binding inspection contract"
  fi
}

classify_skipped_binding_rotation() {
  local report_json="$1"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  "$JQ_BIN" -er \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg foundry_id "$FOUNDRY_ACCOUNT_ID" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      def exact_old_match:
        [
          .matches[]
          | select((.resource_id | same_id($foundry_id)) and .key_slot == "Key1")
        ]
        | length == 1;
      def exact_local_binding:
        [
          .bindings[]
          | select(.provider == "local-dotenv-file")
          | select(.location == "local")
          | select(.management == "update-and-verify")
          | select((.key_resource_id | same_id($foundry_id)) and .key_slot == "Key1")
        ]
        | length == 1;
      def exact_local_inspection:
        [
          .binding_inspections[]
          | select(.provider == "local-dotenv-file")
          | select(.location == "local")
          | select(.resource_id | same_id($foundry_id))
        ]
        | length == 1;
      def base_contract:
        .schema_version == "1"
        and .subscription_id == $subscription_id
        and .azure_binding_inspection == "skipped"
        and ([.providers[] | select(.name == "azure-foundry-connections")] | length) == 0
        and ([.providers[] | select(.name == "azure-app-service-settings")] | length) == 0
        and ([.binding_inspections[] | select(.location == "azure")] | length) == 0
        and ([.bindings[] | select(.location == "azure")] | length) == 0;

      if (base_contract | not) then
        error("invalid skipped-binding match contract")
      elif (.matches == [] and .binding_inspections == [] and .bindings == []) then
        "rotated"
      elif (
        (.matches | length) == 1
        and (.binding_inspections | length) == 1
        and (.bindings | length) == 1
        and exact_old_match
        and exact_local_inspection
        and exact_local_binding
      ) then
        "unchanged"
      else
        error("the pre-rotation key matched an unexpected resource, slot, or binding")
      end
    ' <<<"$report_json"
}

validate_sops_match_report() {
  local report_json="$1"
  local sops_path="$2"
  local storage_selector="$3"
  local storage_secondary_selector="$4"
  local openai_selector="$5"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg app_service_id "$APP_SERVICE_ID" \
    --arg sops_path "$sops_path" \
    --arg storage_selector "$storage_selector" \
    --arg storage_alias "$STORAGE_LOCAL_ALIAS" \
    --arg storage_secondary_selector "$storage_secondary_selector" \
    --arg storage_secondary_alias "$STORAGE_SECONDARY_LOCAL_ALIAS" \
    --arg openai_selector "$openai_selector" \
    --arg openai_alias "$OPENAI_LOCAL_ALIAS" \
    --arg unrelated "$UNRELATED_LOCAL_SELECTOR" \
    --arg empty "$EMPTY_LOCAL_SELECTOR" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      def same_strings($actual; $expected):
        ($actual | sort) == ($expected | sort);
      def exact_match($selector; $resource_id; $slot):
        [
          .matches[]
          | select(.input_selector == $selector)
          | select((.resource_id | same_id($resource_id)) and .key_slot == $slot)
        ]
        | length == 1;
      def exact_binding($provider; $location; $resource_id; $slot):
        [
          .bindings[]
          | select(.provider == $provider)
          | select(.location == $location)
          | select(.management == "update-and-verify")
          | select(.key_resource_id | same_id($resource_id))
          | select(.key_slot == $slot)
        ]
        | length == 1;
      def exact_inspection($provider; $location; $resource_id):
        [
          .binding_inspections[]
          | select(.provider == $provider)
          | select(.location == $location)
          | select(.resource_id | same_id($resource_id))
          | select(.status == "inspected")
        ]
        | length == 1;

      .schema_version == "1"
      and .subscription_id == $subscription_id
      and .azure_binding_inspection == "enabled"
      and same_strings(
        .input_selectors;
        [
          $storage_selector,
          $storage_secondary_selector,
          $openai_selector,
          $storage_alias,
          $storage_secondary_alias,
          $openai_alias,
          $unrelated
        ]
      )
      and .skipped_empty_selectors == [$empty]
      and (.matches | length == 6)
      and (.bindings | length == 7)
      and (.binding_inspections | length == 6)
      and exact_match($storage_selector; $storage_id; "key1")
      and exact_match($storage_alias; $storage_id; "key1")
      and exact_match($storage_secondary_selector; $storage_id; "key2")
      and exact_match($storage_secondary_alias; $storage_id; "key2")
      and exact_match($openai_selector; $openai_id; "Key1")
      and exact_match($openai_alias; $openai_id; "Key1")
      and exact_inspection("azure-foundry-connections"; "azure"; $storage_id)
      and exact_inspection("azure-foundry-connections"; "azure"; $openai_id)
      and exact_inspection("azure-app-service-settings"; "azure"; $storage_id)
      and exact_inspection("azure-app-service-settings"; "azure"; $openai_id)
      and exact_inspection("local-sops-dotenv-file"; "local"; $storage_id)
      and exact_inspection("local-sops-dotenv-file"; "local"; $openai_id)
      and exact_binding("azure-foundry-connections"; "azure"; $storage_id; "key1")
      and exact_binding("azure-foundry-connections"; "azure"; $openai_id; "Key1")
      and (
        [
          .bindings[]
          | select(.provider == "azure-app-service-settings")
          | select(.location == "azure")
          | select(.management == "update-and-verify")
          | select(.scope_id | same_id($app_service_id))
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
          | select(.selectors == ["AZURATOR_STORAGE_ALIAS", "AZURATOR_STORAGE_CONNECTION", "AZURATOR_STORAGE_KEY"])
        ]
        | length == 1
      )
      and (
        [
          .bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.management == "update-and-verify")
          | select(.binding_type == "local/sops-dotenv-file")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key2")
          | select(.selectors == [$storage_secondary_selector, $storage_secondary_alias])
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
          | select(.key_resource_id | same_id($openai_id))
          | select(.key_slot == "Key1")
          | select(.selectors == ["AZURATOR_OPENAI_KEY"])
        ]
        | length == 1
      )
      and (
        [
          .bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.management == "update-and-verify")
          | select(.binding_type == "local/sops-dotenv-file")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
          | select(.selectors == [$storage_selector, $storage_alias])
        ]
        | length == 1
      )
      and (
        [
          .bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.management == "update-and-verify")
          | select(.binding_type == "local/sops-dotenv-file")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($openai_id))
          | select(.key_slot == "Key1")
          | select(.selectors == [$openai_selector, $openai_alias])
        ]
        | length == 1
      )
      and ([.providers[] | select(.name == "local-sops-dotenv-file")] | length == 1)
      and ([.providers[] | select(.name == "local-dotenv-file")] | length == 0)
      and (
        [
          .warnings[]
          | select(.code == "sops-file-managed-update")
          | select(.impact == "advisory")
          | select(.category == "persistence")
          | select(.provider == "local-sops-dotenv-file")
        ]
        | length == 1
      )
    ' >/dev/null 2>&1 <<<"$report_json"; then
    fail "SOPS matching did not confirm the exact aliases and managed Azure binding records"
  fi
}

validate_sops_plan() {
  local report_json="$1"
  local sops_path="$2"
  local storage_selector="$3"
  local storage_secondary_selector="$4"
  local openai_selector="$5"
  # jq variables, not shell variables, are intentionally expanded here.
  # shellcheck disable=SC2016
  if ! "$JQ_BIN" -e \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg storage_id "$STORAGE_ACCOUNT_ID" \
    --arg openai_id "$OPENAI_ACCOUNT_ID" \
    --arg sops_path "$sops_path" \
    --arg storage_selector "$storage_selector" \
    --arg storage_alias "$STORAGE_LOCAL_ALIAS" \
    --arg storage_secondary_selector "$storage_secondary_selector" \
    --arg storage_secondary_alias "$STORAGE_SECONDARY_LOCAL_ALIAS" \
    --arg openai_selector "$openai_selector" \
    --arg openai_alias "$OPENAI_LOCAL_ALIAS" \
    --arg unrelated "$UNRELATED_LOCAL_SELECTOR" \
    --arg empty "$EMPTY_LOCAL_SELECTOR" \
    '
      def same_id($expected):
        (type == "string") and ((ascii_downcase) == ($expected | ascii_downcase));
      def same_strings($actual; $expected):
        ($actual | sort) == ($expected | sort);
      def exact_step($steps; $action; $phase; $resource_id; $slot; $binding_id):
        [
          $steps[]
          | select(.action == $action)
          | select(.phase == $phase)
          | select(.resource_id | same_id($resource_id))
          | select(.key_slot == $slot)
          | select(.binding_id == $binding_id)
        ]
        | length == 1;
      def transition_steps($resource_id; $slot; $phase; $binding_ids):
        [
          $binding_ids[] as $binding_id
          | {
              action: "update-binding",
              phase: $phase,
              resource_id: ($resource_id | ascii_downcase),
              key_slot: $slot,
              binding_id: $binding_id
            },
            {
              action: "verify-binding",
              phase: $phase,
              resource_id: ($resource_id | ascii_downcase),
              key_slot: $slot,
              binding_id: $binding_id
            }
        ];
      def managed_binding_ids($bindings; $resource_id; $slot):
        [
          $bindings[]
          | select(.key_resource_id | same_id($resource_id))
          | select(.key_slot == $slot)
          | select(.management == "update-and-verify")
          | .binding_id
        ];
      def managed_binding_ids_for_slots($bindings; $resource_id; $first_slot; $second_slot):
        [
          $bindings[]
          | select(.key_resource_id | same_id($resource_id))
          | select(.key_slot == $first_slot or .key_slot == $second_slot)
          | select(.management == "update-and-verify")
          | .binding_id
        ];
      def expected_one_slot_steps($bindings; $resource_id; $selected_slot; $bridge_slot):
        managed_binding_ids($bindings; $resource_id; $selected_slot) as $affected
        | transition_steps($resource_id; $bridge_slot; "bridge"; $affected)
          + [
              {
                action: "regenerate-key",
                phase: "rotate",
                resource_id: ($resource_id | ascii_downcase),
                key_slot: $selected_slot,
                binding_id: null
              }
            ]
          + transition_steps($resource_id; $selected_slot; "finalize"; $affected);
      def expected_two_slot_steps($bindings; $resource_id; $primary_slot; $bridge_slot):
        managed_binding_ids($bindings; $resource_id; $primary_slot) as $primary_bindings
        | managed_binding_ids($bindings; $resource_id; $bridge_slot) as $bridge_bindings
        | managed_binding_ids_for_slots(
            $bindings;
            $resource_id;
            $primary_slot;
            $bridge_slot
          ) as $all_bindings
        | transition_steps($resource_id; $bridge_slot; "bridge"; $primary_bindings)
          + [
              {
                action: "regenerate-key",
                phase: "rotate",
                resource_id: ($resource_id | ascii_downcase),
                key_slot: $primary_slot,
                binding_id: null
              }
            ]
          + transition_steps(
              $resource_id;
              $primary_slot;
              "finalize";
              $all_bindings
            )
          + [
              {
                action: "regenerate-key",
                phase: "rotate",
                resource_id: ($resource_id | ascii_downcase),
                key_slot: $bridge_slot,
                binding_id: null
              }
            ]
          + transition_steps($resource_id; $bridge_slot; "finalize"; $bridge_bindings);
      def normalized_steps($steps):
        [
          $steps[]
          | {
              action,
              phase,
              resource_id: (.resource_id | ascii_downcase),
              key_slot,
              binding_id
            }
        ];
      def expected_plan_steps($bindings; $resources; $storage_id; $openai_id):
        [
          $resources[].resource_id as $resource_id
          | if ($resource_id | same_id($storage_id))
            then expected_two_slot_steps($bindings; $resource_id; "key1"; "key2")[]
            elif ($resource_id | same_id($openai_id))
            then expected_one_slot_steps($bindings; $resource_id; "Key1"; "Key2")[]
            else error("unexpected resource in the reviewed live-test plan")
            end
        ];
      def exact_one_slot_steps($bindings; $steps; $resource_id; $selected_slot; $bridge_slot):
        [
          $bindings[]
          | select(.key_resource_id | same_id($resource_id))
          | select(.key_slot == $selected_slot)
          | select(.management == "update-and-verify")
        ] as $affected
        | ($affected | length) == 3
        and exact_step($steps; "regenerate-key"; "rotate"; $resource_id; $selected_slot; null)
        and all(
          $affected[];
          .binding_id as $binding_id
          | exact_step($steps; "update-binding"; "bridge"; $resource_id; $bridge_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "bridge"; $resource_id; $bridge_slot; $binding_id)
          and exact_step($steps; "update-binding"; "finalize"; $resource_id; $selected_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "finalize"; $resource_id; $selected_slot; $binding_id)
        );
      def exact_two_slot_steps($bindings; $steps; $resource_id; $primary_slot; $bridge_slot):
        [
          $bindings[]
          | select(.key_resource_id | same_id($resource_id))
          | select(.key_slot == $primary_slot)
          | select(.management == "update-and-verify")
        ] as $primary_bindings
        | [
            $bindings[]
            | select(.key_resource_id | same_id($resource_id))
            | select(.key_slot == $bridge_slot)
            | select(.management == "update-and-verify")
          ] as $bridge_bindings
        | ($primary_bindings | length) == 3
        and ($bridge_bindings | length) == 1
        and exact_step($steps; "regenerate-key"; "rotate"; $resource_id; $primary_slot; null)
        and exact_step($steps; "regenerate-key"; "rotate"; $resource_id; $bridge_slot; null)
        and all(
          $primary_bindings[];
          .binding_id as $binding_id
          | exact_step($steps; "update-binding"; "bridge"; $resource_id; $bridge_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "bridge"; $resource_id; $bridge_slot; $binding_id)
          and exact_step($steps; "update-binding"; "finalize"; $resource_id; $primary_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "finalize"; $resource_id; $primary_slot; $binding_id)
        )
        and all(
          $bridge_bindings[];
          .binding_id as $binding_id
          | exact_step($steps; "update-binding"; "finalize"; $resource_id; $primary_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "finalize"; $resource_id; $primary_slot; $binding_id)
          and exact_step($steps; "update-binding"; "finalize"; $resource_id; $bridge_slot; $binding_id)
          and exact_step($steps; "verify-binding"; "finalize"; $resource_id; $bridge_slot; $binding_id)
        );

      .bindings as $bindings
      | .steps as $steps
      | .schema_version == "1"
      and .subscription_id == $subscription_id
      and .source_format == "sops-dotenv-file"
      and .source_path == $sops_path
      and .azure_binding_inspection == "enabled"
      and same_strings(
        .source_selectors;
        [
          $storage_selector,
          $storage_secondary_selector,
          $openai_selector,
          $storage_alias,
          $storage_secondary_alias,
          $openai_alias,
          $unrelated
        ]
      )
      and .skipped_empty_selectors == [$empty]
      and (.resources | length) == 2
      and ([.resources[] | select(.resource_id | same_id($storage_id))] | length == 1)
      and ([.resources[] | select(.resource_id | same_id($openai_id))] | length == 1)
      and (.scheduled_slots | length) == 3
      and (
        [
          .scheduled_slots[]
          | select(.resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
          | select(.input_selectors == [$storage_selector, $storage_alias])
        ]
        | length == 1
      )
      and (
        [
          .scheduled_slots[]
          | select(.resource_id | same_id($storage_id))
          | select(.key_slot == "key2")
          | select(.input_selectors == [$storage_secondary_selector, $storage_secondary_alias])
        ]
        | length == 1
      )
      and (
        [
          .scheduled_slots[]
          | select(.resource_id | same_id($openai_id))
          | select(.key_slot == "Key1")
          | select(.input_selectors == [$openai_selector, $openai_alias])
        ]
        | length == 1
      )
      and ($bindings | length) == 7
      and (.binding_inspections | length) == 6
      and ([.providers[] | select(.name == "local-sops-dotenv-file")] | length == 1)
      and ([.providers[] | select(.name == "local-dotenv-file")] | length == 0)
      and (
        [
          $bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key1")
          | select(.selectors == [$storage_selector, $storage_alias])
        ]
        | length == 1
      )
      and (
        [
          $bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($storage_id))
          | select(.key_slot == "key2")
          | select(.selectors == [$storage_secondary_selector, $storage_secondary_alias])
        ]
        | length == 1
      )
      and (
        [
          $bindings[]
          | select(.provider == "local-sops-dotenv-file")
          | select(.location == "local")
          | select(.scope_id == $sops_path)
          | select(.key_resource_id | same_id($openai_id))
          | select(.key_slot == "Key1")
          | select(.selectors == [$openai_selector, $openai_alias])
        ]
        | length == 1
      )
      and ($steps | length) == 31
      and ([$steps[].sequence] == [range(1; 32)])
      and ([$steps[] | select(.action == "update-binding")] | length) == 14
      and ([$steps[] | select(.action == "verify-binding")] | length) == 14
      and ([$steps[] | select(.action == "regenerate-key")] | length) == 3
      and exact_two_slot_steps($bindings; $steps; $storage_id; "key1"; "key2")
      and exact_one_slot_steps($bindings; $steps; $openai_id; "Key1"; "Key2")
      and (
        normalized_steps($steps)
        == expected_plan_steps($bindings; .resources; $storage_id; $openai_id)
      )
      and .state == "confirmation-required"
      and ([.warnings[] | select(.impact == "blocking")] | length) == 0
      and (
        [
          .warnings[]
          | select(.code == "sops-file-managed-update")
          | select(.impact == "advisory")
          | select(.category == "persistence")
        ]
        | length == 1
      )
    ' >/dev/null 2>&1 <<<"$report_json"; then
    fail "the SOPS rotation plan did not satisfy the exact mixed one-slot and two-slot bridge contract"
  fi
}

verify_unrelated_app_setting() {
  local count
  count="$(
    "$AZ_BIN" webapp config appsettings list \
      --name "$APP_SERVICE_NAME" \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --query "[?name=='AZURATOR_UNRELATED' && value=='preserve-me'] | length(@)" \
      --output tsv \
      --only-show-errors
  )"
  [[ "$count" == "1" ]] \
    || fail "the unrelated App Service setting did not survive full-dictionary rotation updates"
}

verify_storage_connection_string_shape() {
  local count
  count="$(
    "$AZ_BIN" webapp config appsettings list \
      --name "$APP_SERVICE_NAME" \
      --resource-group "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --query "[?name=='AZURATOR_STORAGE_CONNECTION' && starts_with(value, 'DefaultEndpointsProtocol=https;AccountName=$STORAGE_ACCOUNT_NAME;AccountKey=') && ends_with(value, ';EndpointSuffix=core.windows.net')] | length(@)" \
      --output tsv \
      --only-show-errors
  )"
  [[ "$count" == "1" ]] \
    || fail "the App Service Storage connection string did not preserve its reviewed shape"
}

main() {
  local exists before_file_state after_file_state discovery_report_json match_report_json
  local age_identity age_recipient key_map managed_sops mapped_sops openai_selector plan_report_json
  local skip_match_report_json skip_plan_json skip_rotation_state skip_snapshot storage_selector
  local storage_secondary_selector
  local -a exported_selectors
  local reuse_fixture=false

  if [[ $# -eq 1 && "$1" == "--reuse-fixture" ]]; then
    reuse_fixture=true
  elif [[ $# -ne 0 ]]; then
    usage
    exit 2
  fi
  require_runtime
  load_live_test_subscription_allowlist || exit 1
  load_account_scope

  printf '%s\n' \
    'Guided Azurator live end-to-end test' \
    "Subscription: $SUBSCRIPTION_ID" \
    'This development workflow deploys the tagged provider matrix, validates enabled and' \
    'disabled key authentication, exercises skipped Azure-binding planning and rotation on' \
    'the unbound Foundry host key, then rotates both Storage slots plus Azure OpenAI Key1 and' \
    'SOPS aliases, Foundry connections, and App Service settings before offering teardown.' \
    'It does not invoke a model, upload Storage data, or test a workload.'

  "$AZURATOR_BIN" auth status --subscription "$SUBSCRIPTION_ID"
  if [[ "$reuse_fixture" == true ]]; then
    exists="$(fixture_exists)"
    [[ "$exists" == "true" ]] \
      || fail "--reuse-fixture requires the existing tagged Azurator test resource group"
    validate_reusable_fixture_group
    validate_empty_operation_catalog
    FIXTURE_CREATED=true
    load_fixture_resources
    printf 'Reusing the complete existing tagged fixture; deployment was not invoked.\n'
  else
    run_lifecycle up

    exists="$(fixture_exists)"
    [[ "$exists" == "true" || "$exists" == "false" ]] \
      || fail "Azure CLI returned an invalid resource-group existence result"
    if [[ "$exists" == "false" ]]; then
      printf 'Fixture deployment was cancelled; no end-to-end test was run.\n'
      WORKFLOW_COMPLETED=true
      return
    fi
    FIXTURE_CREATED=true
    load_fixture_resources
  fi
  printf '\nStep 1/7: metadata-only key-authentication matrix discovery\n'
  discovery_report_json="$(
    "$AZURATOR_BIN" discover \
      --subscription "$SUBSCRIPTION_ID" \
      --json
  )"
  validate_discovery_report "$discovery_report_json"
  discovery_report_json=""
  printf '%s\n' \
    'Verified enabled and disabled key-authentication resources for both reviewed resource providers.' \
    'Only explicitly tagged enabled accounts continue into key-returning or mutating commands.'

  printf '\nStep 2/7: structured skipped Azure-binding plan\n'
  skip_plan_json="$(
    "$AZURATOR_BIN" plan \
      --subscription "$SUBSCRIPTION_ID" \
      --select "$FOUNDRY_ACCOUNT_ID#Key1" \
      --skip-azure-bindings \
      --json
  )"
  validate_skipped_binding_plan "$skip_plan_json"
  skip_plan_json=""
  printf '%s\n' \
    'Verified that the plan selected only the unbound Foundry host Key1, omitted every Azure' \
    'binding provider and binding record, and required confirmation for that explicit gap.'

  E2E_WORKSPACE="$(mktemp -d -t azurator-live-test-e2e.XXXXXXXX)"
  chmod 700 "$E2E_WORKSPACE"
  skip_snapshot="$E2E_WORKSPACE/foundry-key-before.env"
  managed_sops="$E2E_WORKSPACE/managed.enc.env"
  key_map="$E2E_WORKSPACE/azurator.keys.json"
  mapped_sops="$E2E_WORKSPACE/recreated.enc.env"
  age_identity="$E2E_WORKSPACE/age-identity.txt"

  printf '\nStep 3/7: skipped Azure-binding rotation on the unbound Foundry host key\n'
  "$AZURATOR_BIN" export \
    --subscription "$SUBSCRIPTION_ID" \
    --select "$FOUNDRY_ACCOUNT_ID#Key1" \
    --out "$skip_snapshot"

  if [[ ! -f "$skip_snapshot" ]]; then
    printf 'Verification snapshot export was cancelled; no rotation was attempted.\n'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    return
  fi
  [[ ! -L "$skip_snapshot" && "$(stat -c '%a' "$skip_snapshot")" == "600" ]] \
    || fail "the pre-rotation verification snapshot did not satisfy the private mode-0600 contract"

  "$AZURATOR_BIN" rotate \
    --subscription "$SUBSCRIPTION_ID" \
    --select "$FOUNDRY_ACCOUNT_ID#Key1" \
    --skip-azure-bindings

  skip_match_report_json="$(
    "$AZURATOR_BIN" match \
      --subscription "$SUBSCRIPTION_ID" \
      --env-file "$skip_snapshot" \
      --skip-azure-bindings \
      --json
  )"
  if ! skip_rotation_state="$(classify_skipped_binding_rotation "$skip_match_report_json" 2>/dev/null)"; then
    fail "post-rotation matching did not safely prove the skipped-binding rotation result"
  fi
  skip_match_report_json=""
  if [[ "$skip_rotation_state" == "unchanged" ]]; then
    printf 'Skipped-binding rotation was cancelled; the Foundry host Key1 was unchanged.\n'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    return
  fi
  [[ "$skip_rotation_state" == "rotated" ]] \
    || fail "post-rotation matching returned an unknown skipped-binding rotation state"
  rm -f -- "$skip_snapshot"
  printf '%s\n' \
    'Verified that direct skipped-binding rotation changed only the selected fixture key.' \
    'The temporary pre-rotation key snapshot was removed.'

  printf '\nStep 4/7: private SOPS export and disposable alias matrix\n'
  "$AGE_KEYGEN_BIN" -o "$age_identity" >/dev/null 2>&1
  chmod 600 "$age_identity"
  age_recipient="$("$AGE_KEYGEN_BIN" -y "$age_identity")"
  [[ "$age_recipient" =~ ^age1[0-9a-z]+$ ]] \
    || fail "age-keygen returned an invalid recipient"
  export SOPS_AGE_KEY_FILE="$age_identity"
  export SOPS_AGE_RECIPIENTS="$age_recipient"

  "$AZURATOR_BIN" export \
    --subscription "$SUBSCRIPTION_ID" \
    --select "$STORAGE_ACCOUNT_ID#key1" \
    --select "$STORAGE_ACCOUNT_ID#key2" \
    --select "$OPENAI_ACCOUNT_ID#Key1" \
    --sops-out "$managed_sops"

  if [[ ! -f "$managed_sops" ]]; then
    printf 'Export was cancelled; no rotation was attempted.\n'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    return
  fi
  [[ ! -L "$managed_sops" && "$(stat -c '%a' "$managed_sops")" == "600" ]] \
    || fail "the exported SOPS dotenv file did not satisfy the private mode-0600 contract"

  mapfile -t exported_selectors < <(
    "$SOPS_BIN" decrypt \
      --input-type dotenv \
      --output-type dotenv \
      "$managed_sops" \
      | cut -d= -f1
  )
  [[ "${#exported_selectors[@]}" -eq 3 ]] \
    || fail "the selected export did not produce exactly three dotenv assignments"
  storage_selector="${exported_selectors[0]}"
  storage_secondary_selector="${exported_selectors[1]}"
  openai_selector="${exported_selectors[2]}"
  [[ "$storage_selector" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
    || fail "the Storage export selector did not satisfy the reviewed dotenv contract"
  [[ "$storage_secondary_selector" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
    || fail "the secondary Storage export selector did not satisfy the reviewed dotenv contract"
  [[ "$storage_secondary_selector" != "$storage_selector" ]] \
    || fail "the Storage export selectors were not unique"
  [[ "$openai_selector" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
    || fail "the Azure OpenAI export selector did not satisfy the reviewed dotenv contract"
  [[ "$openai_selector" != "$storage_selector" && "$openai_selector" != "$storage_secondary_selector" ]] \
    || fail "the exported dotenv selectors were not unique"

  copy_sops_assignment "$storage_selector" "$STORAGE_LOCAL_ALIAS" "$managed_sops"
  copy_sops_assignment \
    "$storage_secondary_selector" "$STORAGE_SECONDARY_LOCAL_ALIAS" "$managed_sops"
  copy_sops_assignment "$openai_selector" "$OPENAI_LOCAL_ALIAS" "$managed_sops"
  set_public_sops_assignment "$UNRELATED_LOCAL_SELECTOR" '"preserve-me"' "$managed_sops"
  set_public_sops_assignment "$EMPTY_LOCAL_SELECTOR" '""' "$managed_sops"
  validate_sops_document \
    "$managed_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  [[ ! -L "$managed_sops" && "$(stat -c '%a' "$managed_sops")" == "600" ]] \
    || fail "the encrypted export did not remain one private SOPS document"
  [[ ! -L "$age_identity" && "$(stat -c '%a' "$age_identity")" == "600" ]] \
    || fail "the disposable age identity did not satisfy the private mode-0600 contract"
  printf '%s\n' \
    'Exported directly to SOPS ciphertext and added one grouped alias for each selected slot.' \
    'The encrypted document also contains one unrelated value and one empty assignment.'

  printf '\nStep 5/7: reusable key map, SOPS recreation, and executable bridge plan\n'
  "$AZURATOR_BIN" match \
    --subscription "$SUBSCRIPTION_ID" \
    --sops-file "$managed_sops" \
    --key-map-out "$key_map"
  validate_key_map \
    "$key_map" "$storage_selector" "$storage_secondary_selector" "$openai_selector"

  "$AZURATOR_BIN" export \
    --subscription "$SUBSCRIPTION_ID" \
    --key-map "$key_map" \
    --sops-out "$mapped_sops"
  if [[ ! -f "$mapped_sops" ]]; then
    printf 'Key-map export was cancelled; no managed rotation was attempted.\n'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    return
  fi
  [[ ! -L "$mapped_sops" && "$(stat -c '%a' "$mapped_sops")" == "600" ]] \
    || fail "the key-map SOPS export did not satisfy the private mode-0600 contract"
  validate_mapped_sops_document \
    "$mapped_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  rm -f -- "$mapped_sops" "$key_map"

  match_report_json="$(
    "$AZURATOR_BIN" match \
      --subscription "$SUBSCRIPTION_ID" \
      --sops-file "$managed_sops" \
      --json
  )"
  validate_sops_match_report \
    "$match_report_json" "$managed_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  match_report_json=""
  plan_report_json="$(
    "$AZURATOR_BIN" plan \
      --subscription "$SUBSCRIPTION_ID" \
      --sops-file "$managed_sops" \
      --json
  )"
  validate_sops_plan \
    "$plan_report_json" "$managed_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  plan_report_json=""
  printf '%s\n' \
    'Verified the reusable key map and recreated exactly six encrypted Azure assignments.' \
    'Verified six matched assignments grouped into three local SOPS bindings.' \
    'Verified the complete 31-step plan, including Storage key2 restoration after both slots rotate.'

  printf '\nStep 6/7: generated, displayed, and confirmed managed SOPS rotation\n'
  before_file_state="$(sha256sum -- "$managed_sops")"
  ROTATION_ATTEMPTED=true
  "$AZURATOR_BIN" rotate \
    --subscription "$SUBSCRIPTION_ID" \
    --sops-file "$managed_sops"
  after_file_state="$(sha256sum -- "$managed_sops")"

  if [[ "$before_file_state" == "$after_file_state" ]]; then
    ROTATION_ATTEMPTED=false
    printf 'Rotation was cancelled; the managed SOPS file was unchanged.\n'
    remove_workspace
    run_lifecycle down
    WORKFLOW_COMPLETED=true
    return
  fi

  printf '\nStep 7/7: final key and managed-binding verification\n'
  match_report_json="$(
    "$AZURATOR_BIN" match \
      --subscription "$SUBSCRIPTION_ID" \
      --sops-file "$managed_sops" \
      --json
  )"
  validate_sops_match_report \
    "$match_report_json" "$managed_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  match_report_json=""
  validate_sops_document \
    "$managed_sops" "$storage_selector" "$storage_secondary_selector" "$openai_selector"
  verify_unrelated_app_setting
  verify_storage_connection_string_shape
  [[ ! -L "$managed_sops" && "$(stat -c '%a' "$managed_sops")" == "600" ]] \
    || fail "the rotated managed SOPS file no longer satisfied the private mode-0600 contract"

  ROTATION_VERIFIED=true
  printf '%s\n' \
    'Verified both final Storage slots and Azure OpenAI Key1 across six SOPS assignments,' \
    'both Foundry connections,' \
    'all four App Service key settings, and both unrelated local and Azure settings.' \
    'No workload was invoked; this verifies stored configuration only.'
  remove_workspace

  printf '\nFinal teardown\n'
  run_lifecycle down
  WORKFLOW_COMPLETED=true
  printf 'Live end-to-end test completed and the tagged fixture was removed.\n'
}

trap handle_exit EXIT
main "$@"
