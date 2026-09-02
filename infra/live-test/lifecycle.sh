#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
# The shared guard is checked separately.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scope.sh"

readonly RESOURCE_GROUP_NAME="rg-azurator-live-test"
readonly DEPLOYMENT_LOCATION="westeurope"
readonly EXPECTED_FIXTURE_TAG="live-test"
readonly EXPECTED_OWNER_TAG="azurator-repository"

usage() {
  printf 'Usage: %s <what-if|up|down>\n' "${0##*/}" >&2
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

require_fixture_paths() {
  : "${AZURATOR_LIVE_TEST_TEMPLATE:?AZURATOR_LIVE_TEST_TEMPLATE is required}"
  : "${AZURATOR_LIVE_TEST_RESOURCES:?AZURATOR_LIVE_TEST_RESOURCES is required}"
  : "${AZURATOR_LIVE_TEST_PARAMETERS:?AZURATOR_LIVE_TEST_PARAMETERS is required}"
  [[ -f "$AZURATOR_LIVE_TEST_TEMPLATE" ]] || fail "Bicep template not found"
  [[ -f "$AZURATOR_LIVE_TEST_RESOURCES" ]] || fail "Bicep resource template not found"
  [[ -f "$AZURATOR_LIVE_TEST_PARAMETERS" ]] || fail "Bicep parameter file not found"
}

load_account() {
  local account_json subscription_json
  account_json="$(az account show --only-show-errors --output json)"

  SUBSCRIPTION_ID="$(jq -er '.id' <<<"$account_json")"
  AZURE_ENVIRONMENT="$(jq -er '.environmentName' <<<"$account_json")"

  [[ "$SUBSCRIPTION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
    || fail "Azure CLI returned an invalid subscription ID"
  require_live_test_subscription_allowed "$SUBSCRIPTION_ID" || exit 1
  [[ "$AZURE_ENVIRONMENT" == "AzureCloud" ]] \
    || fail "the reviewed live-test fixture supports Azure public cloud only"

  # Azure CLI's local account cache can retain an obsolete subscription state
  # after a billing upgrade. Bind scope to its selected ID, then ask ARM for the
  # current authoritative state before any preview or mutation.
  subscription_json="$(
    az rest \
      --method get \
      --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID?api-version=2022-12-01" \
      --output json \
      --only-show-errors
  )"
  SUBSCRIPTION_NAME="$(jq -er '.displayName' <<<"$subscription_json")"
  SUBSCRIPTION_STATE="$(jq -er '.state' <<<"$subscription_json")"
  [[ "$SUBSCRIPTION_STATE" == "Enabled" ]] \
    || fail "subscription $SUBSCRIPTION_NAME is $SUBSCRIPTION_STATE, not Enabled"
}

show_scope() {
  printf 'Subscription: %s (%s)\n' "$SUBSCRIPTION_NAME" "$SUBSCRIPTION_ID"
  printf 'Resource group: %s\n' "$RESOURCE_GROUP_NAME"
}

require_absent_resource_group() {
  local exists
  exists="$(
    az group exists \
      --name "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --only-show-errors
  )"
  [[ "$exists" == "false" ]] \
    || fail "$RESOURCE_GROUP_NAME already exists; inspect it or run live-test-down before creating another fixture"
}

compile_fixture() {
  local parameter_group
  TEMP_DIR="$(mktemp -d -t azurator-live-test.XXXXXXXX)"
  COMPILED_TEMPLATE="$TEMP_DIR/main.json"
  COMPILED_RESOURCES="$TEMP_DIR/resources.json"
  COMPILED_PARAMETERS="$TEMP_DIR/parameters.json"
  export DOTNET_BUNDLE_EXTRACT_BASE_DIR="$TEMP_DIR/dotnet-bundle"
  mkdir -p "$DOTNET_BUNDLE_EXTRACT_BASE_DIR"

  bicep build "$AZURATOR_LIVE_TEST_TEMPLATE" --outfile "$COMPILED_TEMPLATE"
  bicep build "$AZURATOR_LIVE_TEST_RESOURCES" --outfile "$COMPILED_RESOURCES"
  bicep build-params "$AZURATOR_LIVE_TEST_PARAMETERS" --outfile "$COMPILED_PARAMETERS"

  parameter_group="$(jq -er '.parameters.resourceGroupName.value' "$COMPILED_PARAMETERS")"
  [[ "$parameter_group" == "$RESOURCE_GROUP_NAME" ]] \
    || fail "Bicep parameters target an unexpected resource group"
  RESOURCE_LOCATION="$(jq -er '.parameters.location.value | select(type == "string" and length > 0)' "$COMPILED_PARAMETERS")"
}

cleanup() {
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}

deployment_name() {
  printf 'azurator-live-test-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)"
}

provider_state() {
  az provider show \
    --namespace "$1" \
    --subscription "$SUBSCRIPTION_ID" \
    --query registrationState \
    --output tsv \
    --only-show-errors
}

missing_providers() {
  local namespace
  for namespace in Microsoft.CognitiveServices Microsoft.Storage Microsoft.Web; do
    if [[ "$(provider_state "$namespace")" != "Registered" ]]; then
      printf '%s\n' "$namespace"
    fi
  done
}

require_controlling_terminal() {
  [[ -r /dev/tty && -w /dev/tty ]] || fail "this mutation requires a controlling terminal"
  (true </dev/tty) 2>/dev/null || fail "this mutation requires a controlling terminal"
}

confirm_action() {
  local prompt answer
  prompt="$1"
  printf '%s [y/N] ' "$prompt" >/dev/tty
  IFS= read -r answer </dev/tty
  [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" || "$answer" == "YES" ]]
}

register_missing_providers() {
  local -a providers=("$@")
  local namespace
  for namespace in "${providers[@]}"; do
    printf 'Registering %s...\n' "$namespace"
    az provider register \
      --namespace "$namespace" \
      --subscription "$SUBSCRIPTION_ID" \
      --wait \
      --only-show-errors
  done
}

show_deployment_what_if() {
  local name="$1"
  az deployment sub what-if \
    --name "$name" \
    --location "$DEPLOYMENT_LOCATION" \
    --subscription "$SUBSCRIPTION_ID" \
    --template-file "$COMPILED_TEMPLATE" \
    --parameters "@$COMPILED_PARAMETERS" \
    --result-format ResourceIdOnly \
    --only-show-errors
}

run_what_if() {
  local name
  local -a providers=()
  name="$(deployment_name)"
  mapfile -t providers < <(missing_providers)

  show_scope
  if ((${#providers[@]} > 0)); then
    printf 'Not registered: %s\n' "${providers[*]}" >&2
    printf 'Azure may reject full provider validation until live-test-up registers it.\n' >&2
  fi

  show_deployment_what_if "$name"
}

run_up() {
  local name
  local -a providers=()
  name="$(deployment_name)"
  mapfile -t providers < <(missing_providers)

  show_scope
  printf '%s\n' \
    'Planned fixture:' \
    '  - one Shared-Key-enabled and one Shared-Key-disabled empty Standard_LRS StorageV2 account' \
    '  - one key-authentication-enabled S0 AI Services account and one project' \
    '  - one key-authentication-disabled S0 AI Services discovery account without a project' \
    '  - one key-authentication-enabled S0 Azure OpenAI account without model deployments' \
    '  - one AccountKey Storage connection and one ApiKey OpenAI connection' \
    '  - one Linux F1 App Service app with exact Storage/OpenAI key settings and one unrelated setting' \
    '  - Foundry User for the deploying principal, scoped only to the enabled project host' \
    'No key value is printed or written to a local file.'

  require_controlling_terminal
  if ((${#providers[@]} > 0)); then
    printf 'Registering required resource providers: %s\n' "${providers[*]}"
    register_missing_providers "${providers[@]}"
  fi

  printf '\nAzure deployment preview:\n'
  show_deployment_what_if "$name"
  if ! confirm_action "Create this tagged test fixture?"; then
    printf 'Deployment cancelled; no test resource group was created.\n'
    return
  fi

  az group create \
    --name "$RESOURCE_GROUP_NAME" \
    --location "$RESOURCE_LOCATION" \
    --subscription "$SUBSCRIPTION_ID" \
    --tags \
      "azurator-fixture=$EXPECTED_FIXTURE_TAG" \
      "azurator-owner=$EXPECTED_OWNER_TAG" \
      "azurator-ephemeral=true" \
    --output none \
    --only-show-errors
  load_fixture_group

  az deployment group create \
    --name "$name" \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --template-file "$COMPILED_RESOURCES" \
    --query properties.outputs \
    --output json \
    --only-show-errors

  load_fixture_group

  printf '\nCreated resources:\n'
  az resource list \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --query "[].{Name:name,Type:type,Location:location}" \
    --output table \
    --only-show-errors
}

load_fixture_group() {
  local group_json expected_id
  group_json="$(
    az group show \
      --name "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --output json \
      --only-show-errors
  )"
  expected_id="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP_NAME"

  [[ "$(jq -er '.id | ascii_downcase' <<<"$group_json")" == "${expected_id,,}" ]] \
    || fail "resource-group identity did not match the selected subscription"
  [[ "$(jq -er '.tags["azurator-fixture"] // ""' <<<"$group_json")" == "$EXPECTED_FIXTURE_TAG" ]] \
    || fail "$RESOURCE_GROUP_NAME is missing the required Azurator fixture tag"
  [[ "$(jq -er '.tags["azurator-owner"] // ""' <<<"$group_json")" == "$EXPECTED_OWNER_TAG" ]] \
    || fail "$RESOURCE_GROUP_NAME is missing the required Azurator owner tag"
}

run_down() {
  local exists
  show_scope
  load_fixture_group

  printf 'Resources scheduled for deletion:\n'
  az resource list \
    --resource-group "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --query "[].{Name:name,Type:type,Location:location}" \
    --output table \
    --only-show-errors

  require_controlling_terminal
  confirm_action "Permanently delete this tagged test resource group and every resource in it?" \
    || fail "deletion cancelled"

  # Submit one deletion operation and let Azure CLI implement ARM's standard
  # long-running-operation wait contract. Verify the final state once afterward.
  az group delete \
    --name "$RESOURCE_GROUP_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --yes \
    --only-show-errors

  exists="$(
    az group exists \
      --name "$RESOURCE_GROUP_NAME" \
      --subscription "$SUBSCRIPTION_ID" \
      --only-show-errors
  )"
  [[ "$exists" == "false" ]] || fail "Azure CLI returned before $RESOURCE_GROUP_NAME was fully deleted"
  printf '%s was deleted.\n' "$RESOURCE_GROUP_NAME"
}

main() {
  local command="${1:-}"
  [[ $# -eq 1 ]] || {
    usage
    exit 2
  }

  require_fixture_paths
  load_live_test_subscription_allowlist || exit 1
  load_account

  case "$command" in
    what-if)
      require_absent_resource_group
      compile_fixture
      run_what_if
      ;;
    up)
      require_absent_resource_group
      compile_fixture
      run_up
      ;;
    down)
      run_down
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

trap cleanup EXIT
main "$@"
