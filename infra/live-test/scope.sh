#!/usr/bin/env bash

AZURATOR_LIVE_TEST_ALLOWED_SUBSCRIPTION_ID=""

load_live_test_subscription_allowlist() {
  local scope_file="${AZURATOR_LIVE_TEST_SCOPE_FILE:-}"
  local -a lines=()

  AZURATOR_LIVE_TEST_ALLOWED_SUBSCRIPTION_ID=""
  if [[ -z "$scope_file" || ! -f "$scope_file" || -L "$scope_file" ]]; then
    printf '%s\n' \
      'Error: the local live-test subscription allowlist is missing or unsafe' >&2
    return 1
  fi
  if ! mapfile -t lines <"$scope_file"; then
    printf '%s\n' \
      'Error: the local live-test subscription allowlist could not be read' >&2
    return 1
  fi
  if [[ "${#lines[@]}" -ne 1 \
    || ! "${lines[0]}" =~ ^AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$ \
    || "${BASH_REMATCH[1],,}" == "00000000-0000-0000-0000-000000000000" ]]; then
    printf '%s\n' \
      'Error: the local live-test subscription allowlist must contain exactly one valid subscription ID' >&2
    return 1
  fi

  AZURATOR_LIVE_TEST_ALLOWED_SUBSCRIPTION_ID="${BASH_REMATCH[1],,}"
}

require_live_test_subscription_allowed() {
  local active_subscription_id="${1,,}"

  if [[ -z "$AZURATOR_LIVE_TEST_ALLOWED_SUBSCRIPTION_ID" \
    || "$active_subscription_id" != "$AZURATOR_LIVE_TEST_ALLOWED_SUBSCRIPTION_ID" ]]; then
    printf 'Error: active Azure subscription %s is not allowed by the local live-test subscription allowlist\n' \
      "$1" >&2
    return 1
  fi
}
