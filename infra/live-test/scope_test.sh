#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
TEST_ROOT="$(mktemp -d -t azurator-live-test-scope-test.XXXXXXXX)"
readonly TEST_ROOT
readonly SUBSCRIPTION_ID="11111111-1111-1111-1111-111111111111"

cleanup() {
  rm -rf -- "$TEST_ROOT"
}

fail() {
  printf 'Live-test scope guard test failed: %s\n' "$1" >&2
  exit 1
}

# The shared guard is checked separately.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scope.sh"
trap cleanup EXIT

valid="$TEST_ROOT/valid.env"
printf 'AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=%s\n' "$SUBSCRIPTION_ID" >"$valid"
export AZURATOR_LIVE_TEST_SCOPE_FILE="$valid"
load_live_test_subscription_allowlist
require_live_test_subscription_allowed "$SUBSCRIPTION_ID"
if require_live_test_subscription_allowed "22222222-2222-2222-2222-222222222222" 2>/dev/null; then
  fail "a subscription outside the allowlist was accepted"
fi

invalid="$TEST_ROOT/invalid.env"
printf '%s\n' \
  "AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=$SUBSCRIPTION_ID" \
  "AZURATOR_LIVE_TEST_SUBSCRIPTION_ID=$SUBSCRIPTION_ID" >"$invalid"
export AZURATOR_LIVE_TEST_SCOPE_FILE="$invalid"
if load_live_test_subscription_allowlist 2>/dev/null; then
  fail "a multi-line allowlist was accepted"
fi

link="$TEST_ROOT/link.env"
ln -s -- "$valid" "$link"
export AZURATOR_LIVE_TEST_SCOPE_FILE="$link"
if load_live_test_subscription_allowlist 2>/dev/null; then
  fail "a symlinked allowlist was accepted"
fi

printf 'Live-test subscription scope guard checks passed.\n'
