#!/usr/bin/env bash
# Gateway acceptance test: network isolation, blocked-attempt recording,
# discard accounting, and cleanup.
#
# Safe to rerun: it uses a throwaway TT_HOME and a throwaway timeline, so it
# never touches your real .tt data. Run it with no other gateways up, because
# the leftover checks look for any gateway namespace or firewall table.

cd "$(dirname "$0")/.." || exit 1
cargo build --workspace -q || { echo "build failed"; exit 1; }

TL="$(pwd)/target/debug/tl"
export TT_HOME="$(mktemp -d)"
TRIAL_TIMELINE=acceptance-trial
PASSED_COUNT=0
FAILED_COUNT=0

record_pass() { echo "  PASS  $1"; PASSED_COUNT=$((PASSED_COUNT + 1)); }
record_fail() { echo "  FAIL  $1"; FAILED_COUNT=$((FAILED_COUNT + 1)); }

# expect_success "description" command...  -> passes if the command succeeds
expect_success() {
  local description="$1"; shift
  if "$@" >/dev/null 2>&1; then record_pass "$description"; else record_fail "$description"; fi
}

# expect_failure "description" command...  -> passes if the command fails
expect_failure() {
  local description="$1"; shift
  if "$@" >/dev/null 2>&1; then record_fail "$description"; else record_pass "$description"; fi
}

cleanup() {
  "$TL" gateway down "$TRIAL_TIMELINE" >/dev/null 2>&1
  case "$TT_HOME" in /tmp/*) sudo rm -rf "$TT_HOME" ;; esac
}
trap cleanup EXIT

sudo -v || exit 1
"$TL" init >/dev/null 2>&1
"$TL" fork "$TRIAL_TIMELINE" --from main >/dev/null 2>&1

echo "[1] request validation"
expect_failure "rejects 0.0.0.0/0 (allow-everything)" "$TL" gateway up "$TRIAL_TIMELINE" 0.0.0.0/0
expect_failure "rejects injection attempt in allowlist" "$TL" gateway up "$TRIAL_TIMELINE" "1.1.1.1; flush ruleset"
expect_failure "refuses to isolate MAIN" "$TL" gateway up main 1.1.1.1
expect_failure "rejected requests left no namespace behind" bash -c 'sudo ip netns list | grep -q ttns'

echo "[2] isolation (allowlist: 1.1.1.1 only)"
if "$TL" gateway up "$TRIAL_TIMELINE" 1.1.1.1 >/dev/null 2>&1; then record_pass "gateway up"; else record_fail "gateway up"; fi
expect_success "allowed destination is reachable" "$TL" gateway exec "$TRIAL_TIMELINE" -- ping -c 1 -W 3 1.1.1.1
expect_failure "blocked ICMP (8.8.8.8)" "$TL" gateway exec "$TRIAL_TIMELINE" -- ping -c 1 -W 2 8.8.8.8
expect_failure "blocked TCP (93.184.216.34:443)" "$TL" gateway exec "$TRIAL_TIMELINE" -- timeout 3 bash -c 'echo > /dev/tcp/93.184.216.34/443'
"$TL" gateway exec "$TRIAL_TIMELINE" -- timeout 3 bash -c 'echo hi > /dev/udp/8.8.8.8/53' >/dev/null 2>&1
expect_success "host itself still has internet" ping -c 1 -W 3 8.8.8.8

echo "[3] blocked attempts are recorded"
BLOCKED_REPORT="$("$TL" gateway denied "$TRIAL_TIMELINE" 2>&1)"
if echo "$BLOCKED_REPORT" | grep -q "DENY 8.8.8.8/ICMP"; then record_pass "ICMP attempt recorded"; else record_fail "ICMP attempt recorded"; fi
if echo "$BLOCKED_REPORT" | grep -q "DENY 93.184.216.34:443/TCP"; then record_pass "TCP attempt recorded"; else record_fail "TCP attempt recorded"; fi
if echo "$BLOCKED_REPORT" | grep -q "DENY 8.8.8.8:53/UDP"; then record_pass "UDP attempt recorded"; else record_fail "UDP attempt recorded"; fi
if echo "$BLOCKED_REPORT" | grep -q "1.1.1.1"; then record_fail "allowed traffic was wrongly logged as blocked"; else record_pass "allowed traffic is not logged as blocked"; fi

echo "[4] discard report and cleanup"
DISCARD_REPORT="$("$TL" discard "$TRIAL_TIMELINE" 2>&1)"
if echo "$DISCARD_REPORT" | grep -q "0 allowed, 3 denied"; then
  record_pass "discard reports 0 allowed, 3 denied"
else
  record_fail "discard report (expected: 0 allowed, 3 denied)"
  echo "$DISCARD_REPORT" | sed 's/^/        /'
fi
expect_failure "namespace removed by discard" bash -c 'sudo ip netns list | grep -q ttns'
expect_failure "firewall tables removed by discard" bash -c 'sudo nft list tables | grep -q ttgw'

echo "[5] a reused timeline name does not inherit old history"
sleep 2
"$TL" fork "$TRIAL_TIMELINE" --from main >/dev/null 2>&1
"$TL" gateway up "$TRIAL_TIMELINE" 1.1.1.1 >/dev/null 2>&1
"$TL" gateway exec "$TRIAL_TIMELINE" -- ping -c 1 -W 1 9.9.9.9 >/dev/null 2>&1
DISCARD_REPORT="$("$TL" discard "$TRIAL_TIMELINE" 2>&1)"
if echo "$DISCARD_REPORT" | grep -q "0 allowed, 1 denied"; then
  record_pass "second run reports only its own 1 denied"
else
  record_fail "second run (expected: 0 allowed, 1 denied)"
  echo "$DISCARD_REPORT" | sed 's/^/        /'
fi

echo
echo "RESULT: $PASSED_COUNT passed, $FAILED_COUNT failed"
[ "$FAILED_COUNT" -eq 0 ]