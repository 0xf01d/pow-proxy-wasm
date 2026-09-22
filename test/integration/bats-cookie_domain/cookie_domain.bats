#!/usr/bin/env bats
#
# cookie_domain integration tests.
#
# Runs against test/fixtures/envoy-cookie_domain.yaml (see Makefile target
# test-bats-cookie_domain) with "cookie_domain": "example.com" in the plugin
# config. Asserts the raw Set-Cookie wire format: every cookie the plugin
# sets AND clears must carry ; Domain=example.com — clearing without the
# attribute would leave stale domain cookies in the browser.

load ../bats/lib/common

setup_file() {
  envoy_start
}

teardown_file() {
  if [[ "${KEEP_RUNNING:-0}" != "1" ]]; then
    envoy_cleanup
  else
    envoy_print_keep_running_info
  fi
}

@test "challenge Set-Cookie lines carry Domain attribute" {
  hdr=$(mktemp)
  curl -sD "$hdr" -o /dev/null "$(envoy_base_url)/"
  [ "$(head -1 "$hdr" | awk '{print $2}')" = "403" ]
  grep -qiE '^set-cookie: challenge=.+; domain=example\.com' "$hdr"
  grep -qiE '^set-cookie: challenge-sig=.+; domain=example\.com' "$hdr"
  rm -f "$hdr"
}

@test "cleared stale cookies mirror the Domain attribute" {
  hdr=$(mktemp)
  curl -sD "$hdr" -o /dev/null "$(envoy_base_url)/"
  grep -qiE '^set-cookie: challenge-nonce=;.+; domain=example\.com' "$hdr"
  grep -qiE '^set-cookie: challenge-clearance=;.+; domain=example\.com' "$hdr"
  rm -f "$hdr"
}

@test "clearance Set-Cookie carries Domain attribute" {
  # Renewal path issues a fresh challenge-clearance Set-Cookie without a
  # full PoW solve (clearance tokens are IP-bound; see sliding_renewal.bats).
  ip=$(envoy_client_ip)
  tok=$("$POWCLI" mint-clearance -secret "$PLUGIN_SECRET" -ip "$ip" -expires-in -5s)
  hdr=$(mktemp)
  # Must fire within sliding_renewal_ttl (10s) of expiry — curl immediately.
  curl -sD "$hdr" -o /dev/null -b "challenge-clearance=${tok}" "$(envoy_base_url)/"
  [ "$(head -1 "$hdr" | awk '{print $2}')" = "200" ]
  grep -qiE '^set-cookie: challenge-clearance=..+; domain=example\.com' "$hdr"
  rm -f "$hdr"
}

@test "renewed domain cookie is itself valid on the next request" {
  ip=$(envoy_client_ip)
  tok=$("$POWCLI" mint-clearance -secret "$PLUGIN_SECRET" -ip "$ip" -expires-in -5s)
  hdr=$(mktemp)
  curl -sD "$hdr" -o /dev/null -b "challenge-clearance=${tok}" "$(envoy_base_url)/"
  renewed=$(grep -iE '^set-cookie: challenge-clearance=' "$hdr" \
    | sed 's/^[Ss]et-[Cc]ookie: challenge-clearance=\([^;]*\).*/\1/' | tr -d '\r' | head -1)
  [ -n "$renewed" ]
  rm -f "$hdr"
  run curl -s -o /dev/null -w "%{http_code}" \
    -b "challenge-clearance=${renewed}" "$(envoy_base_url)/"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}
