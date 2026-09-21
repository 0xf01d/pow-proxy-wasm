#!/usr/bin/env bats
#
# Selective enforcement (`protected` config) integration tests.
#
# Runs against test/fixtures/envoy-protected.yaml (see Makefile target
# test-bats-protected) with rules:
#   1. private.example.org + paths /login, /admin
#   2. *.wild.example.org    + path  /api/write
#   3. apex.example.org      (any path)
# Everything else must pass through unchallenged.

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

@test "unprotected host passes through without cookies or challenge" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: public.example.org" "$(envoy_base_url)/"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

@test "protected host+path gets the challenge page" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: private.example.org" "$(envoy_base_url)/login"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "protected host, unprotected path passes through" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: private.example.org" "$(envoy_base_url)/public"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

@test "query string is stripped before prefix matching" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: private.example.org" "$(envoy_base_url)/login?x=1"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "authority case folding and port stripping apply" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: Private.Example.Org:8443" "$(envoy_base_url)/admin"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "wildcard matches exactly one extra leftmost label" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: deep.wild.example.org" "$(envoy_base_url)/api/write"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]

  # Two extra labels: *.wild.example.org must NOT match.
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: a.b.wild.example.org" "$(envoy_base_url)/api/write"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]

  # The wildcard's base host itself is not covered.
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: wild.example.org" "$(envoy_base_url)/api/write"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}

@test "host rule without paths protects the whole host" {
  run curl -s -o /dev/null -w "%{http_code}" -H "Host: apex.example.org" "$(envoy_base_url)/anything"
  [ "$status" -eq 0 ]
  [ "$output" = "403" ]
}

@test "clearance solved on one protected path clears sibling paths" {
  # Solve on /login of the protected host; the host-scoped clearance must
  # then satisfy /admin without a new challenge.
  clearance=$(envoy_get_clearance private.example.org /login)
  [ -n "$clearance" ]
  run curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: private.example.org" \
    -b "challenge-clearance=${clearance}" \
    "$(envoy_base_url)/admin"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
  # ...and the unprotected zone of the same host never needed it anyway.
  run curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: private.example.org" \
    "$(envoy_base_url)/healthz"
  [ "$status" -eq 0 ]
  [ "$output" = "200" ]
}
