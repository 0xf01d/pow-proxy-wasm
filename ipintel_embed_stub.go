// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.

//go:build noipintel

package main

// ipintelDB is nil in NO_IPINTEL=1 builds (make build NO_IPINTEL=1 →
// -tags noipintel). parseIPIntelConfig fails to open the empty buffer and
// disables ipintel: fail-open, a missing DB never breaks traffic.
var ipintelDB []byte
