// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.

//go:build !noipintel

package main

import _ "embed" // blank import required for //go:embed

//go:embed data/ipintel.bin
var ipintelDB []byte // embedded IP intelligence database (build-time; see scripts/build-ipintel-db.sh)
