// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
package main

import (
	"os"
	"testing"

	ipintelbin "github.com/kubewaf-io/pow-proxy-wasm/ipintelbin"
)

func TestDecideIPIntel(t *testing.T) {
	cats := map[string]bool{"vpn": true, "tor": true, "hosting": true}

	// disabled / empty verdict → legacy challenge
	if d, _ := decideIPIntel("", cats, 18, "vpn"); d != ipChallenge {
		t.Fatalf("disabled: got %v", d)
	}
	if d, _ := decideIPIntel(ipintelModeChallenge, nil, 0, "vpn"); d != ipChallenge {
		t.Fatalf("no cats: got %v", d)
	}
	if d, _ := decideIPIntel(ipintelModeChallenge, cats, 0, ""); d != ipChallenge {
		t.Fatalf("empty verdict: got %v", d)
	}

	// challenge mode: match → challenge, miss → pass
	if d, _ := decideIPIntel(ipintelModeChallenge, cats, 0, "vpn"); d != ipChallenge {
		t.Fatalf("challenge mode match: got %v", d)
	}
	if d, _ := decideIPIntel(ipintelModeChallenge, cats, 0, "residential_isp"); d != ipPass {
		t.Fatalf("challenge mode miss: got %v", d)
	}

	// difficulty mode: match → elevated at target, miss → challenge (legacy, no pass!)
	if d, e := decideIPIntel(ipintelModeDifficulty, cats, 18, "vpn"); d != ipElevated || e != 18 {
		t.Fatalf("difficulty mode match: got %v/%d", d, e)
	}
	if d, _ := decideIPIntel(ipintelModeDifficulty, cats, 18, "residential_isp"); d != ipChallenge {
		t.Fatalf("difficulty mode miss: got %v", d)
	}
	// difficulty mode with target 0 → plain challenge
	if d, e := decideIPIntel(ipintelModeDifficulty, cats, 0, "vpn"); d != ipChallenge || e != 0 {
		t.Fatalf("difficulty no target: got %v/%d", d, e)
	}
}

func TestParseIPIntelConfig(t *testing.T) {
	// absent → disabled
	db, mode, cats, target, enabled, problems := parseIPIntelConfig([]byte(`{"secret":"x"}`), nil)
	if enabled || db != nil || mode != "" || cats != nil || target != 0 || len(problems) != 0 {
		t.Fatalf("absent: enabled=%v mode=%q", enabled, mode)
	}

	// mode without categories → disabled, no problems
	_, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge"}}`), nil)
	if enabled || len(problems) != 0 {
		t.Fatalf("mode only: enabled=%v problems=%v", enabled, problems)
	}

	// bad mode → disabled with problem
	_, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"wat","challenge_categories":["vpn"]}}`), nil)
	if enabled || len(problems) != 1 {
		t.Fatalf("bad mode: enabled=%v problems=%v", enabled, problems)
	}

	// valid config, nil db bytes → disabled with problem (fail-open)
	_, _, cats, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge","challenge_categories":["vpn","tor"]}}`), nil)
	if enabled || len(problems) != 1 || cats != nil {
		t.Fatalf("nil db: enabled=%v cats=%v problems=%v", enabled, cats, problems)
	}
}

func TestIPIntelMatchRealDB(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip(err)
	}
	p := &pluginContext{ipintel: db}
	if got := p.ipintelMatch("45.83.91.1"); got != "vpn" {
		t.Fatalf("vpn ip verdict = %q", got)
	}
	if got := p.ipintelMatch("8.8.8.8"); got != "hosting" {
		t.Fatalf("gcloud verdict = %q", got)
	}
}

func openTestDB() (*ipintelbin.DB, error) {
	b, err := os.ReadFile("data/ipintel.bin")
	if err != nil {
		return nil, err
	}
	return ipintelbin.OpenBytes(b)
}
