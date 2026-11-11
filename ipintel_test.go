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

func TestDecideIPIntelBypass(t *testing.T) {
	cats := map[string]bool{"hosting": true}
	bypass := map[string]bool{"search_crawler": true}
	groups := []string{"crawlers", "search_crawler"}

	// A crawler that also scores as hosting is normally challenged; the
	// bypass relaxation wins (pass), but the verdict itself stays hosting.
	if d, _ := decideIPIntel(ipintelModeChallenge, cats, 0, "hosting"); d != ipChallenge {
		t.Fatalf("baseline hosting: got %v", d)
	}
	if d, _ := decideIPIntelGroups(ipintelModeChallenge, cats, bypass, 0, "hosting", groups); d != ipPass {
		t.Fatalf("bypass search_crawler: got %v", d)
	}
	// The source-group spelling is accepted too.
	if d, _ := decideIPIntelGroups(ipintelModeChallenge, cats, map[string]bool{"crawlers": true}, 0, "hosting", groups); d != ipPass {
		t.Fatalf("bypass crawlers group: got %v", d)
	}
	// Difficulty mode is still a challenge; a bypass group turns it into pass.
	if d, _ := decideIPIntelGroups(ipintelModeDifficulty, cats, bypass, 18, "hosting", groups); d != ipPass {
		t.Fatalf("difficulty bypass: got %v", d)
	}
	// Non-crawler evidence is unchanged.
	if d, _ := decideIPIntelGroups(ipintelModeChallenge, cats, bypass, 0, "hosting", []string{"hosting"}); d != ipChallenge {
		t.Fatalf("non-crawler with bypass: got %v", d)
	}
	// Missing bypass is exactly the legacy decision.
	if d, e := decideIPIntelGroups(ipintelModeDifficulty, cats, nil, 18, "hosting", nil); d != ipElevated || e != 18 {
		t.Fatalf("no bypass: got %v/%d", d, e)
	}

	// A bypass never rescues a hard block, and never changes a pass.
	if got := applyIPIntelBypass(ipBlock); got != ipBlock {
		t.Fatalf("bypass changed block to %v", got)
	}
	if got := applyIPIntelBypass(ipPass); got != ipPass {
		t.Fatalf("bypass changed pass to %v", got)
	}
}

func TestParseIPIntelConfig(t *testing.T) {
	// absent → disabled
	db, mode, cats, bypass, target, enabled, problems := parseIPIntelConfig([]byte(`{"secret":"x"}`), nil)
	if enabled || db != nil || mode != "" || cats != nil || bypass != nil || target != 0 || len(problems) != 0 {
		t.Fatalf("absent: enabled=%v mode=%q", enabled, mode)
	}

	// mode without categories → disabled, no problems
	_, _, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge"}}`), nil)
	if enabled || len(problems) != 0 {
		t.Fatalf("mode only: enabled=%v problems=%v", enabled, problems)
	}

	// bad mode → disabled with problem
	_, _, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"wat","challenge_categories":["vpn"]}}`), nil)
	if enabled || len(problems) != 1 {
		t.Fatalf("bad mode: enabled=%v problems=%v", enabled, problems)
	}

	// valid config, nil db bytes → disabled with problem (fail-open)
	_, _, cats, bypass, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge","challenge_categories":["vpn","tor"]}}`), nil)
	if enabled || len(problems) != 1 || cats != nil || bypass != nil {
		t.Fatalf("nil db: enabled=%v cats=%v bypass=%v problems=%v", enabled, cats, bypass, problems)
	}

	// malformed bypass disables the whole block, never half-applies it.
	_, _, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge","challenge_categories":["vpn"],"bypass_groups":"search_crawler"}}`), nil)
	if enabled || len(problems) != 1 {
		t.Fatalf("bad bypass type: enabled=%v problems=%v", enabled, problems)
	}
	_, _, _, _, _, enabled, problems = parseIPIntelConfig([]byte(`{"ipintel":{"mode":"challenge","challenge_categories":["vpn"],"bypass_groups":["search_crawler",42]}}`), nil)
	if enabled || len(problems) != 1 {
		t.Fatalf("bad bypass entry: enabled=%v problems=%v", enabled, problems)
	}

	// normalisation and empty-entry dropping are pure and logged-free.
	bypass, bypassProblems := parseIPIntelBypassGroups([]byte(`{"ipintel":{"bypass_groups":[" Search_Crawler ","", "AI_CRAWLER","crawlers"]}}`))
	if len(bypassProblems) != 0 {
		t.Fatalf("bypass problems = %v", bypassProblems)
	}
	for _, want := range []string{"search_crawler", "ai_crawler", "crawlers"} {
		if !bypass[want] {
			t.Fatalf("bypass = %v, missing %s", bypass, want)
		}
	}
	if len(bypass) != 3 {
		t.Fatalf("bypass = %v, want 3 entries", bypass)
	}
}

func TestIPIntelMatchRealDB(t *testing.T) {
	db, err := openTestDB()
	if err != nil {
		t.Skip(err)
	}
	hasVPN := false
	for _, source := range db.Manifest().Sources {
		if source.Name == "x4b-vpn" {
			hasVPN = true
			break
		}
	}
	if !hasVPN {
		t.Skip("data/ipintel.bin is a synthetic crawler fixture")
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
