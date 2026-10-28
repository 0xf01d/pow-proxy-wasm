// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
//
// ipintel integration: embedded IP intelligence database (build-time) used to
// decide who gets challenged. Config:
//
//	"ipintel": {
//	  "mode": "challenge" | "difficulty",     // default challenge
//	  "challenge_categories": ["vpn","tor",...],  // score.go categories
//	  "target_difficulty": 18                 // mode=difficulty override
//	}
//
// Semantics (see ipintel.go tests + docs/pow-ipintel-spec.md):
//   - disabled unless mode + at least one category are configured
//   - db open failure ⇒ disabled (fail-open, never blocks traffic)
//   - mode=challenge: matching IPs get the normal challenge flow; non-matching
//     pass with NO challenge
//   - mode=difficulty: everyone follows the legacy flow, matching IPs get
//     target_difficulty (clamped to [dynamic_floor, max])
package main

import (
	"sort"
	"strings"

	ipintelbin "github.com/kubewaf-io/pow-proxy-wasm/ipintelbin"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/tidwall/gjson"
)

// parseIPIntelConfig extracts the optional `ipintel` block. enabled is true
// only when a valid mode + at least one category are configured AND the
// embedded database opened successfully.
func parseIPIntelConfig(data []byte, dbBytes []byte) (db *ipintelbin.DB, mode string, cats map[string]bool, target uint, enabled bool, problems []string) {
	mode = strings.ToLower(strings.TrimSpace(gjson.GetBytes(data, "ipintel.mode").Str))
	if mode == "" {
		mode = ipintelModeChallenge
	}
	if mode != ipintelModeChallenge && mode != ipintelModeDifficulty {
		problems = append(problems, "ipintel.mode invalid (challenge|difficulty)")
		mode = ""
	}
	for _, cat := range gjson.GetBytes(data, "ipintel.challenge_categories").Array() {
		c := strings.ToLower(strings.TrimSpace(cat.Str))
		if c != "" {
			if cats == nil {
				cats = map[string]bool{}
			}
			cats[c] = true
		}
	}
	if v := gjson.GetBytes(data, "ipintel.target_difficulty").Uint(); v > 0 {
		target = uint(v)
	}
	if mode == "" || len(cats) == 0 {
		return nil, "", nil, 0, false, problems
	}
	var err error
	db, err = ipintelbin.OpenBytes(dbBytes)
	if err != nil {
		problems = append(problems, "ipintel: db open failed: "+err.Error())
		return nil, "", nil, 0, false, problems
	}
	return db, mode, cats, target, true, problems
}

// ipintelDecision is the pure decision core (unit-tested).
type ipintelDecision uint8

const (
	ipintelModeChallenge  = "challenge"
	ipintelModeDifficulty = "difficulty"

	// ipPass: no challenge at all.
	ipPass ipintelDecision = iota
	// ipChallenge: normal challenge flow.
	ipChallenge
	// ipElevated: challenge at the elevated difficulty.
	ipElevated
)

func decideIPIntel(mode string, cats map[string]bool, target uint, verdict string) (ipintelDecision, uint) {
	if mode == "" || len(cats) == 0 || verdict == "" {
		return ipChallenge, 0
	}
	if !cats[verdict] {
		if mode == ipintelModeDifficulty {
			// legacy flow for everyone; only matching IPs get elevation
			return ipChallenge, 0
		}
		return ipPass, 0
	}
	if mode == ipintelModeDifficulty && target > 0 {
		return ipElevated, target
	}
	return ipChallenge, 0
}

// ipintelMatch looks up ip and returns its best-category verdict
// ("" when the DB is missing or the lookup fails — decision then defaults to
// challenge, i.e. legacy behavior).
func (p *pluginContext) ipintelMatch(ip string) string {
	if p.ipintel == nil {
		return ""
	}
	res, err := p.ipintel.Lookup(ip)
	if err != nil {
		proxywasm.LogDebugf("ipintel: lookup failed for %s: %v", ip, err)
		return ""
	}
	return res.Verdict
}

// keysOf returns sorted map keys (logging only).
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
