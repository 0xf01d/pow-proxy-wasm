// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
//
// ipintel integration: embedded IP intelligence database (build-time) used to
// decide who gets challenged. Config:
//
//	"ipintel": {
//	  "mode": "challenge" | "difficulty",     // default challenge
//	  "challenge_categories": ["vpn","tor",...],  // score.go categories
//	  "bypass_groups": ["search_crawler"],    // crawler groups that skip PoW
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
//   - bypass_groups is a relaxation only: it can turn an ipintel challenge
//     into a pass for crawler-group matches, never turn a pass into anything
//     and never rescue a block decided earlier in the request path.
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
// embedded database opened successfully. Any invalid bypass_groups value
// disables the whole block rather than applying half of it.
func parseIPIntelConfig(data []byte, dbBytes []byte) (db *ipintelbin.DB, mode string, cats map[string]bool, bypass map[string]bool, target uint, enabled bool, problems []string) {
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
	var bypassProblems []string
	bypass, bypassProblems = parseIPIntelBypassGroups(data)
	problems = append(problems, bypassProblems...)
	if v := gjson.GetBytes(data, "ipintel.target_difficulty").Uint(); v > 0 {
		target = uint(v)
	}
	if mode == "" || len(cats) == 0 || len(bypassProblems) > 0 {
		return nil, "", nil, nil, 0, false, problems
	}
	var err error
	db, err = ipintelbin.OpenBytes(dbBytes)
	if err != nil {
		problems = append(problems, "ipintel: db open failed: "+err.Error())
		return nil, "", nil, nil, 0, false, problems
	}
	return db, mode, cats, bypass, target, true, problems
}

// parseIPIntelBypassGroups normalises ipintel.bypass_groups to lowercase names.
// The key is optional; when present it must be an array of strings.
func parseIPIntelBypassGroups(data []byte) (map[string]bool, []string) {
	value := gjson.GetBytes(data, "ipintel.bypass_groups")
	if !value.Exists() {
		return nil, nil
	}
	if !value.IsArray() {
		return nil, []string{"ipintel.bypass_groups must be an array of group names"}
	}
	var bypass map[string]bool
	for _, item := range value.Array() {
		if item.Type != gjson.String {
			return nil, []string{"ipintel.bypass_groups entries must be strings"}
		}
		group := strings.ToLower(strings.TrimSpace(item.Str))
		if group == "" {
			continue
		}
		if bypass == nil {
			bypass = map[string]bool{}
		}
		bypass[group] = true
	}
	return bypass, nil
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
	// ipBlock is a hard verdict from an earlier stage (protected/botscore).
	// It is never produced here; it exists so the bypass relaxation can be
	// tested to leave hard blocks untouched.
	ipBlock
)

// decideIPIntel is the legacy four-argument decision entry point. It also
// accepts optional bypass/group inputs and a full lookup Result so callers on
// the request path do not need a second API.
func decideIPIntel(mode string, args ...any) (ipintelDecision, uint) {
	cats, bypass, target, verdict, groups := parseIPIntelDecisionArgs(args)
	return decideIPIntelGroups(mode, cats, bypass, target, verdict, groups)
}

func parseIPIntelDecisionArgs(args []any) (cats, bypass map[string]bool, target uint, verdict string, groups []string) {
	var maps []map[string]bool
	for _, arg := range args {
		switch v := arg.(type) {
		case map[string]bool:
			maps = append(maps, v)
		case uint:
			target = v
		case int:
			if v > 0 {
				target = uint(v)
			}
		case string:
			verdict = v
		case []string:
			groups = v
		case ipintelbin.Result:
			verdict, groups = v.Verdict, v.Groups
		case *ipintelbin.Result:
			if v != nil {
				verdict, groups = v.Verdict, v.Groups
			}
		}
	}
	if len(maps) > 0 {
		cats = maps[0]
	}
	if len(maps) > 1 {
		bypass = maps[1]
		// Be tolerant of argument order: the crawler map is the bypass map.
		if isCrawlerMap(cats) && !isCrawlerMap(bypass) {
			cats, bypass = bypass, cats
		}
	}
	return cats, bypass, target, verdict, groups
}

func isCrawlerMap(m map[string]bool) bool {
	for _, name := range []string{"search_crawler", "ai_crawler", "crawlers"} {
		if m[name] {
			return true
		}
	}
	return false
}

func decideIPIntelBase(mode string, cats map[string]bool, target uint, verdict string) (ipintelDecision, uint) {
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

// decideIPIntelGroups applies bypass_groups as a relaxation after the ordinary
// category decision. A bypass match only changes challenge/elevated into pass;
// pass and hard block verdicts are never modified.
func decideIPIntelGroups(mode string, cats, bypass map[string]bool, target uint, verdict string, groups []string) (ipintelDecision, uint) {
	decision, elev := decideIPIntelBase(mode, cats, target, verdict)
	if decision == ipPass || len(bypass) == 0 {
		return decision, elev
	}
	if matchBypassGroup(bypass, groups) == "" {
		return decision, elev
	}
	return applyIPIntelBypass(decision), 0
}

func applyIPIntelBypass(decision ipintelDecision) ipintelDecision {
	switch decision {
	case ipChallenge, ipElevated:
		return ipPass
	default:
		return decision
	}
}

// matchBypassGroup returns the first configured group present in groups.
func matchBypassGroup(bypass map[string]bool, groups []string) string {
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group != "" && bypass[group] {
			return group
		}
	}
	return ""
}

// crawlerIdentity finds the operator/bot detail for a matched group.
func crawlerIdentity(crawlers []ipintelbin.CrawlerMatch, group string) (operator, bot string) {
	for _, crawler := range crawlers {
		if group == "" || crawler.Category == group || crawler.Group == group {
			return crawler.Operator, crawler.Bot
		}
	}
	return "", ""
}

// ipintelResult looks up ip once and returns the full result. The bool is false
// when the DB is missing or the lookup fails (legacy behavior follows).
func (p *pluginContext) ipintelResult(ip string) (ipintelbin.Result, bool) {
	if p.ipintel == nil {
		return ipintelbin.Result{}, false
	}
	res, err := p.ipintel.Lookup(ip)
	if err != nil {
		proxywasm.LogDebugf("ipintel: lookup failed for %s: %v", ip, err)
		return ipintelbin.Result{}, false
	}
	return res, true
}

// ipintelMatch looks up ip and returns its best-category verdict
// ("" when the DB is missing or the lookup fails — decision then defaults to
// challenge, i.e. legacy behavior).
func (p *pluginContext) ipintelMatch(ip string) string {
	res, ok := p.ipintelResult(ip)
	if !ok {
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
