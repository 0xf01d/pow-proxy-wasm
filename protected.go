// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// Selective PoW enforcement: the `protected` config list declares which
// requests get challenged. Requests matching ANY rule (rules are OR-ed;
// within a rule, host match AND path match) go through the normal PoW
// flow; everything else passes through untouched.
//
// `protected` absent or empty ⇒ protect everything (legacy behavior).
//
// Matchers are compiled once in OnPluginStart into a flat slice; the
// per-request walk does in-place byte compares on the already-normalized
// authority/path and allocates nothing.

import (
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// protectedHost is one compiled entry of a rule's `hosts` list.
// Either an exact host (after lowercasing/port-stripping) or a single
// leading wildcard `*.suffix` that matches exactly one extra leftmost label.
type protectedHost struct {
	// exact is the lowercased host for non-wildcard entries.
	exact string
	// dotSuffix is ".suffix" for wildcard entries ("*.sub.example.org" →
	// ".sub.example.org"); empty for exact entries.
	dotSuffix string
}

func (h protectedHost) matches(host string) bool {
	if h.dotSuffix == "" {
		return host == h.exact
	}
	// Must end with ".suffix" and the remainder must be a single label
	// (no further dot): a.b.sub.example.org does NOT match *.sub.example.org.
	if len(host) <= len(h.dotSuffix) || !strings.HasSuffix(host, h.dotSuffix) {
		return false
	}
	remainder := host[:len(host)-len(h.dotSuffix)]
	return strings.IndexByte(remainder, '.') < 0
}

// protectedRule is one compiled `protected` entry. Zero-value rules match
// nothing; they are never stored (invalid/empty rules are dropped at parse).
type protectedRule struct {
	anyHost bool
	anyPath bool
	hosts   []protectedHost
	paths   []string // path prefixes

	// ja4 is the positive fingerprint dimension (docs/ja4-support.md §4):
	// OR-ed inside, AND-ed with hosts/paths. Unknown fingerprints (feature
	// off, header absent/garbage) never match it.
	ja4 []ja4Matcher
	// ja4Excluded is the veto dimension, applied after the positive
	// dimensions; it never applies to unknown fingerprints (unknown ≠
	// exemption).
	ja4Excluded []ja4Matcher

	// difficultyBase (when hasDifficulty) replaces the global base difficulty
	// for requests matched by this rule; clamped to the global bounds at
	// parse time. The pressure bump and the global max still apply on top.
	difficultyBase uint
	hasDifficulty  bool
}

func (r *protectedRule) matches(host, path, ja4 string) bool {
	if !r.anyHost {
		hit := false
		for i := range r.hosts {
			if r.hosts[i].matches(host) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if !r.anyPath {
		hit := false
		for i := range r.paths {
			if strings.HasPrefix(path, r.paths[i]) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	// Positive JA4 dimension: unknown fingerprints can never match it (§3.4
	// unknown ≠ bypass), so a rule carrying the dimension stays inert until
	// the edge actually injects a fingerprint.
	if len(r.ja4) > 0 && (ja4 == "" || !matchAnyJA4(r.ja4, ja4)) {
		return false
	}
	// Veto after the positive dimensions; never consulted for unknown
	// fingerprints — being unknown is not an exemption.
	if ja4 != "" && matchAnyJA4(r.ja4Excluded, ja4) {
		return false
	}
	return true
}

// findProtectedRule returns the first compiled rule matching the
// authority/path/ja4 triple, or nil. Query strings are stripped from the
// path; the authority is lowercased and its port stripped. No allocations
// for already-normalized (lowercase, portless) authorities. The returned
// rule carries the per-rule difficulty override (if any).
func findProtectedRule(rules []protectedRule, authority, path, ja4 string) *protectedRule {
	host := normalizeAuthority(authority)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for i := range rules {
		if rules[i].matches(host, path, ja4) {
			return &rules[i]
		}
	}
	return nil
}

// matchProtectedRules is the boolean form of findProtectedRule.
func matchProtectedRules(rules []protectedRule, authority, path, ja4 string) bool {
	return findProtectedRule(rules, authority, path, ja4) != nil
}

// normalizeAuthority lowercases an :authority value and strips the port
// ("Foo.Bar:8443" → "foo.bar"). Bare IPv6 (multiple colons) is lowercased
// as-is; bracketed forms "[::1]:8443" keep only the address.
func normalizeAuthority(a string) string {
	if strings.HasPrefix(a, "[") {
		if i := strings.IndexByte(a, ']'); i >= 0 {
			return strings.ToLower(a[1:i])
		}
		return strings.ToLower(a)
	}
	if i := strings.LastIndexByte(a, ':'); i > 0 {
		rest := a[i+1:]
		digits := true
		for j := 0; j < len(rest); j++ {
			if rest[j] < '0' || rest[j] > '9' {
				digits = false
				break
			}
		}
		// Single colon followed by digits → host:port. Bare IPv6 (::1)
		// has multiple colons and is left intact.
		if digits && strings.IndexByte(a[:i], ':') < 0 {
			return strings.ToLower(a[:i])
		}
	}
	return strings.ToLower(a)
}

// parseProtectedConfig compiles the `protected` config list.
//
// globalMin/globalMax are the plugin's [min_difficulty, max_difficulty]
// bounds; per-rule `difficulty` values are clamped to them at parse time.
//
// Returns the compiled rules and protectAll (true when the feature is
// unconfigured — key absent, empty list, non-array, or every rule invalid —
// meaning "challenge everything", the legacy behavior). problems carries one
// human-readable description per dropped rule (or clamped value) for the
// plugin error log.
func parseProtectedConfig(data []byte, globalMin, globalMax uint) (rules []protectedRule, protectAll bool, problems []string) {
	top := gjson.GetBytes(data, "protected")
	if !top.Exists() {
		return nil, true, nil
	}
	if !top.IsArray() {
		return nil, true, []string{"`protected` must be an array of rule objects; ignoring it and challenging all requests"}
	}

	seen := 0
	top.ForEach(func(_, entry gjson.Result) bool {
		seen++
		rule, probs := compileProtectedRule(entry, seen, globalMin, globalMax)
		problems = append(problems, probs...)
		if rule != nil {
			rules = append(rules, *rule)
		}
		return true
	})

	if seen == 0 {
		// Empty list ⇒ challenge everything (backward compatible default).
		return nil, true, nil
	}
	if len(rules) == 0 {
		return nil, true, append(problems, "every `protected` rule was invalid; falling back to challenging all requests")
	}
	return rules, false, problems
}

// compileProtectedRule validates and compiles one raw rule object.
// Returns nil when the rule must be dropped (with reasons in problems).
func compileProtectedRule(entry gjson.Result, index int, globalMin, globalMax uint) (*protectedRule, []string) {
	bad := func(reason string) (*protectedRule, []string) {
		return nil, []string{"rule #" + strconv.Itoa(index) + ": " + reason + "; dropping rule"}
	}

	if !entry.IsObject() {
		return bad("entry is not an object")
	}

	hostsJ := entry.Get("hosts")
	pathsJ := entry.Get("paths")
	if !hostsJ.Exists() && !pathsJ.Exists() {
		// Spec: an empty rule matches nothing — dropping it has the same
		// effect and keeps the compiled list clean.
		return bad("rule has neither `hosts` nor `paths`; treating as match-nothing")
	}

	var rule protectedRule
	anyHost := true
	if hostsJ.Exists() && !(hostsJ.IsArray() && len(hostsJ.Array()) == 0) {
		if !hostsJ.IsArray() {
			return bad("`hosts` must be an array of strings")
		}
		var hosts []protectedHost
		var probs []string
		valid := true
		hostsJ.ForEach(func(_, h gjson.Result) bool {
			if h.Type != gjson.String {
				probs = append(probs, "rule #"+strconv.Itoa(index)+": non-string `hosts` entry; dropping rule")
				valid = false
				return false
			}
			host, wild, ok := compileProtectedHost(h.String())
			if !ok {
				probs = append(probs, "rule #"+strconv.Itoa(index)+": invalid host `"+h.String()+"`; dropping rule")
				valid = false
				return false
			}
			if wild {
				hosts = append(hosts, protectedHost{dotSuffix: "." + host})
			} else {
				hosts = append(hosts, protectedHost{exact: host})
			}
			return true
		})
		if !valid {
			return nil, probs
		}
		rule.hosts = hosts
		anyHost = false
	}

	anyPath := true
	if pathsJ.Exists() && !(pathsJ.IsArray() && len(pathsJ.Array()) == 0) {
		if !pathsJ.IsArray() {
			return bad("`paths` must be an array of strings")
		}
		var paths []string
		var probs []string
		valid := true
		pathsJ.ForEach(func(_, p gjson.Result) bool {
			if p.Type != gjson.String {
				probs = append(probs, "rule #"+strconv.Itoa(index)+": non-string `paths` entry; dropping rule")
				valid = false
				return false
			}
			if p.String() == "" {
				probs = append(probs, "rule #"+strconv.Itoa(index)+": empty `paths` entry; dropping rule")
				valid = false
				return false
			}
			paths = append(paths, p.String())
			return true
		})
		if !valid {
			return nil, probs
		}
		rule.paths = paths
		anyPath = false
	}

	rule.anyHost = anyHost
	rule.anyPath = anyPath

	// ja4 / ja4_excluded: optional fingerprint dimensions (docs/ja4-support.md
	// §4). Invalid entries are dropped individually; a list that ends up
	// empty behaves as if the dimension were absent. The lists are compiled
	// regardless of whether ja4_header is configured — the request-time
	// lookup is what gates them (unknown fingerprints never match a positive
	// list, and vetoes never apply to unknown).
	var problems []string
	var probs []string
	rule.ja4, probs = compileJA4List(entry.Get("ja4"), index)
	problems = append(problems, probs...)
	rule.ja4Excluded, probs = compileJA4List(entry.Get("ja4_excluded"), index)
	problems = append(problems, probs...)

	// difficulty: optional per-rule base override. min/max are accepted for
	// schema compatibility but have no effect — the global bounds are the
	// only clamp (docs/ja4-support.md §4).
	if diffJ := entry.Get("difficulty"); diffJ.Exists() {
		if !diffJ.IsObject() {
			return bad("`difficulty` must be an object with a numeric `base`")
		}
		baseJ := diffJ.Get("base")
		// Int() (not Uint()): negative JSON numbers wrap into huge uints.
		baseInt := baseJ.Int()
		if !baseJ.Exists() || baseInt <= 0 {
			return bad("`difficulty` must include a numeric `base` > 0")
		}
		base := uint(baseInt)
		if clamped := clampDifficulty(base, globalMin, globalMax); clamped != base {
			problems = append(problems, "rule #"+strconv.Itoa(index)+": difficulty base "+strconv.FormatUint(uint64(base), 10)+
				" outside global bounds; clamped to "+strconv.FormatUint(uint64(clamped), 10))
			base = clamped
		}
		rule.difficultyBase = base
		rule.hasDifficulty = true
	}

	return &rule, problems
}

// compileProtectedHost validates one host entry. Returns the lowercased
// host (wildcard suffix stripped for wildcards) and whether it was a
// wildcard ("*.suffix" — matches exactly one extra leftmost label).
func compileProtectedHost(h string) (host string, wild bool, ok bool) {
	if h == "" {
		return "", false, false
	}
	if strings.HasPrefix(h, "*.") {
		suffix := strings.ToLower(h[2:])
		if suffix == "" || strings.ContainsAny(suffix, "*") {
			return "", false, false
		}
		return suffix, true, true
	}
	if strings.Contains(h, "*") {
		// "*", "**.x", "a.*.b" — only the single leading wildcard is supported.
		return "", false, false
	}
	return strings.ToLower(h), false, true
}
