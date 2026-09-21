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
}

func (r *protectedRule) matches(host, path string) bool {
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
	return true
}

// matchProtectedRules reports whether an authority/path pair matches any
// compiled rule. Query strings are stripped from the path; the authority is
// lowercased and its port stripped. No allocations for already-normalized
// (lowercase, portless) authorities.
func matchProtectedRules(rules []protectedRule, authority, path string) bool {
	host := normalizeAuthority(authority)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for i := range rules {
		if rules[i].matches(host, path) {
			return true
		}
	}
	return false
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
// Returns the compiled rules and protectAll (true when the feature is
// unconfigured — key absent, empty list, non-array, or every rule invalid —
// meaning "challenge everything", the legacy behavior). problems carries one
// human-readable description per dropped rule for the plugin error log.
func parseProtectedConfig(data []byte) (rules []protectedRule, protectAll bool, problems []string) {
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
		rule, probs := compileProtectedRule(entry, seen)
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
func compileProtectedRule(entry gjson.Result, index int) (*protectedRule, []string) {
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
	return &rule, nil
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
