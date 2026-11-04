// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
//
// JA4 fingerprint input (docs/ja4-support.md): the plugin cannot see the TLS
// ClientHello (the proxy-wasm ABI exposes no JA4 property), so the edge —
// Envoy tls_inspector ≥ 1.35 plus an HCM header substitution — computes the
// fingerprint and injects it as a request header named by `ja4_header`. The
// header is unauthenticated; it is trusted only because the edge strips
// client-supplied values of that name before injecting its own (§3). The
// plugin additionally treats every structurally invalid value as unknown, so
// a leaked spoof can never select a class by accident.
//
// JA4 is per-connection: HTTP/2 multiplexes many requests over one
// ClientHello, so every request on a connection carries the same fingerprint.
// That is expected, not a bug.
//
// Feature off (`ja4_header` absent/empty): no rule's JA4 dimension can ever
// match (unknown fingerprints never match a positive list) and vetoes never
// apply — zero behavior change for legacy configs.
package main

import (
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// ja4FPLen is the exact length of a JA4 fingerprint:
// 10 (part a) + 1 underscore + 12 (part b) + 1 underscore + 12 (part c).
const ja4FPLen = 36

// parseJA4Config reads `ja4_header`: the request header carrying the
// edge-injected JA4 fingerprint. Empty/absent ⇒ feature off. A non-empty but
// structurally invalid header name is rejected (problem + feature off) —
// never half-enable.
func parseJA4Config(data []byte) (headerName string, problems []string) {
	v := gjson.GetBytes(data, "ja4_header")
	if !v.Exists() {
		return "", nil
	}
	if v.Type != gjson.String {
		return "", []string{"`ja4_header` must be a string header name; feature stays off"}
	}
	raw := strings.TrimSpace(v.Str)
	if raw == "" {
		return "", nil
	}
	h := strings.ToLower(raw)
	if strings.ContainsAny(h, " :") || len(h) > 64 {
		return "", []string{"ja4_header " + strconv.Quote(raw) + " is not a valid header name (no spaces or colons, max 64 chars); feature stays off"}
	}
	return h, nil
}

// ja4Kind selects which part of the fingerprint a compiled entry pins.
type ja4Kind uint8

const (
	ja4Full    ja4Kind = iota // exact full fingerprint
	ja4PartA                  // exact part a (transport+version+SNI+counts+ALPN class)
	ja4PrefixA                // part-a prefix — the only wildcard form (`a=t13d*`)
	ja4PartB                  // exact part b (cipher-list hash)
	ja4PartC                  // exact part c (extension+sigalg hash)
)

// ja4Matcher is one compiled selector entry (docs/ja4-support.md §4).
// Stored strings are lowercase; matches() does in-place byte compares and
// allocates nothing.
type ja4Matcher struct {
	kind ja4Kind
	a    string // part a: exact 10 chars, or the prefix chars for ja4PrefixA
	b    string // part b: 12 lowercase hex
	c    string // part c: 12 lowercase hex
}

func (m ja4Matcher) matches(fp string) bool {
	// Covers unknown ("") too, so slicing below can never panic.
	if len(fp) != ja4FPLen {
		return false
	}
	switch m.kind {
	case ja4Full:
		return fp[:10] == m.a && fp[11:23] == m.b && fp[24:] == m.c
	case ja4PartA:
		return fp[:10] == m.a
	case ja4PrefixA:
		return strings.HasPrefix(fp[:10], m.a)
	case ja4PartB:
		return fp[11:23] == m.b
	case ja4PartC:
		return fp[24:] == m.c
	}
	return false
}

// matchAnyJA4 ORs a compiled list. An empty list matches nothing (a rule
// whose ja4 list ended up empty after validation behaves as if the dimension
// were absent — see protectedRule.matches).
func matchAnyJA4(list []ja4Matcher, fp string) bool {
	for i := range list {
		if list[i].matches(fp) {
			return true
		}
	}
	return false
}

// compileJA4List compiles a rule's `ja4` / `ja4_excluded` list. Invalid
// entries are dropped with one problem each; a list that ends up empty
// behaves as if the dimension were absent — never "challenge everything" by
// accident.
func compileJA4List(raw gjson.Result, index int) (m []ja4Matcher, problems []string) {
	if !raw.Exists() {
		return nil, nil
	}
	if !raw.IsArray() {
		return nil, []string{"rule #" + strconv.Itoa(index) + ": `ja4` must be an array of selector strings; ignoring the dimension"}
	}
	raw.ForEach(func(_, e gjson.Result) bool {
		if e.Type != gjson.String {
			problems = append(problems, "rule #"+strconv.Itoa(index)+": non-string ja4 entry; dropping entry")
			return true
		}
		matcher, reason := compileJA4Entry(e.String())
		if reason != "" {
			problems = append(problems, "rule #"+strconv.Itoa(index)+": invalid ja4 selector `"+e.String()+"`: "+reason+"; dropping entry")
			return true
		}
		m = append(m, matcher)
		return true
	})
	return m, problems
}

// compileJA4Entry validates one selector entry (docs/ja4-support.md §4):
// a bare full fingerprint, or `a=` (exact 10-char part a, or a trailing-`*`
// prefix — the only wildcard), or `b=`/`c=` (exact 12 lowercase hex).
// Returns the compiled matcher, or a rejection reason.
func compileJA4Entry(s string) (ja4Matcher, string) {
	if s == "" {
		return ja4Matcher{}, "empty entry"
	}
	if strings.HasPrefix(s, "*") {
		return ja4Matcher{}, "leading wildcard (only a trailing `*` on an `a=` entry is supported)"
	}
	key, value, hasEq := strings.Cut(s, "=")
	if !hasEq {
		if len(s) != ja4FPLen || s[10] != '_' || s[23] != '_' ||
			!validJA4PartA(s[:10]) || !isLowerHex(s[11:23]) || !isLowerHex(s[24:]) {
			return ja4Matcher{}, "not a full fingerprint (tQQddccaa_hhhhhhhhhhhh_hhhhhhhhhhhh) and not a key=value selector"
		}
		return ja4Matcher{kind: ja4Full, a: s[:10], b: s[11:23], c: s[24:]}, ""
	}
	if value == "" {
		return ja4Matcher{}, "empty value"
	}
	switch key {
	case "a":
		if strings.HasSuffix(value, "*") {
			prefix := value[:len(value)-1]
			if strings.Contains(prefix, "*") {
				return ja4Matcher{}, "wildcard must be the trailing character"
			}
			if !validJA4PrefixA(prefix) {
				return ja4Matcher{}, "invalid part-a prefix (lowercase t|q|d, then alphanumeric version/count chars, `d`|`i` at position 4)"
			}
			return ja4Matcher{kind: ja4PrefixA, a: prefix}, ""
		}
		if strings.Contains(value, "*") {
			return ja4Matcher{}, "wildcard must be the trailing character"
		}
		if !validJA4PartA(value) {
			return ja4Matcher{}, "part a must be exactly 10 lowercase chars (t|q|d + version + d|i + counts + ALPN)"
		}
		return ja4Matcher{kind: ja4PartA, a: value}, ""
	case "b", "c":
		if strings.Contains(value, "*") {
			return ja4Matcher{}, "wildcard is only supported on `a=` entries"
		}
		if len(value) != 12 || !isLowerHex(value) {
			return ja4Matcher{}, "part " + key + " must be exactly 12 lowercase hex chars"
		}
		if key == "b" {
			return ja4Matcher{kind: ja4PartB, b: value}, ""
		}
		return ja4Matcher{kind: ja4PartC, c: value}, ""
	default:
		return ja4Matcher{}, "unknown key (expected a=, b=, c=, or a bare fingerprint)"
	}
}

// normalizeJA4 validates a raw header value and returns the canonical
// fingerprint, or "" (unknown) for absent/placeholder/garbage values (§3.5
// header hygiene). Structure and charset are checked, not just length:
// t|q|d + 2 version chars + d|i + 2 count chars + 2 count chars + 2 ALPN
// chars, then `_`, 12 lowercase hex, `_`, 12 lowercase hex.
func normalizeJA4(v string) string {
	if v == "" || v == "-" || v == "unknown" {
		return ""
	}
	if len(v) != ja4FPLen || v[10] != '_' || v[23] != '_' {
		return ""
	}
	if !validJA4PartA(v[:10]) || !isLowerHex(v[11:23]) || !isLowerHex(v[24:]) {
		return ""
	}
	return v
}

// validJA4PartA checks a complete part a (10 chars): transport char, SNI
// marker, lowercase alphanumeric version/count/ALPN chars in their slots.
func validJA4PartA(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[0] != 't' && s[0] != 'q' && s[0] != 'd' {
		return false
	}
	if s[3] != 'd' && s[3] != 'i' {
		return false
	}
	return isLowerAlphaNum(s[1:3]) && isLowerAlphaNum(s[4:])
}

// validJA4PrefixA checks a part-a prefix (the value of `a=t13d*`, without
// the wildcard): 1-9 chars with the same per-slot constraints as a complete
// part a wherever the prefix reaches them.
func validJA4PrefixA(s string) bool {
	if len(s) == 0 || len(s) >= 10 {
		return false
	}
	if s[0] != 't' && s[0] != 'q' && s[0] != 'd' {
		return false
	}
	if len(s) >= 4 && s[3] != 'd' && s[3] != 'i' {
		return false
	}
	return isLowerAlphaNum(s[1:])
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isLowerAlphaNum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
