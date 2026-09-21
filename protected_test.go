package main

import (
	"strings"
	"testing"
)

// compile takes a raw plugin config JSON and returns (rules, protectAll).
func compile(t *testing.T, config string) ([]protectedRule, bool) {
	t.Helper()
	rules, protectAll, problems := parseProtectedConfig([]byte(config))
	for _, p := range problems {
		t.Logf("config problem: %s", p)
	}
	return rules, protectAll
}

func TestProtectedAbsentChallengesAll(t *testing.T) {
	// Spec case 1: no `protected` key ⇒ challenge everything (compat).
	_, protectAll := compile(t, `{"secret":"0123456789abcdef0123456789abcdef"}`)
	if !protectAll {
		t.Fatal("absent `protected` must protect everything")
	}
}

func TestProtectedEmptyListChallengesAll(t *testing.T) {
	// Spec case 2: empty list ⇒ challenge everything.
	_, protectAll := compile(t, `{"protected":[]}`)
	if !protectAll {
		t.Fatal("empty `protected` must protect everything")
	}
	// Non-array garbage is treated the same (boring + safe).
	_, protectAll = compile(t, `{"protected":"yes"}`)
	if !protectAll {
		t.Fatal("non-array `protected` must protect everything")
	}
}

func TestProtectedHostAndPathMatching(t *testing.T) {
	// Spec case 3: host exact + path prefix; wildcard-1 semantics.
	rules, protectAll := compile(t, `{"protected":[
		{"hosts":["kanidm.example.org"],"paths":["/login","/admin"]},
		{"hosts":["*.sub.example.org"],"paths":["/api/write"]}
	]}`)
	if protectAll {
		t.Fatal("valid rules must not trigger protect-all")
	}
	cases := []struct {
		authority, path string
		want            bool
	}{
		{"kanidm.example.org", "/login", true},       // exact host + prefix path
		{"kanidm.example.org", "/admin/users", true}, // prefix covers subpaths
		{"kanidm.example.org", "/logout", false},     // path not listed
		{"other.example.org", "/login", false},       // host not listed
		{"a.sub.example.org", "/api/write", true},    // wildcard: one extra label
		{"a.sub.example.org", "/api/read", false},    // path mismatch
		{"sub.example.org", "/api/write", false},     // wildcard needs the extra label
		{"a.b.sub.example.org", "/api/write", false}, // two extra labels: NOT matched
	}
	for _, tc := range cases {
		if got := matchProtectedRules(rules, tc.authority, tc.path); got != tc.want {
			t.Errorf("match(%q, %q) = %v, want %v", tc.authority, tc.path, got, tc.want)
		}
	}
}

func TestProtectedPortStripAndCaseFold(t *testing.T) {
	// Spec case 4: port stripping + case folding on the authority.
	rules, _ := compile(t, `{"protected":[{"hosts":["foo.bar"],"paths":["/"]}]}`)
	cases := []struct {
		authority string
		want      bool
	}{
		{"foo.bar", true},
		{"FOO.BAR", true},
		{"Foo.Bar:8443", true},
		{"foo.bar:80", true},
		{"foo.bar.evil.com", false},
		{"evil.com", false},
	}
	for _, tc := range cases {
		if got := matchProtectedRules(rules, tc.authority, "/x"); got != tc.want {
			t.Errorf("match(%q) = %v, want %v", tc.authority, got, tc.want)
		}
	}
}

func TestProtectedQueryStripped(t *testing.T) {
	// Spec case 5: query string stripped before prefix match.
	rules, _ := compile(t, `{"protected":[{"hosts":["h.example"],"paths":["/login"]}]}`)
	if !matchProtectedRules(rules, "h.example", "/login?x=1&y=2") {
		t.Fatal("/login?x=1 must match /login prefix")
	}
	// Documented wart: bare prefix semantics — /loginout prefix-matches
	// /login. Accepted per spec (exact-match mode is out of scope for v1).
	if !matchProtectedRules(rules, "h.example", "/loginout") {
		t.Fatal("/loginout must prefix-match /login (documented wart)")
	}
}

func TestProtectedOrAcrossAndWithin(t *testing.T) {
	// Spec case 6: rules OR-ed; within a rule host AND path must hold.
	rules, _ := compile(t, `{"protected":[
		{"hosts":["a.example"],"paths":["/x"]},
		{"hosts":["b.example"],"paths":["/y"]}
	]}`)
	if !matchProtectedRules(rules, "a.example", "/x") {
		t.Fatal("rule 1 host+path must match")
	}
	if !matchProtectedRules(rules, "b.example", "/y") {
		t.Fatal("rule 2 host+path must match (OR)")
	}
	if matchProtectedRules(rules, "a.example", "/y") {
		t.Error("host from rule 1 with path from rule 2 must NOT match")
	}
	if matchProtectedRules(rules, "b.example", "/x") {
		t.Error("host from rule 2 with path from rule 1 must NOT match")
	}
}

func TestProtectedEmptyRuleMatchesNothing(t *testing.T) {
	// Spec case 7: empty rule matches nothing — other rules still work.
	rules, protectAll := compile(t, `{"protected":[{},{"hosts":["a.example"]}]}`)
	if protectAll {
		t.Fatal("one valid rule must keep selective mode on")
	}
	if !matchProtectedRules(rules, "a.example", "/anything") {
		t.Fatal("valid rule must still match")
	}
	if matchProtectedRules(rules, "other.example", "/anything") {
		t.Fatal("empty rule must contribute no matches")
	}
	// An empty rule ALONE makes the whole list invalid ⇒ protect-everything.
	_, protectAll = compile(t, `{"protected":[{}]}`)
	if !protectAll {
		t.Fatal("all-invalid rules must fall back to challenge-everything")
	}
}

func TestProtectedMalformedHostDropped(t *testing.T) {
	// Spec case 8: bad wildcard ⇒ dropped; alone ⇒ protect-everything fallback.
	if _, protectAll := compile(t, `{"protected":[{"hosts":["**.x.example"]}]}`); !protectAll {
		t.Fatal("all-invalid (malformed host) must fall back to protect-everything")
	}
	rules, protectAll := compile(t, `{"protected":[{"hosts":["**.x.example"]},{"hosts":["good.example"]}]}`)
	if protectAll {
		t.Fatal("valid sibling rule must keep selective mode on")
	}
	if !matchProtectedRules(rules, "good.example", "/") {
		t.Fatal("valid rule must survive an invalid sibling")
	}
	if matchProtectedRules(rules, "x.example", "/") {
		t.Fatal("dropped rule must not match")
	}
}

func TestProtectedMissingFieldMeansAny(t *testing.T) {
	// hosts missing ⇒ any host; paths missing ⇒ any path.
	rules, _ := compile(t, `{"protected":[{"paths":["/login"]},{"hosts":["apex.example"]}]}`)
	if !matchProtectedRules(rules, "anything.example", "/login") {
		t.Fatal("missing hosts must match any host")
	}
	if !matchProtectedRules(rules, "apex.example", "/whatever") {
		t.Fatal("missing paths must match any path")
	}
	if matchProtectedRules(rules, "anything.example", "/other") {
		t.Fatal("path rule must still constrain the path")
	}
}

func TestNormalizeAuthority(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Foo.Bar:8443", "foo.bar"},
		{"foo.bar", "foo.bar"},
		{"EXAMPLE.com", "example.com"},
		{"foo.bar:80", "foo.bar"},
		{"::1", "::1"},        // bare IPv6: no port stripping
		{"[::1]:8443", "::1"}, // bracketed IPv6 with port
		{"[2001:DB8::1]", "2001:db8::1"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := normalizeAuthority(tc.in); got != tc.want {
			t.Errorf("normalizeAuthority(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProtectedMatcherZeroAlloc(t *testing.T) {
	// Spec case 9: the compiled matcher walk must not allocate.
	rules, protectAll := compile(t, `{"protected":[
		{"hosts":["kanidm.example.org"],"paths":["/login","/admin"]},
		{"hosts":["*.sub.example.org"],"paths":["/api/write"]},
		{"hosts":["signoz.example.org"],"paths":["/"]},
		{"hosts":["a.example"]},
		{"hosts":["b.example"],"paths":["/x","/y","/z"]},
		{"hosts":["c.example","d.example"],"paths":["/w"]},
		{"hosts":["e.example"],"paths":["/v"]},
		{"hosts":["f.example"],"paths":["/u"]}
	]}`)
	if protectAll || len(rules) != 8 {
		t.Fatalf("expected 8 compiled rules, got %d (protectAll=%v)", len(rules), protectAll)
	}
	host := normalizeAuthority("kanidm.example.org")
	path := "/login?session=abc"
	if allocs := testing.AllocsPerRun(100, func() {
		_ = matchProtectedRules(rules, host, path)
	}); allocs != 0 {
		t.Fatalf("matcher allocated %v times per run, want 0", allocs)
	}
	// Uppercase authority allocates once inside strings.ToLower — documented
	// single alloc, still no per-rule cost.
	if allocs := testing.AllocsPerRun(100, func() {
		_ = matchProtectedRules(rules, "Kanidm.Example.org", path)
	}); allocs > 1 {
		t.Fatalf("matcher allocated %v times per run with uppercase authority, want <= 1", allocs)
	}
}

func BenchmarkProtectedMatch8Rules(b *testing.B) {
	rules, _, _ := parseProtectedConfig([]byte(`{"protected":[
		{"hosts":["kanidm.example.org"],"paths":["/login","/admin"]},
		{"hosts":["*.sub.example.org"],"paths":["/api/write"]},
		{"hosts":["signoz.example.org"],"paths":["/"]},
		{"hosts":["a.example"]},
		{"hosts":["b.example"],"paths":["/x","/y","/z"]},
		{"hosts":["c.example","d.example"],"paths":["/w"]},
		{"hosts":["e.example"],"paths":["/v"]},
		{"hosts":["f.example"],"paths":["/u"]}
	]}`))
	host := normalizeAuthority("dashboard.example.org")
	path := "/api/write?stream=1"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = matchProtectedRules(rules, host, path)
	}
}

func TestProtectedCompileRejectsBadEntries(t *testing.T) {
	// Non-string list entries, empty host/path strings, stray wildcards.
	configs := []string{
		`{"protected":[{"hosts":[1,2]}]}`,
		`{"protected":[{"hosts":[""]}]} `,
		`{"protected":[{"hosts":["*"]}]}`,
		`{"protected":[{"hosts":["*."]}]}`,
		`{"protected":[{"hosts":["a.*.b"]}]}`,
		`{"protected":[{"paths":[""]}]} `,
		`{"protected":[{"paths":"notanarray"}]}`,
		`{"protected":["notanobject"]}`,
	}
	for _, cfg := range configs {
		rules, protectAll := compile(t, cfg)
		if len(rules) != 0 {
			t.Errorf("config %s: expected all rules dropped, got %d", strings.TrimSpace(cfg), len(rules))
		}
		if !protectAll {
			t.Errorf("config %s: expected protect-everything fallback", strings.TrimSpace(cfg))
		}
	}
}
