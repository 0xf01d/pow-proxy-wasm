package main

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

const (
	// Shape-valid fingerprints (values are illustrative, per docs/ja4-support.md §5).
	ja4TestFP  = "t13d1516h2_8daaf6152771_b186095e22b6"
	ja4TestFP2 = "t12d2116h1_9fd4d8ad2b64_5b495ccfc4bd"
	ja4TestFP3 = "t13d1516h2_111111111111_222222222222"
)

func TestNormalizeJA4(t *testing.T) {
	valid := []string{
		ja4TestFP,
		"q13d0203h3_a1b2c3d4e5f6_0123456789ab",
		"t11i0000no_000000000000_000000000000",
	}
	for _, fp := range valid {
		if got := normalizeJA4(fp); got != fp {
			t.Errorf("normalizeJA4(%q) = %q, want identity", fp, got)
		}
	}
	invalid := []string{
		"",
		"-",
		"unknown",
		"t13d1516h2_8DAAF6152771_b186095e22b6", // uppercase hex (part b)
		"t13d1516h2_8daaf6152771_B186095E22B6", // uppercase hex (part c)
		"T13D1516H2_8daaf6152771_b186095e22b6", // uppercase part a
		ja4TestFP[:25],                         // 25 chars
		ja4TestFP[:27],                         // 27 chars
		ja4TestFP + "x",                        // 37 chars
		"t13d1516h2x8daaf6152771xb186095e22b6", // right length, no underscores
		"t13d1516h2_8daaf615277g_b186095e22b6", // non-hex part b
		"x13d1516h2_8daaf6152771_b186095e22b6", // bad transport char
		"t13x1516h2_8daaf6152771_b186095e22b6", // bad SNI slot
	}
	for _, v := range invalid {
		if got := normalizeJA4(v); got != "" {
			t.Errorf("normalizeJA4(%q) = %q, want unknown", v, got)
		}
	}
}

func TestCompileJA4EntryAccepted(t *testing.T) {
	cases := []struct {
		entry string
		want  ja4Matcher
	}{
		{ja4TestFP, ja4Matcher{kind: ja4Full, a: "t13d1516h2", b: "8daaf6152771", c: "b186095e22b6"}},
		{"a=t13d1516h2", ja4Matcher{kind: ja4PartA, a: "t13d1516h2"}},
		{"a=t13d*", ja4Matcher{kind: ja4PrefixA, a: "t13d"}},
		{"a=t13d1516*", ja4Matcher{kind: ja4PrefixA, a: "t13d1516"}},
		{"a=t*", ja4Matcher{kind: ja4PrefixA, a: "t"}},
		{"b=8daaf6152771", ja4Matcher{kind: ja4PartB, b: "8daaf6152771"}},
		{"c=b186095e22b6", ja4Matcher{kind: ja4PartC, c: "b186095e22b6"}},
	}
	for _, tc := range cases {
		got, reason := compileJA4Entry(tc.entry)
		if reason != "" {
			t.Errorf("compileJA4Entry(%q) rejected: %s", tc.entry, reason)
			continue
		}
		if got != tc.want {
			t.Errorf("compileJA4Entry(%q) = %+v, want %+v", tc.entry, got, tc.want)
		}
	}
}

func TestCompileJA4EntryRejected(t *testing.T) {
	rejected := []string{
		"",
		"*t13d1516h2_8daaf6152771_b186095e22b6", // leading wildcard
		"a=t13*5",                               // wildcard in the middle
		"a=*t13d",                               // leading wildcard inside a=
		"b=8daaf6152771*",                       // wildcard on b=
		"b=8daaf615277",                         // 11 hex chars
		"b=8daaf61527711",                       // 13 hex chars
		"d=t13d1516h2",                          // unknown key
		"x=foo",                                 // unknown key
		"a=",                                    // empty value
		"b=",                                    // empty value
		"c=B186095E22B6",                        // uppercase hex
		"a=t13d1516H2",                          // uppercase part a
		"A=t13d1516h2",                          // uppercase key
		"t13d1516h2_8daaf6152771_b186095e22b",   // 35 chars
		"t13d1516h2_8daaf6152771_b186095e22b6x", // 37 chars
		"t13d1516h2_8daaf6152771xb186095e22b6",  // no underscores
		"t13d1516h2_8daaf615277g_b186095e22b6",  // non-hex bare fingerprint
	}
	for _, entry := range rejected {
		if _, reason := compileJA4Entry(entry); reason == "" {
			t.Errorf("compileJA4Entry(%q) accepted, want rejection", entry)
		}
	}
}

func TestCompileJA4List(t *testing.T) {
	m, problems := compileJA4List(gjson.Parse(`["`+ja4TestFP+`", "a=t13*5", "b=8daaf6152771"]`), 1)
	if len(m) != 2 {
		t.Fatalf("expected 2 valid matchers, got %d", len(m))
	}
	if len(problems) != 1 {
		t.Fatalf("expected 1 problem for the invalid entry, got %v", problems)
	}

	m, problems = compileJA4List(gjson.Parse(`"notanarray"`), 1)
	if m != nil || len(problems) != 1 {
		t.Fatalf("non-array list: got %d matchers, %d problems", len(m), len(problems))
	}

	m, problems = compileJA4List(gjson.Parse(`[1, "a=t13d*"]`), 1)
	if len(m) != 1 || len(problems) != 1 {
		t.Fatalf("non-string entry: got %d matchers, %d problems", len(m), len(problems))
	}

	// Absent field: no matchers, no problems.
	m, problems = compileJA4List(gjson.Result{}, 1)
	if m != nil || problems != nil {
		t.Fatalf("absent list: got %d matchers, %d problems", len(m), len(problems))
	}
}

func TestJA4Matching(t *testing.T) {
	cases := []struct {
		list    string
		fp      string
		matches bool
	}{
		{`["` + ja4TestFP + `"]`, ja4TestFP, true},   // exact full fingerprint
		{`["` + ja4TestFP + `"]`, ja4TestFP2, false}, // different fingerprint
		{`["` + ja4TestFP + `"]`, ja4TestFP3, false},
		{`["a=t13d1516h2"]`, ja4TestFP, true},  // exact part a
		{`["a=t13d1516h2"]`, ja4TestFP3, true}, // same part a, different b/c
		{`["a=t13d1516h2"]`, ja4TestFP2, false},
		{`["a=t13d*"]`, ja4TestFP, true},  // prefix matches
		{`["a=t13d*"]`, ja4TestFP3, true}, // prefix matches
		{`["a=t13d*"]`, ja4TestFP2, false},
		{`["a=t12d*"]`, ja4TestFP2, true},
		{`["a=t12d*"]`, ja4TestFP, false},
		{`["b=8daaf6152771"]`, ja4TestFP, true}, // cipher hash
		{`["b=8daaf6152771"]`, ja4TestFP2, false},
		{`["c=b186095e22b6"]`, ja4TestFP, true}, // extension hash
		{`["c=b186095e22b6"]`, ja4TestFP3, false},
		// OR inside the list.
		{`["a=t12d*", "b=111111111111"]`, ja4TestFP2, true},
		{`["a=t12d*", "b=111111111111"]`, ja4TestFP3, true},
		{`["a=t12d*", "b=111111111111"]`, ja4TestFP, false},
	}
	for _, tc := range cases {
		list, problems := compileJA4List(gjson.Parse(tc.list), 1)
		if len(problems) != 0 {
			t.Fatalf("list %s: unexpected problems %v", tc.list, problems)
		}
		if got := matchAnyJA4(list, tc.fp); got != tc.matches {
			t.Errorf("matchAnyJA4(%s, %q) = %v, want %v", tc.list, tc.fp, got, tc.matches)
		}
	}
}

func TestJA4UnknownNeverMatches(t *testing.T) {
	positive, _ := compileJA4List(gjson.Parse(`["a=t13d*", "`+ja4TestFP+`"]`), 1)
	veto, _ := compileJA4List(gjson.Parse(`["a=t13d*", "`+ja4TestFP+`"]`), 1)
	// Unknown fingerprint: positive lists can never match, veto lists never fire.
	if matchAnyJA4(positive, "") {
		t.Fatal("unknown fingerprint must not match a positive list")
	}
	if matchAnyJA4(veto, "") {
		t.Fatal("unknown fingerprint must not trigger a veto list")
	}
	// Non-fingerprint garbage behaves the same (normalizeJA4 → unknown).
	if matchAnyJA4(positive, normalizeJA4("garbage")) {
		t.Fatal("garbage fingerprint must not match a positive list")
	}
}

// compileJA4Rules parses a protected config with fixed globals [12, 26].
func compileJA4Rules(t *testing.T, config string) ([]protectedRule, bool, []string) {
	t.Helper()
	return parseProtectedConfig([]byte(config), 12, 26)
}

func TestJA4RulePositiveAndVeto(t *testing.T) {
	rules, protectAll, problems := compileJA4Rules(t, `{"protected":[
		{"hosts":["api.example"],"paths":["/write"],
		 "ja4":["a=t13d*", "`+ja4TestFP3+`"],
		 "ja4_excluded":["`+ja4TestFP3+`"]}
	]}`)
	if protectAll || len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule (protectAll=%v)", protectAll)
	}
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	cases := []struct {
		fp      string
		matches bool
		note    string
	}{
		{ja4TestFP, true, "in positive class, not vetoed"},
		{ja4TestFP3, false, "vetoed after positive match"},
		{ja4TestFP2, false, "outside positive class"},
		{"", false, "unknown never matches a positive list"},
	}
	for _, tc := range cases {
		if got := findProtectedRule(rules, "api.example", "/write", tc.fp) != nil; got != tc.matches {
			t.Errorf("fp %q (%s): matched=%v, want %v", tc.fp, tc.note, got, tc.matches)
		}
	}
	// The veto must not leak outside the rule's hosts/paths.
	if findProtectedRule(rules, "api.example", "/read", ja4TestFP) != nil {
		t.Error("veto rule must stay constrained by paths")
	}
}

func TestJA4VetoOnlyRule(t *testing.T) {
	rules, protectAll, _ := compileJA4Rules(t, `{"protected":[
		{"hosts":["status.example"],"paths":["/healthz"],
		 "ja4_excluded":["a=t11i0000no"]}
	]}`)
	if protectAll || len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule (protectAll=%v)", protectAll)
	}
	vetoed := "t11i0000no_aaaaaaaaaaaa_bbbbbbbbbbbb"
	if findProtectedRule(rules, "status.example", "/healthz", vetoed) != nil {
		t.Error("vetoed fingerprint must not be challenged")
	}
	if findProtectedRule(rules, "status.example", "/healthz", ja4TestFP) == nil {
		t.Error("non-vetoed fingerprint must still be challenged")
	}
	// Unknown ≠ exemption (§3.4): the veto is skipped, hosts/paths decide.
	if findProtectedRule(rules, "status.example", "/healthz", "") == nil {
		t.Error("unknown fingerprint must still be challenged (veto never applies)")
	}
}

func TestProtectedJA4FeatureOff(t *testing.T) {
	// ja4_header absent ⇒ unknown lookups: positive-ja4 rules go inert,
	// veto-only rules keep protecting (unknown ≠ exemption).
	header, problems := parseJA4Config([]byte(`{"protected":[]}`))
	if header != "" || problems != nil {
		t.Fatalf("absent ja4_header: %q, %v", header, problems)
	}
	rules, protectAll, _ := compileJA4Rules(t, `{"protected":[
		{"hosts":["a.example"],"ja4":["a=t13d*"]},
		{"hosts":["b.example"],"ja4_excluded":["a=t13d*"]}
	]}`)
	if protectAll || len(rules) != 2 {
		t.Fatalf("expected 2 compiled rules (protectAll=%v)", protectAll)
	}
	if findProtectedRule(rules, "a.example", "/x", "") != nil {
		t.Error("positive-ja4 rule must never match while the feature is off")
	}
	if findProtectedRule(rules, "b.example", "/x", "") == nil {
		t.Error("veto-only rule must keep matching while the feature is off")
	}
	// Legacy parity: rules without JA4 dimensions behave exactly as before.
	if findProtectedRule(rules, "c.example", "/x", "") != nil {
		t.Error("no rule should match an unlisted host")
	}
}

func TestRuleDifficultyClamp(t *testing.T) {
	rules, protectAll, problems := compileJA4Rules(t, `{"protected":[
		{"hosts":["a.example"],"difficulty":{"base":5}},
		{"hosts":["b.example"],"difficulty":{"base":40,"min":16,"max":26}},
		{"hosts":["c.example"],"difficulty":{"base":20}},
		{"hosts":["d.example"]},
		{"hosts":["e.example"],"difficulty":{"base":"abc"}},
		{"hosts":["f.example"],"difficulty":20}
	]}`)
	if protectAll {
		t.Fatal("valid rules must keep selective mode on")
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 compiled rules (2 with invalid difficulty dropped), got %d", len(rules))
	}
	// 2 clamps (a, b) + 2 rule drops (e, f).
	if len(problems) != 4 {
		t.Fatalf("expected 4 problems, got %v", problems)
	}
	if rules[0].difficultyBase != 12 || !rules[0].hasDifficulty {
		t.Errorf("rule a: base %d hasDifficulty %v, want clamp to global min 12", rules[0].difficultyBase, rules[0].hasDifficulty)
	}
	if rules[1].difficultyBase != 26 || !rules[1].hasDifficulty {
		t.Errorf("rule b: base %d hasDifficulty %v, want clamp to global max 26 (min/max fields ignored)", rules[1].difficultyBase, rules[1].hasDifficulty)
	}
	if rules[2].difficultyBase != 20 || !rules[2].hasDifficulty {
		t.Errorf("rule c: base %d hasDifficulty %v, want in-range 20", rules[2].difficultyBase, rules[2].hasDifficulty)
	}
	if rules[3].hasDifficulty {
		t.Error("rule d without `difficulty` must leave the base unset")
	}

	// An all-invalid list falls back to challenge-everything.
	_, protectAll, _ = compileJA4Rules(t, `{"protected":[{"hosts":["g.example"],"difficulty":{}}]}`)
	if !protectAll {
		t.Fatal("rule with empty difficulty object must be dropped; all-invalid ⇒ protect-everything")
	}
	_, protectAll, _ = compileJA4Rules(t, `{"protected":[{"hosts":["g.example"],"difficulty":{"base":-3}}]}`)
	if !protectAll {
		t.Fatal("negative difficulty base must drop the rule")
	}
}

func TestJA4HeaderConfig(t *testing.T) {
	cases := []struct {
		config   string
		want     string
		problems int
	}{
		{`{"secret":"x"}`, "", 0},                  // absent ⇒ off
		{`{"ja4_header":""}`, "", 0},               // empty ⇒ off
		{`{"ja4_header":"  X-Ja4  "}`, "x-ja4", 0}, // trimmed + lowercased
		{`{"ja4_header":"x-client-tls-class"}`, "x-client-tls-class", 0},
		{`{"ja4_header":"x ja4"}`, "", 1},                           // space
		{`{"ja4_header":"x:ja4"}`, "", 1},                           // colon
		{`{"ja4_header":123}`, "", 1},                               // non-string
		{`{"ja4_header":"` + strings.Repeat("a", 65) + `"}`, "", 1}, // too long
		{`{"ja4_header":"` + strings.Repeat("a", 64) + `"}`, strings.Repeat("a", 64), 0},
	}
	for _, tc := range cases {
		got, problems := parseJA4Config([]byte(tc.config))
		if got != tc.want || len(problems) != tc.problems {
			t.Errorf("parseJA4Config(%s) = %q, %d problems; want %q, %d", tc.config, got, len(problems), tc.want, tc.problems)
		}
	}
}

func TestJA4MatcherZeroAlloc(t *testing.T) {
	list, _ := compileJA4List(gjson.Parse(`["`+ja4TestFP+`","a=t13d*","b=8daaf6152771","c=b186095e22b6"]`), 1)
	rules, _, _ := compileJA4Rules(t, `{"protected":[
		{"hosts":["api.example"],"paths":["/write"],"ja4":["a=t13d*"],"ja4_excluded":["`+ja4TestFP2+`"]},
		{"hosts":["other.example"],"difficulty":{"base":20}}
	]}`)
	fp := normalizeJA4(ja4TestFP)
	allocs := testing.AllocsPerRun(100, func() {
		_ = matchAnyJA4(list, fp)
		_ = matchAnyJA4(list, "") // unknown path
		_ = findProtectedRule(rules, "api.example", "/write", fp)
		_ = findProtectedRule(rules, "api.example", "/write", "")
	})
	if allocs != 0 {
		t.Fatalf("JA4 matching allocated %v times per run, want 0", allocs)
	}
}

func TestGetEffectiveDifficultyRuleBase(t *testing.T) {
	p := &pluginContext{baseDifficulty: 14, minDifficulty: 12, maxDifficulty: 26, currentDiff: 16}

	// Raw resolution ignores the rule base (dynamic source); the floor at the
	// call site lifts it: rule base 20 > dynamic 16.
	d, src := p.getEffectiveDifficulty(20, "")
	if d != 16 || src != diffSourceDynamic {
		t.Fatalf("dynamic under rule base: d=%d src=%s", d, src)
	}
	if d, src = applyRuleBase(20, p.baseDifficulty, d, src); d != 20 || src != diffSourceRule {
		t.Fatalf("rule base must floor dynamic: d=%d src=%s", d, src)
	}

	// The pressure bump still rises above the rule base.
	p.currentDiff = 24
	d, src = p.getEffectiveDifficulty(20, "")
	d, src = applyRuleBase(20, p.baseDifficulty, d, src)
	if d != 24 || src != diffSourceDynamic {
		t.Fatalf("pressure above rule base must win: d=%d src=%s", d, src)
	}

	// Header steering clamps from the rule base, not the global base.
	d, src = p.getEffectiveDifficulty(20, "18")
	if d != 20 || src != diffSourceHeader {
		t.Fatalf("header below rule base: d=%d src=%s", d, src)
	}
	d, src = p.getEffectiveDifficulty(20, "22")
	if d, src = applyRuleBase(20, p.baseDifficulty, d, src); d != 22 || src != diffSourceHeader {
		t.Fatalf("header above rule base: d=%d src=%s", d, src)
	}

	// No rule base: no floor — legacy resolution stays byte-identical, even
	// when the dynamic value sits below the global base.
	p2 := &pluginContext{baseDifficulty: 18, minDifficulty: 12, maxDifficulty: 26, currentDiff: 15}
	d, src = p2.getEffectiveDifficulty(p2.baseDifficulty, "")
	d, src = applyRuleBase(p2.baseDifficulty, p2.baseDifficulty, d, src)
	if d != 15 || src != diffSourceDynamic {
		t.Fatalf("legacy parity: d=%d src=%s, want 15 dynamic", d, src)
	}
}

func TestJA4ConfigIntegrationLegacy(t *testing.T) {
	// Regression: a config with no ja4_header and no ja4 rule fields compiles
	// and matches exactly as before (all protected_test.go cases keep passing
	// with the "" fingerprint).
	h, problems := parseJA4Config([]byte(`{"protected":[{"hosts":["kanidm.example.org"],"paths":["/login"]}]}`))
	if h != "" || problems != nil {
		t.Fatalf("legacy config must leave ja4 off: %q %v", h, problems)
	}
	rules, protectAll, probs := compileJA4Rules(t, `{"protected":[{"hosts":["kanidm.example.org"],"paths":["/login"]}]}`)
	if protectAll || len(rules) != 1 || len(probs) != 0 {
		t.Fatalf("legacy rule compile changed: %d rules, protectAll=%v, problems=%v", len(rules), protectAll, probs)
	}
	if rules[0].ja4 != nil || rules[0].ja4Excluded != nil || rules[0].hasDifficulty {
		t.Fatal("legacy rule must carry no JA4 dimensions and no difficulty override")
	}
	if !matchProtectedRules(rules, "kanidm.example.org", "/login", "") {
		t.Fatal("legacy matching behavior must be unchanged")
	}
}
