package main

import "testing"

func TestGetCookie(t *testing.T) {
	cases := []struct {
		header string
		name   string
		want   string
	}{
		{"", "challenge", ""},
		{"challenge=abc", "challenge", "abc"},
		{"challenge=abc; challenge-sig=xyz", "challenge", "abc"},
		{"challenge=abc; challenge-sig=xyz", "challenge-sig", "xyz"},
		{"foo=1; challenge=val; bar=2", "challenge", "val"},
		{"challenge=abc;challenge-sig=xyz", "challenge-sig", "xyz"},
		{"other=1", "challenge", ""},
		{"challenge=  spaced  ", "challenge", "spaced"},
		{"a=1; challenge-nonce=42; b=2", "challenge-nonce", "42"},
	}
	for _, tc := range cases {
		if got := getCookie(tc.header, tc.name); got != tc.want {
			t.Errorf("getCookie(%q, %q)=%q want %q", tc.header, tc.name, got, tc.want)
		}
	}
}

func TestParseChallengeCookies(t *testing.T) {
	h := "a=1; challenge=abc; challenge-sig=sig; challenge-nonce=9; challenge-clearance=cltok; b=2"
	got := parseChallengeCookies(h)
	if got.challenge != "abc" || got.signature != "sig" || got.nonce != "9" || got.clearance != "cltok" {
		t.Fatalf("got %+v", got)
	}
	// single-pass equals individual getCookie
	if got.challenge != getCookie(h, "challenge") {
		t.Fatal("challenge mismatch")
	}
	empty := parseChallengeCookies("")
	if empty.clearance != "" || empty.challenge != "" {
		t.Fatal("expected empty")
	}
	// IPv6-looking values without separators in name still work
	h2 := "challenge-clearance=body.sig"
	if parseChallengeCookies(h2).clearance != "body.sig" {
		t.Fatal("clearance with dot in value")
	}
}

func TestSetCookie(t *testing.T) {
	got := setCookie("challenge", "tok", 60, false, false)
	if got != "challenge=tok; Path=/; Max-Age=60; SameSite=Lax" {
		t.Fatalf("got %q", got)
	}
	got = setCookie("challenge-clearance", "tok", 1800, true, true)
	if got != "challenge-clearance=tok; Path=/; Max-Age=1800; SameSite=Lax; HttpOnly; Secure" {
		t.Fatalf("got %q", got)
	}
}

func TestClearCookie(t *testing.T) {
	got := clearCookie("challenge", false)
	if got != "challenge=; Path=/; Max-Age=0; SameSite=Lax" {
		t.Fatalf("got %q", got)
	}
	got = clearCookie("challenge-clearance", true)
	if got != "challenge-clearance=; Path=/; Max-Age=0; SameSite=Lax; Secure; HttpOnly" {
		t.Fatalf("got %q", got)
	}
}

func TestClampDifficulty(t *testing.T) {
	if got := clampDifficulty(5, 12, 26); got != 12 {
		t.Fatalf("below min: %d", got)
	}
	if got := clampDifficulty(30, 12, 26); got != 26 {
		t.Fatalf("above max: %d", got)
	}
	if got := clampDifficulty(18, 12, 26); got != 18 {
		t.Fatalf("in range: %d", got)
	}
}

// TestGetEffectiveDifficultyHeaderOverride pins the edge-only steering
// semantics of difficulty_header (CVE-2025-24369 class regression): a header
// value can only steer difficulty UP within [base, max] — never below the
// configured base, even when base > min. Invalid values never error; they
// fall through to the ordinary (non-header) resolution, which is the dynamic
// value here and equals base with currentDiff=base.
func TestGetEffectiveDifficultyHeaderOverride(t *testing.T) {
	p := &pluginContext{
		baseDifficulty: 18,
		minDifficulty:  12,
		maxDifficulty:  26,
		// currentDiff=base keeps the fallback path off the Wasm host ABI
		// (currentDiff=0 would reach GetSharedData, which panics without a host).
		currentDiff: 18,
	}
	cases := []struct {
		name    string
		header  string
		wantD   uint
		wantSrc difficultySource
	}{
		{"empty header falls back to base", "", 18, diffSourceDynamic},
		{"non-numeric falls back to base", "abc", 18, diffSourceDynamic},
		{"negative falls back to base", "-3", 18, diffSourceDynamic},
		{"zero falls back to base", "0", 18, diffSourceDynamic},
		{"float falls back to base", "1.5", 18, diffSourceDynamic},
		{"header at base", "18", 18, diffSourceHeader},
		{"header raises within bounds", "22", 22, diffSourceHeader},
		{"header above max clamps down", "99", 26, diffSourceHeader},
		{"header below base clamps up (CVE)", "4", 18, diffSourceHeader},
		{"header at one clamps up to base", "1", 18, diffSourceHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, src := p.getEffectiveDifficulty(tc.header)
			if d != tc.wantD || src != tc.wantSrc {
				t.Fatalf("header=%q: got d=%d src=%s, want d=%d src=%s", tc.header, d, src, tc.wantD, tc.wantSrc)
			}
		})
	}
}

// TestGetEffectiveDifficultyNonHeaderSources preserves the existing precedence
// and bounds of every non-header difficulty source: dynamic pressure still
// wins over base and keeps its own [min, max] bounds.
func TestGetEffectiveDifficultyNonHeaderSources(t *testing.T) {
	p := &pluginContext{
		baseDifficulty: 18,
		minDifficulty:  12,
		maxDifficulty:  26,
		currentDiff:    20,
	}
	d, src := p.getEffectiveDifficulty("")
	if d != 20 || src != diffSourceDynamic {
		t.Fatalf("dynamic: d=%d src=%s", d, src)
	}
	d, src = p.getEffectiveDifficulty("not-a-number")
	if d != 20 || src != diffSourceDynamic {
		t.Fatalf("invalid header must not error or apply: d=%d src=%s", d, src)
	}
	p.currentDiff = 15
	d, src = p.getEffectiveDifficulty("")
	if d != 15 || src != diffSourceDynamic {
		t.Fatalf("local dynamic: d=%d src=%s", d, src)
	}
}

// TestDifficultyOverrideFeatureOff is the feature-off regression: with no
// difficulty_header configured, the plugin must not consult ANY request
// header for difficulty — the resolver receives an empty override.
func TestDifficultyOverrideFeatureOff(t *testing.T) {
	p := &pluginContext{} // difficultyHeader empty = feature off (default)
	if got := p.difficultyOverride(); got != "" {
		t.Fatalf("feature off must ignore request headers, got %q", got)
	}
}

func TestHasLeadingZeroBits(t *testing.T) {
	// All-zero hash satisfies any reasonable difficulty.
	zero := make([]byte, 32)
	if !hasLeadingZeroBits(zero, 0) {
		t.Fatal("0 bits should pass")
	}
	if !hasLeadingZeroBits(zero, 16) {
		t.Fatal("zero hash should pass 16 bits")
	}
	// 0x0f = 00001111 → first 4 bits are zero
	h := make([]byte, 32)
	h[0] = 0x0f
	if !hasLeadingZeroBits(h, 4) {
		t.Fatal("expected 4 leading zero bits")
	}
	if hasLeadingZeroBits(h, 5) {
		t.Fatal("should fail 5 leading zero bits")
	}
}
