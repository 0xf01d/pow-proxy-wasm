package main

import (
	"testing"
)

// Real fingerprints captured from the homelab gateway access log (brief).
// The first two are family-labeled; the rest exercise the "unknown family"
// path and must never score a mismatch.
const (
	botTestFPChrome = "t13d1517h2_8daaf6152771_e6dcd7ae0a9e"
	botTestFPCli    = "t13d3814h1_765413786415_374df4ed9e6a"
	botTestFPH1     = "t13d5212h1_b262b3658495_8e6e362c5eac"
	botTestFPNoALPN = "t13d141100_cbb2034c60b8_e5728521abd4"
	botTestFPNoSNI  = "t13i131000_f57a46bbacb6_ab7e3b40a677"
)

const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// botTestConfig returns an enabled config with the brief's default weights
// and thresholds; tests override fields as needed.
func botTestConfig() botScoreConfig {
	return botScoreConfig{
		enabled:           true,
		wIPIntel:          defaultWIPIntel,
		wUAMismatch:       defaultWUAMismatch,
		wNoBrowserHeaders: defaultWNoBrowserHeaders,
		wUnknownJA4:       defaultWUnknownJA4,
		wKnownBadJA4:      defaultWKnownBadJA4,
	}
}

func TestBotscoreDisabledNoop(t *testing.T) {
	// Zero-value (empty) config: score must not panic on any input shape and
	// must never compute a score; actionFor is always challenge/0.
	var cfg botScoreConfig
	inputs := []botScoreInput{
		{},
		{userAgent: chromeUA, ja4: botTestFPCli, ipintelVerdict: "vpn"},
		{ipintelVerdict: "tor", ipintelCats: map[string]bool{"tor": true}},
		{userAgent: "curl/8.5.0", ja4: botTestFPCli},
	}
	for _, in := range inputs {
		if got := cfg.score(in); got != 0 {
			t.Errorf("disabled score(%+v) = %d, want 0", in, got)
		}
	}
	for _, score := range []int{0, 20, 50, 100} {
		action, diff := cfg.actionFor(score)
		if action != botChallenge || diff != 0 {
			t.Errorf("disabled actionFor(%d) = (%v, %d), want (challenge, 0)", score, action, diff)
		}
	}
}

func TestBotscoreWeightsContribute(t *testing.T) {
	cfg := botTestConfig()
	cats := map[string]bool{"vpn": true, "tor": true}

	base := botScoreInput{userAgent: chromeUA, ja4: botTestFPChrome, hasAcceptLang: true, hasSecFetch: true}
	if got := cfg.score(base); got != 0 {
		t.Errorf("clean browser input scored %d, want 0", got)
	}

	ipintel := base
	ipintel.ipintelVerdict = "vpn"
	ipintel.ipintelCats = cats
	if got := cfg.score(ipintel); got != 40 {
		t.Errorf("ipintel weight: got %d, want 40", got)
	}

	mismatch := base
	mismatch.ja4 = botTestFPCli
	if got := cfg.score(mismatch); got != 40 {
		t.Errorf("ua_mismatch weight: got %d, want 40", got)
	}

	noHeaders := base
	noHeaders.hasAcceptLang = false
	noHeaders.hasSecFetch = false
	if got := cfg.score(noHeaders); got != 15 {
		t.Errorf("no_browser_headers weight: got %d, want 15", got)
	}

	unknown := base
	unknown.ja4 = ""
	cfg.ja4Configured = true
	if got := cfg.score(unknown); got != 10 {
		t.Errorf("unknown_ja4 weight: got %d, want 10", got)
	}
	cfg.ja4Configured = false

	// ipintel + mismatch + no-browser-headers fire together: 40+40+15 = 95.
	// (unknown-JA4 is mutually exclusive with mismatch by design — the JA4
	// cannot be both known-and-mismatched and unknown.)
	all := botScoreInput{
		userAgent:      chromeUA,
		ja4:            botTestFPCli,
		ipintelVerdict: "tor",
		ipintelCats:    cats,
	}
	if got := cfg.score(all); got != 95 {
		t.Errorf("three concurrent signals: got %d, want 95", got)
	}

	// A single oversized weight still caps at 100 (two browser penalties).
	cfg.wUAMismatch = 100
	cfg.wNoBrowserHeaders = 100
	if got := cfg.score(noHeaders); got != 100 {
		t.Errorf("oversized weights: got %d, want 100", got)
	}
}

func TestBotscoreUAMismatchMatrix(t *testing.T) {
	cfg := botTestConfig()
	full := func(ua, fp string) botScoreInput {
		return botScoreInput{userAgent: ua, ja4: fp, hasAcceptLang: true, hasSecFetch: true}
	}

	cases := []struct {
		name   string
		ua     string
		fp     string
		expect int
	}{
		{"chrome UA + chrome JA4", chromeUA, botTestFPChrome, 0},
		{"chrome UA + CLI JA4", chromeUA, botTestFPCli, 40},
		{"curl UA + CLI JA4 (honest non-browser)", "curl/8.5.0", botTestFPCli, 0},
		{"python UA + python JA4 (honest)", "python-requests/2.31", "t13d4312h1_c7886603b240_b26ce05bbdd6", 0},
		{"go UA + go JA4 (honest)", "Go-http-client/2.0", "t13d191000_9dc949149365_e7c285222651", 0},
		{"wget UA + CLI JA4 (honest)", "Wget/1.21.2", botTestFPCli, 0},
		{"empty UA + CLI JA4", "", botTestFPCli, 0},
		{"garbage UA + CLI JA4 (no browser claim)", "SomeRandomBot/1.0", botTestFPCli, 0},
		{"edge UA + chromium JA4 (same TLS stack)", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", botTestFPChrome, 0},
		{"edge UA + CLI JA4", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", botTestFPCli, 40},
		{"firefox UA + CLI JA4", "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0", botTestFPCli, 40},
		{"safari UA + CLI JA4", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15", botTestFPCli, 40},
		{"iOS chrome UA (CriOS, carries Safari token) + safari-class JA4 — WebKit-consistent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1", "t13d2014h2_a09f3c656075_14788d8d241b", 0},
		{"chrome UA + unknown-family JA4 (no judgment)", chromeUA, botTestFPNoSNI, 0},
		{"chrome UA + no-ALPN JA4 (unknown family, unknown ≠ other)", chromeUA, botTestFPNoALPN, 0},
		{"chrome UA + h1 JA4 (unknown family)", chromeUA, botTestFPH1, 0},
		{"uppercase UA still classified", "MOZILLA/5.0 (X11) CHROME/141.0.0.0 SAFARI/537.36", botTestFPCli, 40},
	}
	for _, tc := range cases {
		if got := cfg.score(full(tc.ua, tc.fp)); got != tc.expect {
			t.Errorf("%s: score = %d, want %d", tc.name, got, tc.expect)
		}
	}
}

func TestBotscoreUnknownJA4(t *testing.T) {
	cfg := botTestConfig()

	browserNoJA4 := botScoreInput{userAgent: chromeUA, hasAcceptLang: true, hasSecFetch: true}
	if got := cfg.score(browserNoJA4); got != 0 {
		t.Errorf("ja4 feature off + browser UA + no fp: got %d, want 0", got)
	}

	cfg.ja4Configured = true
	if got := cfg.score(browserNoJA4); got != 10 {
		t.Errorf("ja4 feature on + browser UA + no fp: got %d, want 10", got)
	}
	if got := cfg.score(botScoreInput{userAgent: chromeUA, ja4: botTestFPChrome, hasAcceptLang: true, hasSecFetch: true}); got != 0 {
		t.Errorf("ja4 feature on + browser UA + known fp: got %d, want 0", got)
	}
	// Unparsable values are normalized to "" by the caller (normalizeJA4);
	// score() sees the same "" case — a curl UA with no fingerprint has no
	// browser claim and must not be penalized.
	if got := cfg.score(botScoreInput{userAgent: "curl/8.5.0", hasAcceptLang: true, hasSecFetch: true}); got != 0 {
		t.Errorf("ja4 feature on + curl UA + no fp: got %d, want 0", got)
	}
}

func TestBotscoreNoBrowserHeaders(t *testing.T) {
	cfg := botTestConfig()
	cases := []struct {
		name          string
		ua            string
		hasAcceptLang bool
		hasSecFetch   bool
		expect        int
	}{
		{"browser UA, both headers present", chromeUA, true, true, 0},
		{"browser UA, only accept-language (Safari-shaped: no sec-fetch)", chromeUA, true, false, 0},
		{"browser UA, no headers at all", chromeUA, false, false, 15},
		{"curl UA, no headers (no browser claim)", "curl/8.5.0", false, false, 0},
		{"empty UA, no headers", "", false, false, 0},
	}
	for _, tc := range cases {
		got := cfg.score(botScoreInput{userAgent: tc.ua, hasAcceptLang: tc.hasAcceptLang, hasSecFetch: tc.hasSecFetch, ja4: botTestFPChrome})
		if got != tc.expect {
			t.Errorf("%s: score = %d, want %d", tc.name, got, tc.expect)
		}
	}
}

func TestBotscoreIPIntelWeight(t *testing.T) {
	cfg := botTestConfig()
	cats := map[string]bool{"vpn": true, "tor": true}

	if got := cfg.score(botScoreInput{ipintelVerdict: "vpn", ipintelCats: cats, userAgent: chromeUA, ja4: botTestFPChrome, hasAcceptLang: true, hasSecFetch: true}); got != 40 {
		t.Errorf("verdict in cats: got %d, want 40", got)
	}
	if got := cfg.score(botScoreInput{ipintelVerdict: "residential", ipintelCats: cats}); got != 0 {
		t.Errorf("verdict not in cats: got %d, want 0", got)
	}
	if got := cfg.score(botScoreInput{ipintelCats: cats}); got != 0 {
		t.Errorf("empty verdict: got %d, want 0", got)
	}
	// nil category map must not panic.
	if got := cfg.score(botScoreInput{ipintelVerdict: "vpn"}); got != 0 {
		t.Errorf("nil cats: got %d, want 0", got)
	}
}

func TestBotscoreScoreIsAllocationFree(t *testing.T) {
	cfg := botTestConfig()
	cfg.ja4Configured = true
	cats := map[string]bool{"vpn": true}
	in := botScoreInput{
		ipintelVerdict: "vpn",
		ipintelCats:    cats,
		ja4:            botTestFPChrome,
		userAgent:      chromeUA,
		hasAcceptLang:  true,
		hasSecFetch:    true,
	}
	if avg := testing.AllocsPerRun(100, func() { cfg.score(in) }); avg != 0 {
		t.Errorf("score() allocated %v bytes/run, want 0", avg)
	}
}

func TestBotscoreLadderBoundaries(t *testing.T) {
	cfg := botTestConfig()
	cfg.ladder = []botScoreStep{
		{minScore: 25, difficulty: 16},
		{minScore: 55, difficulty: 20},
		{minScore: 80, difficulty: 24},
	}
	cases := []struct {
		score      int
		action     botScoreAction
		difficulty uint
	}{
		{0, botChallenge, 0},  // below first rung → global base
		{24, botChallenge, 0}, // still below first rung
		{25, botChallenge, 16},
		{26, botChallenge, 16},
		{54, botChallenge, 16},
		{55, botChallenge, 20},
		{56, botChallenge, 20},
		{79, botChallenge, 20},
		{80, botChallenge, 24},
		{100, botChallenge, 24},
	}
	for _, tc := range cases {
		action, diff := cfg.actionFor(tc.score)
		if action != tc.action || diff != tc.difficulty {
			t.Errorf("actionFor(%d) = (%v, %d), want (%v, %d)", tc.score, action, diff, tc.action, tc.difficulty)
		}
	}

	// First rung at 0 covers every score.
	cfg.ladder = []botScoreStep{{minScore: 0, difficulty: 14}}
	if action, diff := cfg.actionFor(0); action != botChallenge || diff != 14 {
		t.Errorf("rung at 0: actionFor(0) = (%v, %d), want (challenge, 14)", action, diff)
	}
}

func TestBotscorePassBlockPrecedence(t *testing.T) {
	// Hand-built config with pass_below > block_above — parse() rejects this
	// combination, but the pure function must still prefer block when both
	// thresholds match.
	cfg := botTestConfig()
	cfg.passBelow = 100
	cfg.blockAbove = 10
	if action, _ := cfg.actionFor(50); action != botBlock {
		t.Errorf("block must win when both thresholds match: action = %v", action)
	}
	if action, _ := cfg.actionFor(5); action != botPass {
		t.Errorf("score below pass_below: action = %v, want pass", action)
	}

	// block_above only: everything below it is challenged.
	cfg = botTestConfig()
	cfg.blockAbove = 90
	if action, _ := cfg.actionFor(90); action != botBlock {
		t.Errorf("block boundary (score == block_above): action = %v, want block", action)
	}
	action, diff := cfg.actionFor(89)
	if action != botChallenge || diff != 0 {
		t.Errorf("below block_above with no ladder: (%v, %d), want (challenge, 0)", action, diff)
	}

	// pass_below only: humans below it invisible, everything else challenged.
	cfg = botTestConfig()
	cfg.passBelow = 20
	if action, _ := cfg.actionFor(19); action != botPass {
		t.Errorf("pass boundary (score 19 < 20): action = %v, want pass", action)
	}
	if action, _ := cfg.actionFor(20); action != botChallenge {
		t.Errorf("pass is strict below pass_below (score 20): action = %v, want challenge", action)
	}
}

func TestParseBotscoreConfigAbsentAndDisabled(t *testing.T) {
	cfg, problems := parseBotscoreConfig([]byte(`{"secret":"x"}`), 12, 26)
	if cfg.enabled || len(cfg.ladder) != 0 || len(problems) != 0 {
		t.Errorf("absent botscore block: enabled=%v ladder=%d problems=%v", cfg.enabled, len(cfg.ladder), problems)
	}

	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": false, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if cfg.enabled || len(problems) != 0 {
		t.Errorf("explicit disabled: enabled=%v problems=%v", cfg.enabled, problems)
	}

	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": "junk"}`), 12, 26)
	if cfg.enabled || len(problems) != 1 {
		t.Errorf("non-object botscore: enabled=%v problems=%v", cfg.enabled, problems)
	}
}

func TestParseBotscoreConfigValid(t *testing.T) {
	raw := `{"botscore": {
		"enabled": true,
		"w_ipintel": 40, "w_ua_mismatch": 40, "w_no_browser_headers": 15, "w_unknown_ja4": 10,
		"pass_below": 20, "block_above": 90,
		"ladder": [
			{"min_score": 80, "difficulty": 24},
			{"min_score": 0, "difficulty": 14},
			{"min_score": 25, "difficulty": 16},
			{"min_score": 55, "difficulty": 20}
		]
	}}`
	cfg, problems := parseBotscoreConfig([]byte(raw), 12, 26)
	if len(problems) != 0 {
		t.Fatalf("valid config produced problems: %v", problems)
	}
	if !cfg.enabled {
		t.Fatal("valid config must be enabled")
	}
	if cfg.wIPIntel != 40 || cfg.wUAMismatch != 40 || cfg.wNoBrowserHeaders != 15 || cfg.wUnknownJA4 != 10 {
		t.Errorf("weights not parsed: %+v", cfg)
	}
	if cfg.passBelow != 20 || cfg.blockAbove != 90 {
		t.Errorf("thresholds not parsed: %+v", cfg)
	}
	// Unsorted input must come out sorted by min_score.
	wantMin := []int{0, 25, 55, 80}
	wantDiff := []uint{14, 16, 20, 24}
	if len(cfg.ladder) != len(wantMin) {
		t.Fatalf("ladder len = %d, want %d", len(cfg.ladder), len(wantMin))
	}
	for i, step := range cfg.ladder {
		if step.minScore != wantMin[i] || step.difficulty != wantDiff[i] {
			t.Errorf("ladder[%d] = {%d, %d}, want {%d, %d}", i, step.minScore, step.difficulty, wantMin[i], wantDiff[i])
		}
	}
}

func TestParseBotscoreConfigDefaults(t *testing.T) {
	cfg, problems := parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if len(problems) != 0 {
		t.Fatalf("defaults config produced problems: %v", problems)
	}
	if cfg.wIPIntel != 40 || cfg.wUAMismatch != 40 || cfg.wNoBrowserHeaders != 15 || cfg.wUnknownJA4 != 10 {
		t.Errorf("weight defaults wrong: %+v", cfg)
	}
	if cfg.passBelow != 0 || cfg.blockAbove != 0 {
		t.Errorf("threshold defaults must be disabled (0): %+v", cfg)
	}
}

func TestParseBotscoreConfigValidation(t *testing.T) {
	// Malformed steps dropped, difficulty clamped to global bounds, remainder sorted.
	raw := `{"botscore": {"enabled": true, "ladder": [
		{"min_score": 40, "difficulty": 5},
		{"min_score": 10},
		{"min_score": -2, "difficulty": 16},
		{"min_score": 30, "difficulty": 0},
		"notanobject",
		{"min_score": 0, "difficulty": 16}
	]}}`
	cfg, problems := parseBotscoreConfig([]byte(raw), 12, 26)
	if !cfg.enabled {
		t.Fatalf("expected enabled after valid steps survived, problems: %v", problems)
	}
	if len(cfg.ladder) != 2 {
		t.Fatalf("ladder len = %d, want 2 (two malformed + one clamped... remaining)", len(cfg.ladder))
	}
	if cfg.ladder[0].minScore != 0 || cfg.ladder[0].difficulty != 16 {
		t.Errorf("ladder[0] = %+v, want {0, 16}", cfg.ladder[0])
	}
	if cfg.ladder[1].minScore != 40 || cfg.ladder[1].difficulty != 12 {
		t.Errorf("ladder[1] = %+v, want {40, 12 (clamped to global min)}", cfg.ladder[1])
	}
	if len(problems) != 5 { // 4 dropped steps + 1 clamp
		t.Errorf("problems = %d, want 5: %v", len(problems), problems)
	}

	// Upward clamp: difficulty above max clamps down.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": [{"min_score": 0, "difficulty": 99}]}}`), 12, 26)
	if cfg.ladder[0].difficulty != 26 || len(problems) != 1 {
		t.Errorf("difficulty 99 with max 26: %+v, problems %v", cfg.ladder, problems)
	}

	// Enabled with empty ladder ⇒ whole block disabled.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": []}}`), 12, 26)
	if cfg.enabled || len(problems) != 1 {
		t.Errorf("empty ladder: enabled=%v problems=%v", cfg.enabled, problems)
	}

	// Enabled with all-invalid ladder ⇒ whole block disabled.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": [{"min_score": 5}, {"difficulty": -1}]}}`), 12, 26)
	if cfg.enabled || len(problems) != 3 {
		t.Errorf("all-invalid ladder: enabled=%v problems=%v", cfg.enabled, problems)
	}

	// Enabled with ladder not an array ⇒ disabled.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": 7}}`), 12, 26)
	if cfg.enabled || len(problems) != 2 {
		t.Errorf("non-array ladder: enabled=%v problems=%v", cfg.enabled, problems)
	}

	// pass_below >= block_above (both non-zero) ⇒ disabled.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "pass_below": 90, "block_above": 90, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if cfg.enabled || len(problems) != 1 {
		t.Errorf("pass_below == block_above: enabled=%v problems=%v", cfg.enabled, problems)
	}
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "pass_below": 95, "block_above": 90, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if cfg.enabled || len(problems) != 1 {
		t.Errorf("pass_below > block_above: enabled=%v problems=%v", cfg.enabled, problems)
	}

	// pass_below == block_above == 0 is fine (both disabled).
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if !cfg.enabled || len(problems) != 0 {
		t.Errorf("zero thresholds must not disable: enabled=%v problems=%v", cfg.enabled, problems)
	}

	// Negative weights and thresholds clamp to 0 with a problem each.
	cfg, problems = parseBotscoreConfig([]byte(`{"botscore": {"enabled": true, "w_ipintel": -5, "pass_below": -1, "block_above": 90, "ladder": [{"min_score": 0, "difficulty": 14}]}}`), 12, 26)
	if cfg.wIPIntel != 0 || cfg.passBelow != 0 || cfg.blockAbove != 90 {
		t.Errorf("negative knobs not clamped: %+v", cfg)
	}
	if len(problems) != 2 {
		t.Errorf("negative knobs: problems = %d, want 2: %v", len(problems), problems)
	}
}

func TestBotscoreFixturesAreValidJA4(t *testing.T) {
	for _, fp := range []string{botTestFPChrome, botTestFPCli, botTestFPH1, botTestFPNoALPN, botTestFPNoSNI} {
		if got := normalizeJA4(fp); got != fp {
			t.Errorf("fixture %q does not normalize to itself (got %q)", fp, got)
		}
	}
}

func TestClassifyUserAgentFamilies(t *testing.T) {
	cases := []struct {
		ua   string
		want uaFamily
	}{
		{chromeUA, uaChrome},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", uaEdge},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0", uaFirefox},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15", uaSafari},
		{"curl/8.5.0", uaOther},
		{"Wget/1.21.2", uaOther},
		{"python-requests/2.31.0", uaOther},
		{"python-urllib/3.12", uaOther},
		{"Go-http-client/2.0", uaOther},
		{"", uaNone},
		{"SomeRandomBot/1.0", uaNone},
		// iOS UAs all carry the WebKit "Safari/…" token (CriOS/FxiOS/EdgiOS do
		// NOT match chrome/edg patterns) → safari family, which is exactly
		// their real TLS family. Android Edge ("EdgA/" lacks the "edg/" token)
		// classifies via its Chrome token → chromium, also its real family.
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1", uaSafari},
		{"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 EdgA/141.0.0.0", uaChrome},
	}
	for _, tc := range cases {
		if got := classifyUserAgent(tc.ua); got != tc.want {
			t.Errorf("classifyUserAgent(%q) = %s, want %s", tc.ua, got, tc.want)
		}
	}
}

func TestClassifyJA4Families(t *testing.T) {
	cases := []struct {
		fp   string
		want ja4Family
	}{
		{botTestFPChrome, ja4FamChromium},
		{botTestFPCli, ja4FamOther},
		{"t13d1516h2_8daaf6152771_02713d6af862", ja4FamChromium}, // FoxIO mapping
		{"t13d1715h2_5b57614c22b0_7121afd63204", ja4FamFirefox},  // FoxIO mapping
		{"t13d2014h2_a09f3c656075_14788d8d241b", ja4FamSafari},   // FoxIO mapping
		{"t13d4312h1_c7886603b240_b26ce05bbdd6", ja4FamOther},    // Python (FoxIO)
		{"t13d190900_9dc949149365_97f8aa674fd9", ja4FamOther},    // Go (FoxIO)
		{botTestFPH1, ja4FamUnknown},
		{botTestFPNoALPN, ja4FamUnknown},
		{botTestFPNoSNI, ja4FamUnknown},
		{"", ja4FamUnknown},
		{"short", ja4FamUnknown},
	}
	for _, tc := range cases {
		if got := classifyJA4(tc.fp); got != tc.want {
			t.Errorf("classifyJA4(%q) = %d, want %d", tc.fp, got, tc.want)
		}
	}
}

func TestUaFamilyString(t *testing.T) {
	cases := map[uaFamily]string{
		uaChrome: "chrome", uaFirefox: "firefox", uaSafari: "safari",
		uaEdge: "edge", uaOther: "other", uaNone: "none",
		uaFamily(99): "none",
	}
	for f, want := range cases {
		if got := f.String(); got != want {
			t.Errorf("uaFamily(%d).String() = %q, want %q", f, got, want)
		}
	}
}
