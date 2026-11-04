// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
//
// botscore: Akamai-style risk scoring at the HTTP layer (docs/botscore.md).
// One pure score per protected request over the signals this layer can
// actually verify — ipintel verdict, edge-injected JA4, User-Agent, and the
// presence of browser-only headers — mapped to pass / challenge / block.
//
// The honest constraint: an HTTP filter cannot prove "this is a real
// browser". JA4 is public and reproducible; a client running a real JS engine
// solves the same PoW a browser does. The one high-value signal is
// CONSISTENCY: a User-Agent claiming Chrome while the ClientHello is stock
// curl is a mismatch no honest client produces, and faking it requires
// shipping a genuine browser TLS stack (curl-impersonate does exactly that —
// see docs/botscore.md §"What would break this"). This module never treats a
// client-supplied claim (UA strings included) as attestation, and it keeps no
// state: no per-IP memory, no queues, no "is this headless" heuristics.
package main

import (
	"sort"
	"strconv"

	"github.com/tidwall/gjson"
)

// Default weights (overridable per key in the `botscore` config object).
const (
	defaultWIPIntel          = 40
	defaultWUAMismatch       = 40
	defaultWNoBrowserHeaders = 15
	defaultWUnknownJA4       = 10
)

// botScoreStep is one ladder rung: at score >= minScore, challenge at
// difficulty (clamped to the global [min_difficulty, max_difficulty] at
// parse time).
type botScoreStep struct {
	minScore   int
	difficulty uint
}

type botScoreConfig struct {
	enabled bool

	wIPIntel          int // ipintel verdict in challenge_categories
	wUAMismatch       int // UA claims browser X, JA4 says family Y ≠ X
	wNoBrowserHeaders int // browser-claimed UA but accept-language AND sec-fetch-mode both absent
	wUnknownJA4       int // ja4_header configured, fingerprint unknown, UA claims a browser

	passBelow  int // score <  passBelow  → continue, no challenge. 0 = disabled
	blockAbove int // score >= blockAbove → 403. 0 = disabled

	ladder []botScoreStep // sorted by minScore at parse time

	// ja4Configured mirrors pluginContext.ja4Header != "" (set in
	// OnPluginStart). score() needs it to tell "feature off — never penalize
	// an unknown fingerprint" apart from "feature on but the fingerprint is
	// absent/unparsable" (+wUnknownJA4).
	ja4Configured bool
}

// botScoreInput is the per-request evidence. Everything is already
// normalized by the caller (ja4 via normalizeJA4, "" = unknown).
type botScoreInput struct {
	ipintelVerdict string          // "" when unknown
	ipintelCats    map[string]bool // the configured challenge_categories
	ja4            string          // normalized, "" = unknown
	userAgent      string
	hasAcceptLang  bool
	hasSecFetch    bool
}

// parseBotscoreConfig compiles the optional `botscore` block. The zero
// config (feature absent or disabled) scores 0 and never changes behavior.
// Validation never half-enables: an enabled block with an empty (or fully
// invalid) ladder, or with pass_below >= block_above (both non-zero), is
// disabled with a logged problem.
func parseBotscoreConfig(data []byte, globalMin, globalMax uint) (botScoreConfig, []string) {
	var cfg botScoreConfig
	top := gjson.GetBytes(data, "botscore")
	if !top.Exists() {
		return cfg, nil
	}
	if !top.IsObject() {
		return cfg, []string{"`botscore` must be a JSON object; ignoring it"}
	}
	cfg.enabled = top.Get("enabled").Bool()
	if !cfg.enabled {
		return cfg, nil
	}

	var problems []string
	cfg.wIPIntel = parseBotscoreInt(top.Get("w_ipintel"), defaultWIPIntel, "w_ipintel", &problems)
	cfg.wUAMismatch = parseBotscoreInt(top.Get("w_ua_mismatch"), defaultWUAMismatch, "w_ua_mismatch", &problems)
	cfg.wNoBrowserHeaders = parseBotscoreInt(top.Get("w_no_browser_headers"), defaultWNoBrowserHeaders, "w_no_browser_headers", &problems)
	cfg.wUnknownJA4 = parseBotscoreInt(top.Get("w_unknown_ja4"), defaultWUnknownJA4, "w_unknown_ja4", &problems)
	cfg.passBelow = parseBotscoreInt(top.Get("pass_below"), 0, "pass_below", &problems)
	cfg.blockAbove = parseBotscoreInt(top.Get("block_above"), 0, "block_above", &problems)

	if steps := top.Get("ladder"); steps.Exists() {
		if !steps.IsArray() {
			problems = append(problems, "`botscore.ladder` must be an array of {min_score, difficulty} objects; ignoring it")
		} else {
			steps.ForEach(func(_, e gjson.Result) bool {
				if !e.IsObject() {
					problems = append(problems, "botscore.ladder: step is not an object; dropping step")
					return true
				}
				minScore := e.Get("min_score")
				diff := e.Get("difficulty")
				if !minScore.Exists() || !diff.Exists() || minScore.Int() < 0 || diff.Int() <= 0 {
					problems = append(problems, "botscore.ladder: step needs `min_score` >= 0 and `difficulty` > 0; dropping step")
					return true
				}
				clamped := clampDifficulty(uint(diff.Int()), globalMin, globalMax)
				if clamped != uint(diff.Int()) {
					problems = append(problems, "botscore.ladder: difficulty "+strconv.FormatInt(diff.Int(), 10)+
						" outside global bounds; clamped to "+strconv.FormatUint(uint64(clamped), 10))
				}
				cfg.ladder = append(cfg.ladder, botScoreStep{minScore: int(minScore.Int()), difficulty: clamped})
				return true
			})
			sort.SliceStable(cfg.ladder, func(i, j int) bool { return cfg.ladder[i].minScore < cfg.ladder[j].minScore })
		}
	}

	if len(cfg.ladder) == 0 {
		problems = append(problems, "botscore: enabled but `ladder` is empty (or every step was invalid); the whole botscore block stays disabled")
		cfg.enabled = false
	}
	if cfg.enabled && cfg.passBelow > 0 && cfg.blockAbove > 0 && cfg.passBelow >= cfg.blockAbove {
		problems = append(problems, "botscore: pass_below >= block_above; the whole botscore block stays disabled")
		cfg.enabled = false
	}
	return cfg, problems
}

// parseBotscoreInt reads one numeric botscore knob: absent → default;
// negative → 0 (a negative weight or threshold is always a config bug, not a
// feature).
func parseBotscoreInt(v gjson.Result, def int, name string, problems *[]string) int {
	if !v.Exists() {
		return def
	}
	n := int(v.Int())
	if n < 0 {
		*problems = append(*problems, "botscore."+name+" is negative; clamped to 0")
		return 0
	}
	return n
}

// uaFamily is the browser family a User-Agent CLAIMS — a claim, never
// evidence (docs/botscore.md). uaNone: empty or unrecognized (nothing to
// contradict → never penalized beyond ipintel). uaOther: an honest
// non-browser tool (curl, wget, python, Go) — honest clients are not bots,
// they just get the normal challenge.
type uaFamily uint8

const (
	uaNone uaFamily = iota
	uaOther
	uaChrome
	uaFirefox
	uaSafari
	uaEdge
)

func (f uaFamily) isBrowser() bool {
	return f == uaChrome || f == uaFirefox || f == uaSafari || f == uaEdge
}

func (f uaFamily) String() string {
	switch f {
	case uaChrome:
		return "chrome"
	case uaFirefox:
		return "firefox"
	case uaSafari:
		return "safari"
	case uaEdge:
		return "edge"
	case uaOther:
		return "other"
	}
	return "none"
}

// classifyUserAgent maps a User-Agent to the family it claims. Order
// matters: Edge UAs embed "Chrome", Chrome UAs embed "Safari". Platform
// variants work out without special cases: iOS UAs (CriOS/FxiOS/EdgiOS)
// carry the WebKit "Safari/…" token and no chrome/edg one → safari family,
// exactly their real TLS family; Android Edge ("EdgA/" has no "edg/" token)
// classifies via its Chrome token → chromium, also its real family.
// Matching is ASCII case-insensitive without allocation (hot path).
func classifyUserAgent(ua string) uaFamily {
	switch {
	case containsFold(ua, "firefox"):
		return uaFirefox
	case containsFold(ua, "edg/"), containsFold(ua, "edge/"):
		return uaEdge
	case containsFold(ua, "chrome"):
		return uaChrome
	case containsFold(ua, "safari"):
		return uaSafari
	case containsFold(ua, "curl/"), containsFold(ua, "wget"),
		containsFold(ua, "python"), containsFold(ua, "go-http-client"):
		return uaOther
	}
	return uaNone
}

// containsFold is a non-allocating ASCII case-insensitive substring test;
// sub must already be lowercase. (strings.ToLower would allocate on the
// per-request path.)
func containsFold(s, sub string) bool {
	n := len(sub)
	if n == 0 {
		return true
	}
	for i := 0; i+n <= len(s); i++ {
		match := true
		for j := 0; j < n; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ja4Family is the client family derived from the JA4 part-a. ja4FamUnknown
// (the zero value, also returned for map misses) means "valid fingerprint
// that matches no known prefix" — no judgment, never a mismatch: browser
// majors drift their extension counts every release, and penalizing an
// unmapped value would hit real users.
type ja4Family uint8

const (
	ja4FamUnknown ja4Family = iota
	ja4FamChromium
	ja4FamFirefox
	ja4FamSafari
	ja4FamOther
)

// ja4FamilyTable maps known JA4 part-a values (exactly 10 chars) to client
// families. BEST-EFFORT HEURISTICS, NOT SECURITY: this table cannot
// authenticate anything — it only catches clients too lazy to ship a real
// browser ClientHello. Every value is sourced, none guessed: FoxIO's
// published ja4plus-mapping.csv (github.com/FoxIO-LLC/ja4) plus the homelab
// gateway capture for the CLI entry. Part-a values shared by multiple
// non-browser apps (e.g. t12d190800: WinINET AND Go) are fine — they land in
// the same family. QUIC ('q…') rows are omitted: the fingerprint is injected
// by the TCP tls_inspector.
var ja4FamilyTable = map[string]ja4Family{
	// Chromium (FoxIO mapping; t13d1517h2 also confirmed by homelab capture)
	"t13d1516h2": ja4FamChromium,
	"t13d1517h2": ja4FamChromium,
	"t13i1516h2": ja4FamChromium,
	// Firefox (FoxIO mapping)
	"t13d1715h2": ja4FamFirefox,
	"t13i1714h2": ja4FamFirefox,
	// Safari (FoxIO mapping)
	"t13d2014h2": ja4FamSafari,
	"t13i2013h2": ja4FamSafari,
	// Honest non-browser stacks — Python and Go (FoxIO mapping) and the
	// homelab CLI capture. A browser-claimed UA over one of these is the
	// classic spoof.
	"t13d3814h1": ja4FamOther,
	"t13d4312h1": ja4FamOther,
	"t13d181000": ja4FamOther,
	"t13i181000": ja4FamOther,
	"t13d190900": ja4FamOther,
	"t13i190800": ja4FamOther,
	"t13d191000": ja4FamOther,
	"t13d1412h2": ja4FamOther,
	"t13d141000": ja4FamOther,
}

// classifyJA4 maps a normalized fingerprint to its family via part-a.
func classifyJA4(fp string) ja4Family {
	if len(fp) < 10 {
		return ja4FamUnknown
	}
	return ja4FamilyTable[fp[:10]]
}

// uaMatchesJA4Family reports whether the family the UA claims is consistent
// with the JA4-derived family. Edge is Chromium (same BoringSSL
// ClientHello), so it is compatible with the Chromium class.
func uaMatchesJA4Family(ua uaFamily, jf ja4Family) bool {
	switch ua {
	case uaChrome, uaEdge:
		return jf == ja4FamChromium
	case uaFirefox:
		return jf == ja4FamFirefox
	case uaSafari:
		return jf == ja4FamSafari
	}
	return false
}

// score computes the 0..100 bot score. Pure and allocation-free (asserted by
// test): it runs on every protected request when enabled. Boring rules, in
// order:
//
//  1. ipintel: verdict in the configured challenge_categories → +wIPIntel.
//  2. UA vs JA4: the UA names a browser family, the JA4 is known, and the
//     JA4 family differs → +wUAMismatch. Unknown/unmapped JA4 never scores a
//     mismatch; honest non-browser UAs (curl etc.) and empty UAs have no
//     browser claim to contradict and score nothing here.
//  3. No browser headers: browser-claimed UA but BOTH accept-language and
//     sec-fetch-mode absent → +wNoBrowserHeaders (both, not either: Safari
//     never sends sec-fetch-* and must not be penalized).
//  4. Unknown JA4: ja4_header configured but no usable fingerprint while the
//     UA claims a browser → +wUnknownJA4.
//
// The sum is capped at 100.
func (c *botScoreConfig) score(in botScoreInput) int {
	if !c.enabled {
		return 0
	}
	score := 0
	if in.ipintelVerdict != "" && in.ipintelCats[in.ipintelVerdict] {
		score += c.wIPIntel
	}
	ua := classifyUserAgent(in.userAgent)
	if ua.isBrowser() {
		if in.ja4 != "" {
			if jf := classifyJA4(in.ja4); jf != ja4FamUnknown && !uaMatchesJA4Family(ua, jf) {
				score += c.wUAMismatch
			}
		} else if c.ja4Configured {
			score += c.wUnknownJA4
		}
		if !in.hasAcceptLang && !in.hasSecFetch {
			score += c.wNoBrowserHeaders
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// botScoreAction is what the score asks for.
type botScoreAction uint8

const (
	botPass      botScoreAction = iota // continue, never challenged
	botChallenge                       // normal flow; ladder may raise the difficulty floor
	botBlock                           // 403 immediately
)

// actionFor maps a score to an action. blockAbove wins first, then
// passBelow; otherwise challenge with the ladder's difficulty (0 = below the
// first rung → caller keeps the ordinary base resolution). A disabled
// config always challenges with difficulty 0 (the gate is not even entered).
func (c *botScoreConfig) actionFor(score int) (botScoreAction, uint) {
	if !c.enabled {
		return botChallenge, 0
	}
	if c.blockAbove > 0 && score >= c.blockAbove {
		return botBlock, 0
	}
	if c.passBelow > 0 && score < c.passBelow {
		return botPass, 0
	}
	return botChallenge, c.ladderDifficultyFor(score)
}

// ladderDifficultyFor returns the difficulty of the highest rung the score
// reaches, or 0 when the score is below the first rung's min_score (caller
// uses the ordinary base). The ladder is sorted by min_score at parse time.
func (c *botScoreConfig) ladderDifficultyFor(score int) uint {
	for i := len(c.ladder) - 1; i >= 0; i-- {
		if score >= c.ladder[i].minScore {
			return c.ladder[i].difficulty
		}
	}
	return 0
}
