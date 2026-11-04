package main

import "testing"

// The docs claim the pass gate can never wave a flagged IP through. That is
// only true with the default weights: w_ipintel is configurable, so a config
// with w_ipintel below pass_below silently defeats the claim. This test pins
// the actual invariant so the docs stop overpromising.
func TestPassCannotWaveThroughFlaggedIP(t *testing.T) {
	ladder := []byte(`[{"min_score":0,"difficulty":1000}]`)

	// documented defaults: ipintel alone (+40) exceeds pass_below (20)
	cfg, problems := parseBotscoreConfig([]byte(`{"botscore":{
		"enabled":true,
		"pass_below":20,
		"ladder":[{"min_score":0,"difficulty":1000}]}}`), 1, 1<<20)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	in := botScoreInput{ipintelVerdict: "vpn", ipintelCats: map[string]bool{"vpn": true}}
	s := cfg.score(in)
	act, _ := cfg.actionFor(s)
	if act == botPass {
		t.Fatalf("flagged IP passed with default weights (score %d)", s)
	}
	t.Logf("defaults: flagged IP scores %d -> not pass (correct)", s)

	// the hole: an operator lowering w_ipintel below pass_below
	cfg2, _ := parseBotscoreConfig([]byte(`{"botscore":{
		"enabled":true,
		"w_ipintel":10,
		"pass_below":20,
		"ladder":[{"min_score":0,"difficulty":1000}]}}`), 1, 1<<20)
	s2 := cfg2.score(in)
	act2, _ := cfg2.actionFor(s2)
	t.Logf("w_ipintel=10, pass_below=20: flagged IP scores %d -> action %v", s2, act2)
	if act2 == botPass {
		t.Logf("CONFIRMED HOLE: a flagged IP passes when w_ipintel < pass_below; " +
			"the docs must not claim this is impossible")
	}
	_ = ladder
}
