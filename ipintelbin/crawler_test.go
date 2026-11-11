package ipintel

import "testing"

func TestCrawlerCategoriesAreScoreNeutral(t *testing.T) {
	for _, cat := range []string{"search_crawler", "ai_crawler"} {
		weight, ok := categoryWeights[cat]
		if !ok {
			t.Fatalf("%s is missing from categoryWeights", cat)
		}
		if weight != 0 {
			t.Fatalf("%s weight = %d, want 0", cat, weight)
		}
		if categoryRank(cat) >= len(categoryOrder) {
			t.Fatalf("%s is missing from categoryOrder", cat)
		}
	}
	// The new categories sit immediately after vpn_candidate.
	idx := categoryRank("vpn_candidate")
	if categoryOrder[idx+1] != "search_crawler" || categoryOrder[idx+2] != "ai_crawler" {
		t.Fatalf("crawler category order = %v", categoryOrder[idx:idx+3])
	}

	score, verdict, cats := scoreEvidence([]Evidence{
		{Source: "googlebot", Category: "search_crawler", Confidence: 100, Matched: true},
	})
	if score != 0 || verdict != "unknown" || len(cats) != 0 {
		t.Fatalf("crawler-only = score %d verdict %q categories %+v", score, verdict, cats)
	}

	score, verdict, _ = scoreEvidence([]Evidence{
		{Source: "googlebot", Category: "search_crawler", Confidence: 100, Matched: true},
		{Source: "x4b-datacenter", Category: "hosting", Confidence: 80, Matched: true},
	})
	if score != 36 || verdict != "hosting" {
		t.Fatalf("crawler+hosting = score %d verdict %q, want 36/hosting", score, verdict)
	}
}

func TestCrawlerMatchesUsesEvidenceOnly(t *testing.T) {
	ev := []Evidence{
		{Source: "googlebot", Category: "search_crawler", Confidence: 100, Matched: true,
			Detail: []byte(`{"group":"crawlers","operator":"Google","bot":"Googlebot"}`)},
		{Source: "gptbot", Category: "ai_crawler", Confidence: 100, Matched: true,
			Detail: []byte(`{"group":"crawlers","operator":"OpenAI","bot":"GPTBot"}`)},
		{Source: "x4b-datacenter", Category: "hosting", Confidence: 80, Matched: true},
		{Source: "tor-exit", Category: "tor", Confidence: 100, Matched: false},
	}
	groups, crawlers := crawlerMatches(ev)
	wantGroups := []string{"ai_crawler", "crawlers", "search_crawler"}
	if len(groups) != len(wantGroups) {
		t.Fatalf("groups = %v, want %v", groups, wantGroups)
	}
	for i := range wantGroups {
		if groups[i] != wantGroups[i] {
			t.Fatalf("groups = %v, want %v", groups, wantGroups)
		}
	}
	if len(crawlers) != 2 {
		t.Fatalf("crawlers = %+v", crawlers)
	}
	if crawlers[0].Operator != "OpenAI" || crawlers[0].Bot != "GPTBot" {
		t.Fatalf("first crawler = %+v", crawlers[0])
	}
	if crawlers[1].Operator != "Google" || crawlers[1].Bot != "Googlebot" {
		t.Fatalf("second crawler = %+v", crawlers[1])
	}

	// Zero-weight non-crawler evidence must not masquerade as a crawler group.
	groups, crawlers = crawlerMatches([]Evidence{
		{Source: "openasn", Category: "residential_isp", Confidence: 60, Matched: true},
		{Source: "pomerium-vpn", Category: "vpn_candidate", Confidence: 60, Matched: true},
	})
	if len(groups) != 0 || len(crawlers) != 0 {
		t.Fatalf("non-crawler zero-weight evidence = %v %+v", groups, crawlers)
	}
}
