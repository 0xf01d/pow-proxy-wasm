//go:build !wasip1

package ipintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCrawlerFixture(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func excludeAllExcept(names ...string) map[string]bool {
	keep := make(map[string]bool, len(names))
	for _, name := range names {
		keep[name] = true
	}
	exclude := map[string]bool{}
	for _, name := range SourceNames() {
		if !keep[name] {
			exclude[name] = true
		}
	}
	return exclude
}

func TestCrawlerSourcesAndParser(t *testing.T) {
	want := map[string]string{
		"googlebot":              "search_crawler",
		"google-special-crawler": "search_crawler",
		"bingbot":                "search_crawler",
		"applebot":               "search_crawler",
		"gptbot":                 "ai_crawler",
		"openai-searchbot":       "ai_crawler",
		"chatgpt-user":           "ai_crawler",
		"perplexitybot":          "ai_crawler",
		"ccbot":                  "ai_crawler",
	}
	seen := map[string]bool{}
	for _, spec := range sourceSpecs(Options{}) {
		category, ok := want[spec.Name]
		if !ok {
			continue
		}
		seen[spec.Name] = true
		if spec.Group != "crawlers" {
			t.Errorf("%s group = %q, want crawlers", spec.Name, spec.Group)
		}
		if !spec.Optional {
			t.Errorf("%s must be optional", spec.Name)
		}
		dir := t.TempDir()
		writeCrawlerFixture(t, dir, spec.Files[0].Name, `{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"2001:db8::/32"},{"neither":true}]}`)
		parsed, err := spec.Parse(dir, []string{spec.Files[0].Name})
		if err != nil {
			t.Fatalf("%s parse: %v", spec.Name, err)
		}
		if len(parsed.Records) != 2 {
			t.Fatalf("%s records = %d, want 2", spec.Name, len(parsed.Records))
		}
		for _, rec := range parsed.Records {
			if rec.Category != category {
				t.Errorf("%s category = %q, want %q", spec.Name, rec.Category, category)
			}
			for _, field := range []string{`"group":"crawlers"`, `"operator":`, `"bot":`} {
				if !strings.Contains(rec.Detail, field) {
					t.Errorf("%s detail %s missing %s", spec.Name, rec.Detail, field)
				}
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("crawler source %q is missing", name)
		}
	}
}

func TestLookupCrawlerGroupAndScore(t *testing.T) {
	raw := t.TempDir()
	const prefix = `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`
	writeCrawlerFixture(t, raw, "googlebot-common.json", prefix)
	writeCrawlerFixture(t, raw, "gptbot.json", prefix)

	out := filepath.Join(t.TempDir(), "db.bin")
	m, err := Build(BuildOptions{
		RawDir: raw, OutFile: out, BlockSize: 8,
		Exclude: excludeAllExcept("googlebot", "gptbot"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != 2 {
		t.Fatalf("sources = %+v", m.Sources)
	}
	for _, source := range m.Sources {
		if source.Group != "crawlers" {
			t.Fatalf("%s group = %q", source.Name, source.Group)
		}
	}

	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 0 {
		t.Fatalf("crawler score = %d, want 0", res.Score)
	}
	if res.Verdict != "unknown" {
		t.Fatalf("crawler verdict = %q, want unknown", res.Verdict)
	}
	for _, group := range []string{"search_crawler", "ai_crawler", "crawlers"} {
		if !containsString(res.Groups, group) {
			t.Fatalf("groups = %v, missing %s", res.Groups, group)
		}
	}
	if len(res.Crawlers) != 2 {
		t.Fatalf("crawlers = %+v", res.Crawlers)
	}
	var google *CrawlerMatch
	for i := range res.Crawlers {
		if res.Crawlers[i].Category == "search_crawler" {
			google = &res.Crawlers[i]
		}
	}
	if google == nil || google.Operator != "Google" || google.Bot != "Googlebot" {
		t.Fatalf("google crawler detail = %+v", res.Crawlers)
	}
}

func TestLookupCrawlerAlsoHostingKeepsVerdict(t *testing.T) {
	raw := t.TempDir()
	writeCrawlerFixture(t, raw, "googlebot-common.json", `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`)
	writeCrawlerFixture(t, raw, "datacenter-ipv4.txt", "203.0.113.0/24\n")
	writeCrawlerFixture(t, raw, "datacenter-ipv6.txt", "\n")

	out := filepath.Join(t.TempDir(), "db.bin")
	_, err := Build(BuildOptions{
		RawDir: raw, OutFile: out, BlockSize: 8,
		Exclude: excludeAllExcept("googlebot", "x4b-datacenter"),
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "hosting" {
		t.Fatalf("crawler+hosting verdict = %q, want hosting", res.Verdict)
	}
	if res.Score == 0 {
		t.Fatal("crawler+hosting score = 0, want hosting score")
	}
	if !containsString(res.Groups, "search_crawler") || !containsString(res.Groups, "crawlers") {
		t.Fatalf("crawler+hosting groups = %v", res.Groups)
	}
}

func TestLookupResidentialHasNoCrawlerGroup(t *testing.T) {
	prefix, err := parsePrefix("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	rec := recordFromPrefix(prefix, "residential_isp", 60, `{"provider":"fixture"}`)
	out := filepath.Join(t.TempDir(), "db.bin")
	if err := writeDatabase(out, []Record{rec}, &Manifest{
		FormatVersion: FormatVersion, BlockSize: 8,
		Sources: []SourceMeta{{ID: 0, Name: "fixture"}},
	}); err != nil {
		t.Fatal(err)
	}
	db, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Lookup("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 0 || len(res.Crawlers) != 0 {
		t.Fatalf("residential groups = %v crawlers = %+v", res.Groups, res.Crawlers)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
