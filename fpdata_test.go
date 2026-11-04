package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// TestKnownBadJA4Denylist pins the denylist rule in score():
//   - every entry in the vendored map (+w_known_bad_ja4, default 100) must
//     block on its own (score >= any sane block_above), independent of the
//     User-Agent — the fingerprint alone is the evidence;
//   - a structurally valid fingerprint absent from the map scores nothing;
//   - an empty/missing ja4 scores nothing;
//   - an EMPTY map (the --no-foxio build) is a no-op: the weight goes inert
//     and nothing in the scorer panics or scores.
//
// The assertions branch on len(knownBadJA4) so the same test pins the
// generated build AND the --no-foxio stub build (make build NO_FOXIO=1).
func TestKnownBadJA4Denylist(t *testing.T) {
	cfg := botTestConfig()
	cfg.blockAbove = 90
	cfg.ja4Configured = true

	quiet := botScoreInput{userAgent: "curl/8.5.0", hasAcceptLang: true, hasSecFetch: true}
	if got := cfg.score(quiet); got != 0 {
		t.Fatalf("clean non-browser input scored %d, want 0", got)
	}

	if len(knownBadJA4) == 0 {
		// --no-foxio build: denylist inert. Any input must score exactly what
		// it would without the rule (here: 0 — no browser claim, no ipintel).
		t.Log("knownBadJA4 is empty (--no-foxio build): asserting the weight is inert")
		in := quiet
		in.ja4 = "t13d201100_2b729b4bf6f3_9e7b989ebec8" // IcedID's fingerprint
		if got := cfg.score(in); got != 0 {
			t.Fatalf("empty denylist scored %d for %s, want 0 (weight must be inert)", got, in.ja4)
		}
		return
	}

	for fp, label := range knownBadJA4 {
		if len(fp) != ja4FPLen || normalizeJA4(fp) == "" {
			t.Errorf("denylist entry %s (%s) is not a valid normalized JA4 fingerprint", fp, label)
			continue
		}
		// UA-independent: an honest non-browser UA over a known-bad
		// fingerprint must still block (the tooling IS the evidence).
		in := quiet
		in.ja4 = fp
		got := cfg.score(in)
		if got != defaultWKnownBadJA4 {
			t.Errorf("known-bad %s (%s) scored %d, want %d", fp, label, got, defaultWKnownBadJA4)
			continue
		}
		act, _ := cfg.actionFor(got)
		if act != botBlock {
			t.Errorf("known-bad %s (%s) score %d → action %v, want block (block_above=90)", fp, label, got, act)
		}
		// browser UA over a known-bad fingerprint: denylist + (possibly)
		// mismatch — must block, never score less.
		in.userAgent = chromeUA
		if got2 := cfg.score(in); got2 < defaultWKnownBadJA4 {
			t.Errorf("known-bad %s with browser UA scored %d, want >= %d", fp, got2, defaultWKnownBadJA4)
		}
	}

	// Unknown fingerprint: valid shape, not in the map → no denylist score.
	unknown := "t13d9999h2_000000000000_000000000000"
	if _, ok := knownBadJA4[unknown]; ok {
		t.Fatalf("probe fingerprint %s unexpectedly denylisted; pick another", unknown)
	}
	in := quiet
	in.ja4 = unknown
	if got := cfg.score(in); got != 0 {
		t.Errorf("unknown fingerprint %s scored %d, want 0", unknown, got)
	}
	// Missing ja4: never a denylist hit.
	if got := cfg.score(quiet); got != 0 {
		t.Errorf("empty ja4 scored %d, want 0", got)
	}
	// Zero weight (operator override) disables the rule without erroring.
	cfg2 := botTestConfig()
	cfg2.wKnownBadJA4 = 0
	for fp := range knownBadJA4 {
		in := quiet
		in.ja4 = fp
		if got := cfg2.score(in); got != 0 {
			t.Errorf("w_known_bad_ja4=0 still scored %d for %s, want 0", got, fp)
			break
		}
	}
}

// TestFamilyTableClassifiesVendoredBrowsers reads the vendored
// browser-fingerprints.json and requires the family table to classify the
// real measured Chrome/Firefox/Safari fingerprints as their browsers. Edge
// and iOS are asserted only when the table carries their machine-refreshed
// entries (the --no-browsers stub ships the original hand-written table,
// which predates those two), keeping the test meaningful in both builds.
func TestFamilyTableClassifiesVendoredBrowsers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("data", "fingerprints", "browser-fingerprints.json"))
	if err != nil {
		t.Fatalf("vendored browser-fingerprints.json unreadable: %v", err)
	}
	for _, probe := range []struct {
		browser string
		family  ja4Family
	}{
		{"chrome", ja4FamChromium},
		{"firefox", ja4FamFirefox},
		{"safari", ja4FamSafari},
	} {
		fp := vendoredBrowserJA4(t, raw, probe.browser)
		norm := normalizeJA4(fp)
		if norm == "" {
			t.Fatalf("%s tls.ja4 %q does not pass normalizeJA4", probe.browser, fp)
		}
		if got := classifyJA4(norm); got != probe.family {
			t.Errorf("%s fingerprint %s classified %v, want %v", probe.browser, norm, got, probe.family)
		}
	}

	// part-a of the fp is what the table keys on.
	for _, probe := range []struct {
		browser string
		family  ja4Family
	}{
		{"edge", ja4FamChromium},
		{"ios", ja4FamSafari},
	} {
		partA := vendoredBrowserJA4(t, raw, probe.browser)[:10]
		if _, ok := ja4FamilyTable[partA]; !ok {
			t.Logf("table has no entry for %s part-a %s (--no-browsers stub build); skipping", probe.browser, partA)
			continue
		}
		if got := ja4FamilyTable[partA]; got != probe.family {
			t.Errorf("%s part-a %s classified %v, want %v", probe.browser, partA, got, probe.family)
		}
	}
}

// vendoredBrowserJA4 extracts browsers[name].tls.ja4 from the vendored JSON.
func vendoredBrowserJA4(t *testing.T, raw []byte, name string) string {
	t.Helper()
	fp := gjson.GetBytes(raw, "browsers."+name+".tls.ja4").Str
	if fp == "" {
		t.Fatalf("browser %q has no tls.ja4 in the vendored JSON", name)
	}
	return fp
}

// TestUpdateFingerprintData drives the real scripts/update-fingerprint-data.sh
// in a sandbox repo (fixtures hook, no network) and asserts the validators
// refuse broken upstream files and never touch the tree, while a valid pair
// regenerates the Go files deterministically — including the denylist
// benign-collision exclusion and the --no-foxio stub.
func TestUpdateFingerprintData(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	script, err := os.ReadFile(filepath.Join("scripts", "update-fingerprint-data.sh"))
	if err != nil {
		t.Fatalf("read script: %v", err)
	}

	goodCSV := buildTestCSV(t)
	goodJSON := buildTestJSON(t)

	t.Run("truncated CSV is refused", func(t *testing.T) {
		sb := sandbox(t, script)
		writeFixtures(t, sb, strings.Join(strings.SplitN(goodCSV, "\n", 4)[:3], "\n")+"\n", goodJSON)
		out, err := runScript(sb, "--fixtures=fixtures")
		if err == nil {
			t.Fatalf("truncated CSV accepted: %s", out)
		}
		assertGenFilesAbsent(t, sb, out)
	})

	t.Run("malformed JSON is refused", func(t *testing.T) {
		sb := sandbox(t, script)
		writeFixtures(t, sb, goodCSV, `{"browsers": {"chrome": {"tls": {"ja4": "t13d1516`)
		out, err := runScript(sb, "--fixtures=fixtures")
		if err == nil {
			t.Fatalf("malformed JSON accepted: %s", out)
		}
		assertGenFilesAbsent(t, sb, out)
	})

	t.Run("ja4 shape violation is refused", func(t *testing.T) {
		sb := sandbox(t, script)
		bad := strings.Replace(goodJSON, "t13d1516h2_8daaf6152771_d8a2da3f94cd", "t13d1516H2_8DAF6152771_D8A2DA3F94CD", 1)
		if bad == goodJSON {
			t.Fatal("fixture mutation did not change the JSON")
		}
		writeFixtures(t, sb, goodCSV, bad)
		out, err := runScript(sb, "--fixtures=fixtures")
		if err == nil {
			t.Fatalf("uppercase-hex ja4 accepted: %s", out)
		}
		assertGenFilesAbsent(t, sb, out)
	})

	t.Run("valid fixtures generate deterministic files", func(t *testing.T) {
		sb := sandbox(t, script)
		writeFixtures(t, sb, goodCSV, goodJSON)
		out, err := runScript(sb, "--fixtures=fixtures")
		if err != nil || !strings.Contains(out, "changed:") {
			t.Fatalf("first run failed: err=%v out=%s", err, out)
		}

		deny := readGen(t, sb, "fpdata_gen.go")
		icedID := "t13d201100_2b729b4bf6f3_9e7b989ebec8"
		goLang := "t13d190900_9dc949149365_97f8aa674fd9"
		if !strings.Contains(deny, `"`+icedID+`"`) {
			t.Error("denylist is missing the IcedID fingerprint")
		}
		if strings.Contains(deny, `"`+goLang+`"`) {
			t.Error("denylist contains the Sliver/GoLang collision — honest Go clients would block")
		}
		table := readGen(t, sb, "fpbrowsers_gen.go")
		for partA, fam := range map[string]string{
			"t13d1516h2": "ja4FamChromium", // chrome
			"t13d1715h2": "ja4FamFirefox",  // firefox
			"t13d2014h2": "ja4FamSafari",   // safari
			"t13d1515h2": "ja4FamChromium", // edge (machine-refreshed entry)
		} {
			if !strings.Contains(table, `"`+partA+`": `+fam) {
				t.Errorf("family table missing %s → %s", partA, fam)
			}
		}

		// second run: byte-identical inputs → "unchanged" (cmp-gated).
		out2, err := runScript(sb, "--fixtures=fixtures")
		if err != nil || !strings.Contains(out2, "unchanged") {
			t.Fatalf("second run must be a no-op: err=%v out=%s", err, out2)
		}
		deny2 := readGen(t, sb, "fpdata_gen.go")
		if deny2 != deny {
			t.Error("regeneration is not deterministic (fpdata_gen.go drifted)")
		}
		if readGen(t, sb, "fpbrowsers_gen.go") != table {
			t.Error("regeneration is not deterministic (fpbrowsers_gen.go drifted)")
		}
	})

	t.Run("--no-foxio emits an empty denylist stub", func(t *testing.T) {
		sb := sandbox(t, script)
		writeFixtures(t, sb, goodCSV, goodJSON)
		out, err := runScript(sb, "--fixtures=fixtures", "--no-foxio")
		if err != nil || !strings.Contains(out, "changed:") {
			t.Fatalf("stub run failed: err=%v out=%s", err, out)
		}
		deny := readGen(t, sb, "fpdata_gen.go")
		if !strings.Contains(deny, "var knownBadJA4 = map[string]string{}") {
			t.Errorf("--no-foxio stub must carry an empty map, got:\n%s", deny)
		}
		// family table generation is unaffected by --no-foxio
		table := readGen(t, sb, "fpbrowsers_gen.go")
		if !strings.Contains(table, `"t13d1516h2": ja4FamChromium`) {
			t.Error("--no-foxio must not affect the family table")
		}
	})

	t.Run("--no-browsers emits the original hand-written table", func(t *testing.T) {
		sb := sandbox(t, script)
		writeFixtures(t, sb, goodCSV, goodJSON)
		out, err := runScript(sb, "--fixtures=fixtures", "--no-browsers")
		if err != nil || !strings.Contains(out, "changed:") {
			t.Fatalf("stub run failed: err=%v out=%s", err, out)
		}
		table := readGen(t, sb, "fpbrowsers_gen.go")
		for _, want := range []string{
			`"t13d1516h2": ja4FamChromium`,
			`"t13i2013h2": ja4FamSafari`,
			`"t13d1412h2": ja4FamOther`,
		} {
			if !strings.Contains(table, want) {
				t.Errorf("--no-browsers stub table missing %s (must be the original hand-written table)", want)
			}
		}
		// denylist generation is unaffected by --no-browsers
		if !strings.Contains(readGen(t, sb, "fpdata_gen.go"), `"t13d201100_2b729b4bf6f3_9e7b989ebec8"`) {
			t.Error("--no-browsers must not affect the denylist")
		}
	})
}

// --- sandbox helpers ---------------------------------------------------------

func sandbox(t *testing.T, script []byte) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "data", "fingerprints"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "scripts", "update-fingerprint-data.sh")
	if err := os.WriteFile(p, script, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFixtures(t *testing.T, root, csv, json string) {
	t.Helper()
	dir := filepath.Join(root, "fixtures")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "foxio-ja4plus-mapping.csv"), []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "browser-fingerprints.json"), []byte(json), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runScript(root string, args ...string) (string, error) {
	cmd := exec.Command("sh", append([]string{filepath.Join("scripts", "update-fingerprint-data.sh")}, args...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readGen(t *testing.T, root, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("generated file %s missing: %v", name, err)
	}
	return string(b)
}

func assertGenFilesAbsent(t *testing.T, root, out string) {
	t.Helper()
	for _, name := range []string{"fpdata_gen.go", "fpbrowsers_gen.go"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Errorf("%s landed in the tree despite a rejected upstream file\nscript output:\n%s", name, out)
		}
	}
}

// buildTestCSV builds a fixture CSV: header + 30 benign rows (>= the
// validator's MIN_JA4_CELLS) + a benign GoLang row + a Sliver row reusing the
// GoLang fingerprint (must be excluded) + an IcedID row (must be included).
func buildTestCSV(t *testing.T) string {
	t.Helper()
	const header = "Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes"
	var b strings.Builder
	b.WriteString(header + "\n")
	for i := 0; i < 30; i++ {
		fp, ok := validTestJA4(i)
		if !ok {
			t.Fatalf("fixture row %d failed to synthesize", i)
		}
		b.WriteString("Python,,," + "," + fp + ",,,,,,\n")
	}
	b.WriteString("GoLang,,,," + "t13d190900_9dc949149365_97f8aa674fd9,,,,,,\n")
	b.WriteString("Sliver Agent,GoLang,,," + ",t13d190900_9dc949149365_97f8aa674fd9,,,,,,\n")
	b.WriteString("IcedID,,,,t13d201100_2b729b4bf6f3_9e7b989ebec8,,,,,,\n")
	return b.String()
}

func buildTestJSON(t *testing.T) string {
	t.Helper()
	return `{
  "$schema": "./fingerprints.schema.json",
  "metadata": {"description": "test fixture", "live_updated": "2026-01-01"},
  "browsers": {
    "chrome":  {"tls": {"ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd"}},
    "edge":    {"tls": {"ja4": "t13d1515h2_8daaf6152771_bc9a4605e104"}},
    "firefox": {"tls": {"ja4": "t13d1715h2_5b57614c22b0_5c2c66f702b0"}},
    "ios":     {"tls": {"ja4": "t13d2613h2_2802a3db6c62_38ba08824cc9"}},
    "safari":  {"tls": {"ja4": "t13d2014h2_a09f3c656075_874d27d7ca63"}}
  },
  "live": []
}
`
}

// validTestJA4 synthesizes the i-th structurally valid fingerprint
// (t13d1516h2_… form, unique per i).
func validTestJA4(i int) (string, bool) {
	hex := "0123456789abcdef"
	enc := func(n int) string {
		var b strings.Builder
		for j := 0; j < 12; j++ {
			b.WriteByte(hex[(n>>(4*(j%8)))&0xf])
		}
		return b.String()
	}
	if i < 0 || i > 0xffff {
		return "", false
	}
	return "t13d1516h2_" + enc(i) + "_" + enc(i*7+3), true
}
