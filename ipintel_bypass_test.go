// Copyright 2026 kubeWAF / pow-proxy-wasm contributors
// Apache License 2.0 — see LICENSE.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	ipintelbin "github.com/kubewaf-io/pow-proxy-wasm/ipintelbin"
)

func buildBypassTestDB(t *testing.T) (*ipintelbin.DB, []byte) {
	t.Helper()
	raw := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(raw, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("googlebot-common.json", `{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`)
	write("datacenter-ipv4.txt", "203.0.113.0/24\n198.51.100.0/24\n")
	write("datacenter-ipv6.txt", "\n")

	exclude := map[string]bool{}
	for _, name := range ipintelbin.SourceNames() {
		if name != "googlebot" && name != "x4b-datacenter" {
			exclude[name] = true
		}
	}
	out := filepath.Join(t.TempDir(), "db.bin")
	if _, err := ipintelbin.Build(ipintelbin.BuildOptions{
		RawDir: raw, OutFile: out, Exclude: exclude, BlockSize: 8,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	db, err := ipintelbin.OpenBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, b
}

func bypassTestPlugin(db *ipintelbin.DB) *pluginContext {
	secret := []byte("0123456789abcdef0123456789abcdef")
	return &pluginContext{
		ipintel:        db,
		ipintelMode:    ipintelModeChallenge,
		ipintelCats:    map[string]bool{"hosting": true},
		ipintelBypass:  map[string]bool{"search_crawler": true},
		ipintelEnabled: true,
		protectAll:     true,
		secret:         secret,
		mac:            hmac.New(sha256.New, secret),
		baseDifficulty: 12,
		minDifficulty:  12,
		maxDifficulty:  26,
		clientIPSource: ipSourcePeer,
	}
}

func TestCrawlerGroupBypassUsesPeerAddressNotUserAgent(t *testing.T) {
	db, _ := buildBypassTestDB(t)
	p := bypassTestPlugin(db)

	// A spoofed User-Agent is not an input to the lookup or the bypass: the
	// non-crawler peer address still takes the ordinary hosting challenge.
	spoofedUserAgent := "Googlebot"
	_ = spoofedUserAgent
	res, ok := p.ipintelResult("198.51.100.7")
	if !ok {
		t.Fatal("lookup failed")
	}
	if len(res.Groups) != 0 {
		t.Fatalf("non-crawler groups = %v", res.Groups)
	}
	decision, _ := decideIPIntelGroups(p.ipintelMode, p.ipintelCats, p.ipintelBypass, p.ipintelDiff, res.Verdict, res.Groups)
	if decision != ipChallenge {
		t.Fatalf("spoofed User-Agent decision = %v, want challenge", decision)
	}

	// The same request from the actual Googlebot range is bypassed.
	res, ok = p.ipintelResult("203.0.113.7")
	if !ok {
		t.Fatal("crawler lookup failed")
	}
	if res.Verdict != "hosting" {
		t.Fatalf("crawler+hosting verdict = %q", res.Verdict)
	}
	decision, _ = decideIPIntelGroups(p.ipintelMode, p.ipintelCats, p.ipintelBypass, p.ipintelDiff, res.Verdict, res.Groups)
	if decision != ipPass {
		t.Fatalf("crawler decision = %v, want pass", decision)
	}
}

func TestParseIPIntelConfigValidBypass(t *testing.T) {
	_, dbBytes := buildBypassTestDB(t)
	cfg := []byte(`{"ipintel":{"mode":"challenge","challenge_categories":["hosting"],"bypass_groups":[" Search_Crawler ","","crawlers"]}}`)
	db, mode, cats, bypass, target, enabled, problems := parseIPIntelConfig(cfg, dbBytes)
	if !enabled || db == nil || mode != ipintelModeChallenge || target != 0 || len(problems) != 0 {
		t.Fatalf("config: db=%v mode=%q target=%d enabled=%v problems=%v", db != nil, mode, target, enabled, problems)
	}
	if !cats["hosting"] || !bypass["search_crawler"] || !bypass["crawlers"] || bypass[""] {
		t.Fatalf("cats=%v bypass=%v", cats, bypass)
	}
}
