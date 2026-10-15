package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestBannerPlainAndColor(t *testing.T) {
	plain := renderBanner(false)
	if strings.Contains(plain, "\x1b") {
		t.Fatal("plain banner contains escape codes")
	}
	col := renderBanner(true)
	if !strings.Contains(col, "\x1b[1;38;5;") {
		t.Fatal("colour banner has no colour")
	}
	if ansiRE.ReplaceAllString(col, "") == "" || !strings.Contains(col, "v"+version) {
		t.Fatal("colour banner lost its text or version")
	}
	// fits an 80-column terminal, and every art row ends with a reset
	for _, l := range strings.Split(ansiRE.ReplaceAllString(col, ""), "\n") {
		if n := utf8.RuneCountInString(l); n > 80 {
			t.Errorf("line is %d columns: %q", n, l)
		}
	}
	if strings.Count(col, ansiReset) < len(bannerArt) {
		t.Error("colour left open at the end of a row")
	}
}

func TestBannerOnlyOnTerminal(t *testing.T) {
	var b bytes.Buffer
	printBanner(&b, false, false)
	printBanner(&b, true, true)
	if b.Len() != 0 {
		t.Fatalf("banner printed off a terminal or with -no-banner: %q", b.String())
	}
	t.Setenv("C2PARSER_NO_BANNER", "1")
	printBanner(&b, true, false)
	if b.Len() != 0 {
		t.Fatal("C2PARSER_NO_BANNER ignored")
	}
}

func TestBannerColorRules(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	for _, c := range []struct {
		kv   map[string]string
		goos string
		want bool
	}{
		{nil, "darwin", true},
		{nil, "linux", true},
		{map[string]string{"NO_COLOR": "1"}, "linux", false},
		{map[string]string{"TERM": "dumb"}, "linux", false},
		{nil, "windows", false}, // legacy console: plain
		{map[string]string{"WT_SESSION": "x"}, "windows", true},
		{map[string]string{"WT_SESSION": "x", "NO_COLOR": "1"}, "windows", false},
	} {
		if got := bannerColor(env(c.kv), c.goos); got != c.want {
			t.Errorf("%v on %s: colour %v, want %v", c.kv, c.goos, got, c.want)
		}
	}
}

func TestBannerOffFlag(t *testing.T) {
	for args, want := range map[string]bool{
		"-json cap.pcap":              false,
		"-no-banner cap.pcap":         true,
		"--no-banner -json x":         true,
		"-no-banner=true x":           true,
		"eval -no-banner -manifest m": true,
		"-- -no-banner":               false,
	} {
		if got := bannerOff(strings.Fields(args)); got != want {
			t.Errorf("%q: off=%v, want %v", args, got, want)
		}
	}
}
