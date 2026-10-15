package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// The startup banner. It goes to stderr, and only when stderr is an
// interactive terminal, so -json output, pipes, redirects and CI logs stay
// clean. NO_COLOR (https://no-color.org) gives a plain banner;
// -no-banner or C2PARSER_NO_BANNER=1 turns it off.

var bannerArt = []string{
	` ██████╗██████╗ ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗ `,
	`██╔════╝╚════██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗`,
	`██║      █████╔╝██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝`,
	`██║     ██╔═══╝ ██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗`,
	`╚██████╗███████╗██║     ██║  ██║██║  ██║███████║███████╗██║  ██║`,
	` ╚═════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝`,
}

// cyan → blue → violet → pink, xterm-256 palette
var bannerGradient = []int{51, 45, 39, 33, 63, 99, 135, 171, 207, 213}

const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[38;5;240m"
)

func fg(c int) string { return fmt.Sprintf("\x1b[1;38;5;%dm", c) }

// renderBanner returns the banner, coloured or plain.
func renderBanner(color bool) string {
	var b strings.Builder
	b.WriteString("\n")
	for _, line := range bannerArt {
		r := []rune(line)
		b.WriteString("  ")
		if !color {
			b.WriteString(line)
			b.WriteString("\n")
			continue
		}
		cur := ""
		for x, ch := range r {
			want := ansiDim // shadow strokes
			if ch == '█' {
				want = fg(bannerGradient[x*len(bannerGradient)/len(r)])
			} else if ch == ' ' {
				want = cur // spaces don't need a colour change
			}
			if want != cur {
				b.WriteString(want)
				cur = want
			}
			b.WriteRune(ch)
		}
		b.WriteString(ansiReset + "\n")
	}
	tag := "passive C2 & exfil hunting in pcaps"
	if color {
		fmt.Fprintf(&b, "  %s▸%s %s%s%s  %s·%s %sv%s%s\n\n",
			fg(51), ansiReset, "\x1b[37m", tag, ansiReset,
			ansiDim, ansiReset, fg(213), version, ansiReset)
	} else {
		fmt.Fprintf(&b, "  > %s  ·  v%s\n\n", tag, version)
	}
	return b.String()
}

// isTerminal reports whether f is an interactive terminal (no extra deps).
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// bannerColor decides whether ANSI colour is safe: not under NO_COLOR or
// TERM=dumb, and on Windows only in terminals known to handle escapes.
func bannerColor(getenv func(string) string, goos string) bool {
	if getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	if goos == "windows" {
		return getenv("WT_SESSION") != "" || getenv("ANSICON") != "" ||
			getenv("ConEmuANSI") == "ON" || getenv("TERM_PROGRAM") != "" || strings.HasPrefix(getenv("TERM"), "xterm")
	}
	return true
}

// bannerOff reports whether -no-banner appears in args. It is checked before
// flag parsing so the banner can lead every run (-h, -version, eval, …).
func bannerOff(args []string) bool {
	for _, a := range args {
		if a == "--" {
			break
		}
		switch a {
		case "-no-banner", "--no-banner", "-no-banner=true", "--no-banner=true":
			return true
		}
	}
	return false
}

// printBanner writes the banner to w if it's wanted.
func printBanner(w io.Writer, tty, disabled bool) {
	if !tty || disabled || os.Getenv("C2PARSER_NO_BANNER") != "" {
		return
	}
	fmt.Fprint(w, renderBanner(bannerColor(os.Getenv, runtime.GOOS)))
}
