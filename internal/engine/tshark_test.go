package engine

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"c2parser/internal/pcapio"
)

// Cross-checks our JA3/JA4/SNI against Wireshark's implementation on every
// ClientHello in the lab captures. Skips without tshark or the captures.
func TestTLSFingerprintsMatchTshark(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed")
	}
	for _, name := range []string{"part2", "http_c2_enum", "smb2-wks"} {
		path := capture(t, name)
		out, err := exec.Command("tshark", "-r", path, "-Y", "tcp && tls.handshake.type==1 && !tcp.analysis.retransmission",
			"-T", "fields", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
			"-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.ja3", "-e", "tls.handshake.ja4").Output()
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(l, "\t")
			if len(f) < 7 {
				continue
			}
			k := fmt.Sprintf("%s:%s>%s:%s", f[0], f[1], f[2], f[3])
			if _, seen := want[k]; !seen { // first ClientHello (a HelloRetryRequest triggers a second)
				want[k] = f[4] + "|" + f[5] + "|" + f[6]
			}
		}
		r, err := pcapio.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		e := New(Config{})
		if err := e.Ingest(r); err != nil {
			t.Fatal(err)
		}
		r.Close()
		e.Finish()
		matched, mismatched := 0, 0
		for _, c := range e.allTCP {
			if c.tls == nil || !c.tls.clientOK {
				continue
			}
			k := fmt.Sprintf("%s>%s", c.client, c.server)
			w, ok := want[k]
			if !ok {
				continue
			}
			got := c.tls.hello.sni + "|" + c.tls.ja3 + "|" + c.tls.ja4
			if got != w {
				mismatched++
				if mismatched <= 5 {
					t.Errorf("%s %s\n  got  %s\n  want %s\n  ja3 %s", name, k, got, w, c.tls.ja3full)
				}
			} else {
				matched++
			}
		}
		seen := map[string]bool{}
		for _, c := range e.allTCP {
			seen[fmt.Sprintf("%s>%s", c.client, c.server)] = c.tls != nil && c.tls.clientOK
		}
		missing := 0
		for k := range want {
			if !seen[k] {
				missing++
				if missing <= 4 {
					t.Logf("not fingerprinted: %s", k)
				}
			}
		}
		t.Logf("%s: %d ClientHellos match tshark, %d mismatch, %d in tshark", name, matched, mismatched, len(want))
		if mismatched > 0 || matched < len(want)*9/10 {
			t.Errorf("%s: only %d of %d ClientHellos fingerprinted", name, matched, len(want))
		}
	}
}
