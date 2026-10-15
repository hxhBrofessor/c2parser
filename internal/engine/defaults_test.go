package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// Tests for the research-derived default indicators: C2 certificate table,
// certificate anomalies, Cobalt Strike DNS defaults, and framework default
// HTTP profiles (Covenant, Merlin, PoshC2, Cobalt Strike no-profile).

// ------------------------------------------------------------- certificates

var certNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

type certSpec struct {
	serial    int64
	bigSerial string
	subject   pkix.Name
	days      int
	parent    *x509.Certificate
	parentKey *ecdsa.PrivateKey
	isCA      bool
}

// mkCert issues a certificate and returns it parsed the way the TLS engine
// parses it (from a Certificate handshake body), plus its raw parts.
func mkCert(t *testing.T, s certSpec) (*certInfo, *x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(s.serial)
	if s.bigSerial != "" {
		serial, _ = new(big.Int).SetString(s.bigSerial, 10)
	}
	if s.days == 0 {
		s.days = 365
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: s.subject, NotBefore: certNow,
		NotAfter: certNow.AddDate(0, 0, s.days), IsCA: s.isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	parent, pkey := tmpl, key
	if s.parent != nil {
		parent, pkey = s.parent, s.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, pkey)
	if err != nil {
		t.Fatal(err)
	}
	ci := parseCertificateMsg(certMsg(der))
	if ci == nil {
		t.Fatal("parseCertificateMsg returned nil")
	}
	c, _ := x509.ParseCertificate(der)
	return ci, c, key, der
}

// certMsg wraps one DER certificate as a TLS Certificate handshake body.
func certMsg(der []byte) []byte {
	u24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	entry := append(u24(len(der)), der...)
	return append(u24(len(entry)), entry...)
}

func TestKnownC2Certs(t *testing.T) {
	ca, caCert, caKey, _ := mkCert(t, certSpec{serial: 7, subject: pkix.Name{CommonName: "Example Issuing CA", Organization: []string{"Example"}}, isCA: true})
	_ = ca
	opCA, opCert, opKey, _ := mkCert(t, certSpec{serial: 8, subject: pkix.Name{CommonName: "operators"}, isCA: true})
	_ = opCA

	cases := []struct {
		name string
		spec certSpec
		want string // substring of the reason; "" = must not match
	}{
		{"cobalt strike serial+DN", certSpec{serial: 146473198, subject: pkix.Name{Country: []string{"Earth"}, Province: []string{"Cyberspace"},
			Locality: []string{"Somewhere"}, Organization: []string{"cobaltstrike"}, OrganizationalUnit: []string{"AdvancedPenTesting"}, CommonName: "Major Cobalt Strike"}}, "Cobalt Strike"},
		{"cobalt strike serial only", certSpec{serial: 146473198, subject: pkix.Name{CommonName: "cdn.example"}}, "0x8BB00EE"},
		{"poshc2", certSpec{serial: 1000, days: 3650, subject: pkix.Name{Country: []string{"US"}, Province: []string{"Minnesota"}, Locality: []string{"Minnetonka"},
			Organization: []string{"Pajfds"}, OrganizationalUnit: []string{"Jethpro"}, CommonName: "P18055077"}}, "PoshC2"},
		{"covenant self-signed", certSpec{serial: 99, days: 3650, subject: pkix.Name{CommonName: "Covenant"}}, "Covenant"},
		{"covenant-named but CA-issued", certSpec{serial: 99, subject: pkix.Name{CommonName: "Covenant"}, parent: caCert, parentKey: caKey}, ""},
		{"brc4 DN", certSpec{serial: 5, subject: pkix.Name{Country: []string{"US"}, Province: []string{"California"}, Organization: []string{"Microsoft"},
			OrganizationalUnit: []string{"Security"}, CommonName: "localhost"}}, "Brute Ratel"},
		{"brc4 serial", certSpec{bigSerial: "476862511373535319627199034793753459614889484917", subject: pkix.Name{CommonName: "x"}}, "Brute Ratel"},
		{"sliver operator", certSpec{serial: 9, subject: pkix.Name{CommonName: "multiplayer"}, parent: opCert, parentKey: opKey}, "Sliver"},
		{"benign CA-issued", certSpec{serial: 0x1234567, subject: pkix.Name{CommonName: "www.example.com", Organization: []string{"Example"}}, parent: caCert, parentKey: caKey}, ""},
	}
	for _, c := range cases {
		ci, _, _, _ := mkCert(t, c.spec)
		why, ok := knownC2Cert(ci)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected match %q", c.name, why)
		case c.want != "" && (!ok || !strings.Contains(why, c.want)):
			t.Errorf("%s: got (%q, %v), want reason containing %q", c.name, why, ok, c.want)
		}
	}
	// Exact-hash path: a cert whose SHA-256 is in the table.
	ci, _, _, _ := mkCert(t, certSpec{serial: 1, subject: pkix.Name{CommonName: "h"}})
	knownCertSHA256[ci.SHA256] = "test hash entry"
	defer delete(knownCertSHA256, ci.SHA256)
	if why, ok := knownC2Cert(ci); !ok || why != "test hash entry" {
		t.Errorf("SHA-256 lookup failed: %q %v", why, ok)
	}
}

func anomalyNames(hs []certHit) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.name)
	}
	return out
}

func TestCertAnomalies(t *testing.T) {
	sliverCA, sliverCACert, sliverCAKey, _ := mkCert(t, certSpec{serial: 11, subject: pkix.Name{}, days: 1095, isCA: true})
	_ = sliverCA
	publicCA, publicCACert, publicCAKey, _ := mkCert(t, certSpec{serial: 12, subject: pkix.Name{CommonName: "Example Issuing CA"}, isCA: true})
	_ = publicCA

	cases := []struct {
		name string
		spec certSpec
		want []string
	}{
		{"merlin empty DN, 2 y", certSpec{serial: 21, subject: pkix.Name{}, days: 730}, []string{"cert_empty_dn", "cert_generator_validity"}},
		{"sliver leaf, empty issuer, 3 y", certSpec{serial: 22, subject: pkix.Name{CommonName: "localhost"}, days: 1095, parent: sliverCACert, parentKey: sliverCAKey},
			[]string{"cert_empty_issuer", "cert_generator_validity"}},
		{"self-signed Microsoft", certSpec{serial: 23, subject: pkix.Name{Organization: []string{"Microsoft Corporation"}, CommonName: "update.microsoft.com"}},
			[]string{"cert_selfsigned_microsoft"}},
		{"self-signed 3650 d", certSpec{serial: 24, subject: pkix.Name{CommonName: "nas.local"}, days: 3650}, []string{"cert_generator_validity"}},
		{"benign self-signed 365 d", certSpec{serial: 25, subject: pkix.Name{CommonName: "printer.local"}}, nil},
		{"CA-issued 730 d is not flagged", certSpec{serial: 26, subject: pkix.Name{CommonName: "www.example.com"}, days: 730, parent: publicCACert, parentKey: publicCAKey}, nil},
		{"CA-issued Microsoft is not flagged", certSpec{serial: 27, subject: pkix.Name{Organization: []string{"Microsoft"}, CommonName: "login.example"}, parent: publicCACert, parentKey: publicCAKey}, nil},
	}
	for _, c := range cases {
		ci, _, _, _ := mkCert(t, c.spec)
		got := anomalyNames(certAnomalies(ci))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: anomalies %v, want %v", c.name, got, c.want)
		}
	}
	// 3650-day spans weigh less than 730/1095 (openssl -days 3650 habit).
	ci10, _, _, _ := mkCert(t, certSpec{serial: 30, subject: pkix.Name{CommonName: "a"}, days: 3650})
	ci2, _, _, _ := mkCert(t, certSpec{serial: 31, subject: pkix.Name{CommonName: "b"}, days: 730})
	if w10, w2 := certAnomalies(ci10)[0].weight, certAnomalies(ci2)[0].weight; w10 >= w2 {
		t.Errorf("3650-day weight %.2f should be below 730-day %.2f", w10, w2)
	}
}

// serverHelloCert builds a TLS 1.2 ServerHello + Certificate flight.
func serverHelloCert(der []byte) []byte {
	sh := []byte{3, 3}
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0)          // session id
	sh = append(sh, 0xc0, 0x30) // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	sh = append(sh, 0)          // compression
	hs := append([]byte{2, 0, byte(len(sh) >> 8), byte(len(sh))}, sh...)
	cm := certMsg(der)
	hs = append(hs, 11, byte(len(cm)>>16), byte(len(cm)>>8), byte(len(cm)))
	hs = append(hs, cm...)
	return append([]byte{0x16, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// End to end: a PoshC2 team server's default certificate over TLS 1.2.
func TestPoshC2CertOverTLS12(t *testing.T) {
	_, _, _, der := mkCert(t, certSpec{serial: 1000, days: 3650, subject: pkix.Name{Country: []string{"US"}, Province: []string{"Minnesota"},
		Locality: []string{"Minnetonka"}, Organization: []string{"Pajfds"}, OrganizationalUnit: []string{"Jethpro"}, CommonName: "P18055077"}})
	s := newSynth(t)
	ts := s.now
	for i := 0; i < 3; i++ {
		c := s.tcp(ts, "10.0.0.40", uint16(42000+i), "203.0.113.80", 443)
		ts = c.Send(ts.Add(5*time.Millisecond), true, clientHello("", nil), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, serverHelloCert(der), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), true, appData(300), 1400)
		ts = c.Send(ts.Add(20*time.Millisecond), false, appData(200), 1400)
		c.Close(ts.Add(10 * time.Millisecond))
		ts = ts.Add(5 * time.Second)
	}
	res := s.analyze(Config{})
	f := findBy(res, CatC2, "203.0.113.80")
	if f == nil || !hasSignal(f, "c2_default_certificate") {
		t.Fatalf("PoshC2 default cert not flagged: %+v", f)
	}
	if !hasSignal(f, "cert_generator_validity") {
		t.Errorf("3650-day self-signed span not flagged: %+v", f.Signals)
	}
}

// --------------------------------------------------------------- CS DNS

func cnameFreeA(name string, ip []byte, ttl uint32) []layers.DNSResourceRecord {
	return []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: ttl, IP: ip}}
}

func TestCSDNSDefaults(t *testing.T) {
	s := newSynth(t)
	ts := s.now
	id := uint16(1)
	q := func(client, name string, qt layers.DNSType, ans []layers.DNSResourceRecord) {
		s.dnsQuery(ts, client, "10.0.0.53", name, qt, id)
		s.dnsResp(ts.Add(15*time.Millisecond), client, "10.0.0.53", name, qt, id, layers.DNSResponseCodeNoErr, ans)
		id++
	}
	zero := []byte{0, 0, 0, 0}

	// 1. Tasked DNS beacon: idle check-ins (<id>.domain → 0.0.0.0, TTL 1)
	//    plus api./post./www. tasking and output names.
	for i := 0; i < 30; i++ {
		ts = ts.Add(60 * time.Second)
		q("10.0.1.5", "4f3a2b1c.ns.updates-cdn.example", layers.DNSTypeA, cnameFreeA("4f3a2b1c.ns.updates-cdn.example", zero, 1))
		if i%5 == 0 {
			n := fmt.Sprintf("api.%08x.4f3a2b1c.ns.updates-cdn.example", 0x1000+i)
			q("10.0.1.5", n, layers.DNSTypeTXT, []layers.DNSResourceRecord{{Name: []byte(n), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 1,
				TXTs: [][]byte{[]byte(base64.StdEncoding.EncodeToString(randB(60)))}}})
			p := fmt.Sprintf("post.%x.%08x.4f3a2b1c.ns.updates-cdn.example", randB(20), 0x2000+i)
			q("10.0.1.5", p, layers.DNSTypeA, cnameFreeA(p, zero, 1))
			w := fmt.Sprintf("www.%x.%08x.4f3a2b1c.ns.updates-cdn.example", randB(16), 0x3000+i)
			q("10.0.1.5", w, layers.DNSTypeA, cnameFreeA(w, zero, 1))
		}
	}
	// 2. Untasked beacon: only idle check-ins.
	ts = s.now
	for i := 0; i < 10; i++ {
		ts = ts.Add(60 * time.Second)
		q("10.0.1.6", "77aa88bb.idle-c2.example", layers.DNSTypeA, cnameFreeA("77aa88bb.idle-c2.example", zero, 1))
	}
	// 3. Stager marker alone.
	q("10.0.1.7", "aaa.stage.123456.stg-c2.example", layers.DNSTypeTXT, nil)
	// 4. Benign: www./api./cdn. hostnames with real answers and normal TTLs,
	//    and a low-TTL CDN that never answers 0.0.0.0.
	ts = s.now
	for i := 0; i < 40; i++ {
		ts = ts.Add(7 * time.Second)
		for _, n := range []string{"www.example.org", "api.github.com", "cdn.jsdelivr.net", "www.v2.api.example.org"} {
			q("10.0.1.8", n, layers.DNSTypeA, cnameFreeA(n, []byte{93, 184, 216, byte(i)}, 300))
		}
		n := fmt.Sprintf("edge-%d.fastcdn.example", i%3)
		q("10.0.1.8", n, layers.DNSTypeA, cnameFreeA(n, []byte{151, 101, 1, byte(i)}, 1))
	}
	res := s.analyze(Config{})

	for _, d := range []string{"updates-cdn.example", "idle-c2.example", "stg-c2.example"} {
		f := findBy(res, CatDNS, d)
		if f == nil || !hasSignal(f, "cs_dns_defaults") {
			t.Errorf("%s: CS DNS defaults not flagged: %+v", d, f)
		}
	}
	tasked := findBy(res, CatDNS, "updates-cdn.example")
	if tasked != nil {
		for _, sg := range tasked.Signals {
			if sg.Name == "cs_dns_defaults" && sg.Score < 0.8 {
				t.Errorf("tasked beacon conjunction scored only %.2f: %s", sg.Score, sg.Detail)
			}
		}
	}
	for _, d := range []string{"example.org", "github.com", "jsdelivr.net", "fastcdn.example"} {
		if f := findBy(res, CatDNS, d); f != nil && hasSignal(f, "cs_dns_defaults") {
			t.Errorf("benign %s flagged as CS DNS: %+v", d, f.Signals)
		}
	}
}

func TestCSDNSPrefixShape(t *testing.T) {
	for sub, want := range map[string]bool{
		"api.1a2b3c4d.4f3a2b1c":     true,
		"post.deadbeef00.11.22":     true,
		"www6.abcdef.1":             true,
		"api.v2":                    false, // too few labels
		"api.v2.prod":               false, // not hex
		"www.abc.1":                 false, // hex label too short
		"mail.1a2b3c4d.4f3a2b1c":    false, // not a CS prefix
		"cdn.1A2B3C4D.x":            false, // qnames are lower-cased before this
		"www.0123456789abcdef.west": true,
	} {
		if _, got := csDNSPrefix(sub); got != want {
			t.Errorf("csDNSPrefix(%q) = %v, want %v", sub, got, want)
		}
	}
}

// ------------------------------------------------------------- HTTP

func httpReq(method, uri string, hdrs []string, body string) []byte {
	h := method + " " + uri + " HTTP/1.1\r\n" + strings.Join(hdrs, "\r\n") + "\r\n"
	if body != "" || method == "POST" {
		h += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	return []byte(h + "\r\n" + body)
}

func httpResp(statusLine string, hdrs []string, body string) []byte {
	h := statusLine + "\r\n" + strings.Join(hdrs, "\r\n") + "\r\n"
	h += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	return []byte(h + "\r\n" + body)
}

// exchange writes n request/response pairs on one keep-alive connection.
func exchange(s *synth, client string, cport uint16, server string, n int, every time.Duration, req func(i int) []byte, resp func(i int) []byte) {
	ts := s.now
	c := s.tcp(ts, client, cport, server, 80)
	for i := 0; i < n; i++ {
		ts = ts.Add(every)
		ts = c.Send(ts, true, req(i), 1400)
		ts = c.Send(ts.Add(30*time.Millisecond), false, resp(i), 1400)
	}
	c.Close(ts.Add(time.Second))
}

func signalNamed(f *Finding, name string) (float64, string, bool) {
	if f == nil {
		return 0, "", false
	}
	for _, sg := range f.Signals {
		if sg.Name == name {
			return sg.Score, sg.Detail, true
		}
	}
	return 0, "", false
}

func TestHTTPFrameworkDefaults(t *testing.T) {
	s := newSynth(t)
	b64 := base64.StdEncoding.EncodeToString

	// Covenant default profile.
	exchange(s, "10.3.0.10", 50010, "198.51.100.10", 8, 10*time.Second, func(i int) []byte {
		hdr := []string{"Host: 198.51.100.10", "User-Agent: " + covenantUA, "Cookie: ASPSESSIONID=3c4e1d2a-5b6f-4a8b-9c0d-1e2f3a4b5c6d, SESSIONID=1552332971750"}
		if i%2 == 1 {
			return httpReq("POST", "/en-us/test.html", hdr, "i=a19ea23062db990386a3a478cb89d52e&data="+b64(randB(96))+"&session=75db-99b1-25fe4e9afbe58696-320bea73")
		}
		return httpReq("GET", "/en-us/index.html?page=1&v=1", hdr, "")
	}, func(i int) []byte {
		return httpResp("HTTP/1.1 200 OK", []string{"Server: Microsoft-IIS/7.5", "Content-Type: text/html"},
			"<html><head><title>Hello World!</title></head><body><p>Hello World!</p>// Hello World! "+b64(randB(48))+"</body></html>")
	})

	// Merlin agent over cleartext HTTP/1.1.
	exchange(s, "10.3.0.11", 50011, "198.51.100.11", 8, 30*time.Second, func(i int) []byte {
		return httpReq("POST", "/", []string{"Host: 198.51.100.11", "User-Agent: " + merlinUA,
			"Content-Type: application/octet-stream; charset=utf-8", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9." + b64(randB(30))}, string(randB(200)))
	}, func(i int) []byte {
		return httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, string(randB(120)))
	})

	// PoshC2: CPython http.server underneath ("Server: Apache " + HTTP/1.0).
	exchange(s, "10.3.0.12", 50012, "198.51.100.12", 8, 5*time.Second, func(i int) []byte {
		return httpReq("GET", "/adsense/troubleshooter/1631343/", []string{"Host: 198.51.100.12",
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36",
			"Cookie: SessionID=" + b64(randB(32))}, "")
	}, func(i int) []byte {
		return httpResp("HTTP/1.0 200 OK", []string{"Server: Apache ", "Date: Mon, 01 Jun 2026 00:00:00 GMT", "Content-type: text/html"}, b64(randB(90)))
	})

	// Cobalt Strike with no malleable profile.
	exchange(s, "10.3.0.13", 50013, "198.51.100.13", 8, 60*time.Second, func(i int) []byte {
		if i == 3 {
			return httpReq("POST", "/submit.php?id=93821", []string{"Host: 198.51.100.13", "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
				"Content-Type: application/octet-stream"}, string(randB(68)))
		}
		return httpReq("GET", "/pixel.gif", []string{"Host: 198.51.100.13", "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
			"Cookie: " + b64(randB(128))}, "")
	}, func(i int) []byte {
		return httpResp("HTTP/1.1 200 OK", []string{"Content-Type: application/octet-stream"}, "")
	})

	// Benign lookalikes: each carries one framework feature on its own.
	exchange(s, "10.3.0.20", 50020, "198.51.100.20", 6, 13*time.Second, func(i int) []byte {
		switch i % 3 {
		case 0:
			return httpReq("GET", "/ga.js", []string{"Host: www.google-analytics.example", "Cookie: _ga=GA1.2.123456789.987654321; _gid=GA1.2.1"}, "")
		case 1:
			return httpReq("POST", "/", []string{"Host: api.example", "Content-Type: application/json", "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig"}, `{"q":1}`)
		default:
			return httpReq("GET", "/en-us/index.html", []string{"Host: docs.example"}, "")
		}
	}, func(i int) []byte {
		return httpResp("HTTP/1.1 200 OK", []string{"Server: Microsoft-IIS/7.5", "Content-Type: text/html"}, "<html>ok</html>")
	})
	exchange(s, "10.3.0.21", 50021, "198.51.100.21", 6, 13*time.Second, func(i int) []byte {
		return httpReq("GET", "/index.html", []string{"Host: web.example", "Cookie: SessionID=abc123"}, "")
	}, func(i int) []byte {
		return httpResp("HTTP/1.1 200 OK", []string{"Server: Apache", "Content-Type: text/html"}, "<html>apache</html>")
	})

	res := s.analyze(Config{})
	for server, sig := range map[string]string{
		"198.51.100.10": "default_profile:covenant",
		"198.51.100.11": "default_profile:merlin",
		"198.51.100.12": "default_profile:poshc2",
		"198.51.100.13": "default_profile:cobalt_strike",
	} {
		f := findBy(res, CatC2, server)
		score, detail, ok := signalNamed(f, sig)
		if !ok || score < fwThreshold {
			var got []string
			if f != nil {
				for _, sg := range f.Signals {
					got = append(got, sg.Name)
				}
			}
			t.Errorf("%s: want %s ≥ %.2f, got %.2f (%s); signals %v", server, sig, fwThreshold, score, detail, got)
		}
	}
	for _, server := range []string{"198.51.100.20", "198.51.100.21"} {
		if f := findBy(res, CatC2, server); f != nil {
			for _, sg := range f.Signals {
				if strings.HasPrefix(sg.Name, "default_profile:") {
					t.Errorf("benign %s flagged: %s (%s)", server, sg.Name, sg.Detail)
				}
			}
		}
	}
}

func TestChecksum8(t *testing.T) {
	for path, want := range map[string]int{"/WWWW": 92, "/WWWX": 93} {
		if sum, ok := checksum8(path); !ok || sum != want {
			t.Errorf("checksum8(%q) = %d, %v; want %d", path, sum, ok, want)
		}
	}
	for _, p := range []string{"/home", "/news", "/WWWWW", "/WW-W", "/"} {
		if _, ok := checksum8(p); ok {
			t.Errorf("checksum8(%q) should not match", p)
		}
	}
}
