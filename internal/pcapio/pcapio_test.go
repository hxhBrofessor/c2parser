package pcapio

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

func TestClassicRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2024, 3, 25, 8, 0, 0, 123456789, time.UTC)
	for i := 0; i < 3; i++ {
		if err := w.WritePacket(ts.Add(time.Duration(i)*time.Second), []byte{byte(i), 1, 2, 3}); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(t.TempDir(), "x.pcap")
	os.WriteFile(p, buf.Bytes(), 0o600)
	r, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; i < 3; i++ {
		pk, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if pk.Data[0] != byte(i) || !pk.Timestamp.Equal(ts.Add(time.Duration(i)*time.Second)) || pk.LinkType != layers.LinkTypeEthernet {
			t.Errorf("packet %d: %+v", i, pk)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("want EOF, got %v", err)
	}
}

// Hand-built pcapng: SHB, IDB with if_tsresol=9 (ns), one EPB.
func TestPcapngNanosecondResolution(t *testing.T) {
	le := binary.LittleEndian
	var b []byte
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		l := uint32(12 + len(body))
		b = le.AppendUint32(b, typ)
		b = le.AppendUint32(b, l)
		b = append(b, body...)
		b = le.AppendUint32(b, l)
	}
	shb := le.AppendUint32(nil, ngByteOrderMag)
	shb = append(shb, 1, 0, 0, 0)
	shb = append(shb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	block(ngSHB, shb)
	idb := []byte{1, 0, 0, 0} // linktype ethernet, reserved
	idb = le.AppendUint32(idb, 65535)
	idb = append(idb, 9, 0, 1, 0, 9, 0, 0, 0) // if_tsresol = 10^-9
	idb = append(idb, 0, 0, 0, 0)             // opt_endofopt
	block(ngIDB, idb)
	ts := time.Date(2024, 4, 1, 13, 45, 2, 176615123, time.UTC)
	ns := uint64(ts.UnixNano())
	epb := le.AppendUint32(nil, 0)
	epb = le.AppendUint32(epb, uint32(ns>>32))
	epb = le.AppendUint32(epb, uint32(ns))
	epb = le.AppendUint32(epb, 5)
	epb = le.AppendUint32(epb, 5)
	epb = append(epb, 'h', 'e', 'l', 'l', 'o')
	block(ngEPB, epb)

	p := filepath.Join(t.TempDir(), "x.pcapng")
	os.WriteFile(p, b, 0o600)
	r, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	pk, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(pk.Data) != "hello" || !pk.Timestamp.Equal(ts) {
		t.Errorf("got %q at %s, want hello at %s", pk.Data, pk.Timestamp, ts)
	}
}

// Writers round-trip through the readers: classic orig_len, and pcapng with
// two interfaces at different timestamp resolutions.
func TestWritersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 6, 1, 12, 0, 0, 123456789, time.UTC)

	var cb bytes.Buffer
	cw, _ := NewWriter(&cb, layers.LinkTypeEthernet)
	if err := cw.WritePacketOrig(ts, make([]byte, 64), 1514); err != nil {
		t.Fatal(err)
	}
	p1 := filepath.Join(dir, "a.pcap")
	_ = os.WriteFile(p1, cb.Bytes(), 0o600)
	r, err := Open(p1)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := r.Next()
	if err != nil || len(pk.Data) != 64 || pk.OrigLen != 1514 || !pk.Timestamp.Equal(ts) {
		t.Fatalf("classic: %+v %v", pk, err)
	}

	var nb bytes.Buffer
	nw, _ := NewNGWriter(&nb)
	us, _ := nw.AddInterface(layers.LinkTypeEthernet, 65535, 6)
	ns, _ := nw.AddInterface(layers.LinkTypeEthernet, 128, 9)
	_ = nw.WritePacket(us, ts, make([]byte, 61), 61)
	_ = nw.WritePacket(ns, ts, make([]byte, 128), 1500)
	p2 := filepath.Join(dir, "b.pcapng")
	_ = os.WriteFile(p2, nb.Bytes(), 0o600)
	r2, err := Open(p2)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := r2.Next()
	b, _ := r2.Next()
	if len(a.Data) != 61 || !a.Timestamp.Equal(ts.Truncate(time.Microsecond)) {
		t.Errorf("µs interface: len %d ts %v", len(a.Data), a.Timestamp)
	}
	if len(b.Data) != 128 || b.OrigLen != 1500 || !b.Timestamp.Equal(ts) {
		t.Errorf("ns interface: len %d orig %d ts %v", len(b.Data), b.OrigLen, b.Timestamp)
	}
}
