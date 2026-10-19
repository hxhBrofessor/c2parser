package synth

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Independent tiny wire reader, not a mirror of the fixture serializer.
func fixtureFields(t *testing.T, b []byte) (map[uint64]uint64, []byte) {
	t.Helper()
	vars := map[uint64]uint64{}
	var data []byte
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatal("bad tag")
		}
		b = b[n:]
		v, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatal("bad value/length")
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			vars[tag>>3] = v
		case 2:
			if tag>>3 != 6 || v > uint64(len(b)) {
				t.Fatal("bad bytes field")
			}
			data = append([]byte(nil), b[:v]...)
			b = b[v:]
		default:
			t.Fatal("unexpected wire type")
		}
	}
	return vars, data
}
func TestSliverDNSFixtureWire(t *testing.T) {
	poll, err := SliverDNSPollFixture(1, [8]byte{0, 1, 2, 3, 4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	b, err := poll.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != "0803100132080001020304050607" {
		t.Fatalf("POLL wire mismatch: %x", b)
	}
	m := SliverDNSFixture{Type: SliverDNSToImplant, ID: 0x03010203, Start: 128, Stop: 256, Size: 512, Data: []byte{0xab, 0xcd}}
	b, err = m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	vars, data := fixtureFields(t, b)
	if !reflect.DeepEqual(vars, map[uint64]uint64{1: 7, 2: 0x03010203, 3: 128, 4: 256, 5: 512}) || !bytes.Equal(data, m.Data) {
		t.Fatalf("field meanings/tags differ: %v", vars)
	}
	for _, typ := range []uint32{0, 2, 3, 4, 6, 7, 8, 9} {
		b, err := (SliverDNSFixture{Type: typ, ID: 1}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		fields, _ := fixtureFields(t, b)
		if fields[1] != uint64(typ) || fields[2] != 1 {
			t.Fatal("enum/default omission")
		}
		if typ == 0 && bytes.Contains(b, []byte{8, 0}) {
			t.Fatal("proto3 zero Type must be omitted")
		}
	}
	for _, typ := range []uint32{1, 5, 10} {
		if _, err := (SliverDNSFixture{Type: typ}).Marshal(); err == nil {
			t.Fatal("reserved/unknown type admitted")
		}
	}
}
func TestSliverDNSFixtureFragments(t *testing.T) {
	const zone = "wire.example"
	for _, n := range []int{1, 127, 128, 129, 256, 512, MaxDNSFixtureData} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*37 + 11)
		}
		parts, err := SliverDNSFragments(zone, 0x123456, 254, data)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := SliverDNSFragments(zone, 0x123456, 254, data)
		if !reflect.DeepEqual(parts, again) {
			t.Fatal("nondeterministic")
		}
		var joined []byte
		for _, m := range parts {
			if m.Start != uint32(len(joined)) || m.Stop != 0 || m.Size != uint32(n) || m.ID != 0xfe123456 || m.Type != 8 {
				t.Fatal("fragment fields", m.Start, m.Stop, m.Size, m.ID, m.Type)
			}
			joined = append(joined, m.Data...)
			name, err := SliverDNSName(zone, m)
			if err != nil {
				t.Fatal(err)
			}
			labels := strings.Split(strings.TrimSuffix(name, "."+zone+"."), ".")
			if len(name) > 254 {
				t.Fatal("oversized name")
			}
			for i, l := range labels {
				if len(l) > 63 || i < len(labels)-1 && len(l) != 63 {
					t.Fatal("label capacity")
				}
			}
			b, err := base32.NewEncoding(DNSAlphaCustom32).WithPadding(base32.NoPadding).DecodeString(strings.Join(labels, ""))
			if err != nil {
				t.Fatal(err)
			}
			vars, wireData := fixtureFields(t, b)
			if vars[1] != 8 || vars[2] != uint64(m.ID) || vars[3] != uint64(m.Start) || vars[4] != 0 || vars[5] != uint64(n) || !bytes.Equal(wireData, m.Data) {
				t.Fatal("encoded wire fields")
			}
		}
		if !bytes.Equal(joined, data) || len(parts) > 128 {
			t.Fatal("fragment reconstruction/bound")
		}
		if n == MaxDNSFixtureData && len(parts) < 2 {
			t.Fatal("fragmentation never exercised")
		}
		t.Logf("payload=%d fragments=%d max-label=63 deterministic=true", n, len(parts))
	}
}
func TestSliverDNSFixtureBounds(t *testing.T) {
	for _, zone := range []string{"", "a..example", "UPPER.example", "-x.example", strings.Repeat("a", 64) + ".example", strings.Repeat("a", 121)} {
		if _, err := SliverDNSName(zone, SliverDNSFixture{Type: 3, ID: 1}); err == nil {
			t.Errorf("invalid zone admitted: %q", zone)
		}
	}
	for _, sid := range []uint32{0, 0x1000000} {
		if _, err := SliverDNSPollFixture(sid, [8]byte{}); err == nil {
			t.Fatal("invalid session")
		}
	}
	if _, err := SliverDNSID(1, 255); err == nil {
		t.Fatal("counter outside observed modulo")
	}
	for _, n := range []int{0, MaxDNSFixtureData + 1} {
		if _, err := SliverDNSFragments("wire.example", 1, 1, make([]byte, n)); err == nil {
			t.Fatal("unbounded payload")
		}
	}
	if _, err := (SliverDNSFixture{Type: 3, Data: make([]byte, MaxDNSFixtureData+1)}).Marshal(); err == nil {
		t.Fatal("unbounded serialization")
	}
	zone := strings.Repeat("a", 60) + "." + strings.Repeat("b", 50)
	parts, err := SliverDNSFragments(zone, 1, 1, make([]byte, MaxDNSFixtureData))
	if err != nil || len(parts) > 128 {
		t.Fatal("long-zone bound", err)
	}
}
