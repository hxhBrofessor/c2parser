package perturb

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// FuzzTransforms: arbitrary frames never panic the frame parser or the
// rewriting transforms.
func FuzzTransforms(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0, 0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0, 80, 0x1f, 0x90})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x81, 0, 0, 100, 8, 0, 0x4f})
	f.Fuzz(func(t *testing.T, d []byte) {
		t0 := time.Unix(1700000000, 0)
		var pk []Packet
		for i := 0; i < 3; i++ {
			pk = append(pk, Packet{Data: append([]byte(nil), d...), Timestamp: t0.Add(time.Duration(i) * time.Second), LinkType: layers.LinkTypeEthernet, OrigLen: len(d) + i})
		}
		a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
		_, _, _ = Readdress(pk, AddrMap{IP: map[netip.Addr]netip.Addr{a: b}, Port: map[uint16]uint16{80: 81}})
		_, _, _ = OneWay(pk, "c2s")
		_, _ = Conflict(pk, 1, true, 1)
		_, _, _ = Clone(pk, a, []netip.Addr{b}, time.Second)
		_, _, _ = Redirect(pk, b, []netip.Addr{a}, "random", 1)
		_, _, _ = RetimeTo(pk, Channel{Client: a, Server: b}, []time.Time{t0, t0, t0})
		for _, k := range []string{"vlan", "gre", "vxlan"} {
			_, _, _ = Wrap(pk, k)
		}
	})
}
