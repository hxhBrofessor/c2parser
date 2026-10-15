// Package pcapio is a small, dependency-free reader for classic pcap and
// pcapng capture files, plus a classic pcap writer used by tests.
//
// It replaces gopacket/pcap (which needs libpcap via cgo) so the tool
// cross-compiles to any GOOS/GOARCH with no system libraries.
package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/google/gopacket/layers"
)

// Packet is one captured frame.
type Packet struct {
	Data      []byte
	Timestamp time.Time
	LinkType  layers.LinkType
	OrigLen   int
}

// Reader yields packets in file order. Next returns io.EOF at the end.
type Reader interface {
	Next() (Packet, error)
	Close() error
}

const (
	maxBlock       = 256 << 20 // refuse absurd block sizes (corrupt file)
	magicMicro     = 0xa1b2c3d4
	magicNano      = 0xa1b23c4d
	ngSHB          = 0x0A0D0D0A
	ngIDB          = 0x00000001
	ngPB           = 0x00000002 // obsolete packet block
	ngSPB          = 0x00000003
	ngEPB          = 0x00000006
	ngByteOrderMag = 0x1A2B3C4D
)

// Open detects the file format from its magic number.
func Open(path string) (Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	head, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: too short to be a capture: %w", path, err)
	}
	le := binary.LittleEndian.Uint32(head)
	be := binary.BigEndian.Uint32(head)
	switch {
	case le == ngSHB:
		r := &ngReader{f: f, r: br, ifaces: nil}
		return r, nil
	case le == magicMicro || le == magicNano || be == magicMicro || be == magicNano:
		r, err := newClassic(f, br)
		if err != nil {
			f.Close()
			return nil, err
		}
		return r, nil
	default:
		f.Close()
		return nil, fmt.Errorf("%s: unrecognised capture format (magic %08x)", path, be)
	}
}

// ---------------------------------------------------------------- classic

type classicReader struct {
	f     *os.File
	r     *bufio.Reader
	bo    binary.ByteOrder
	nano  bool
	link  layers.LinkType
	hdr   [16]byte
	frame int
}

func newClassic(f *os.File, r *bufio.Reader) (*classicReader, error) {
	var h [24]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	c := &classicReader{f: f, r: r}
	switch {
	case binary.LittleEndian.Uint32(h[:]) == magicMicro:
		c.bo = binary.LittleEndian
	case binary.LittleEndian.Uint32(h[:]) == magicNano:
		c.bo, c.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(h[:]) == magicMicro:
		c.bo = binary.BigEndian
	default:
		c.bo, c.nano = binary.BigEndian, true
	}
	c.link = layers.LinkType(c.bo.Uint32(h[20:]) & 0x0fffffff)
	return c, nil
}

func (c *classicReader) Next() (Packet, error) {
	if _, err := io.ReadFull(c.r, c.hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Packet{}, io.EOF // truncated trailing record
		}
		return Packet{}, err
	}
	sec := int64(c.bo.Uint32(c.hdr[0:]))
	frac := int64(c.bo.Uint32(c.hdr[4:]))
	incl := c.bo.Uint32(c.hdr[8:])
	orig := c.bo.Uint32(c.hdr[12:])
	if incl > maxBlock {
		return Packet{}, fmt.Errorf("pcap record length %d is implausible (corrupt file?)", incl)
	}
	data := make([]byte, incl)
	if _, err := io.ReadFull(c.r, data); err != nil {
		return Packet{}, io.EOF
	}
	if !c.nano {
		frac *= 1000
	}
	return Packet{Data: data, Timestamp: time.Unix(sec, frac).UTC(), LinkType: c.link, OrigLen: int(orig)}, nil
}

func (c *classicReader) Close() error { return c.f.Close() }

// ----------------------------------------------------------------- pcapng

type ngIface struct {
	link layers.LinkType
	// timestamp units per second
	tsPerSec float64
	snap     uint32
}

type ngReader struct {
	f      *os.File
	r      *bufio.Reader
	bo     binary.ByteOrder
	ifaces []ngIface
}

func (n *ngReader) Close() error { return n.f.Close() }

func (n *ngReader) Next() (Packet, error) {
	for {
		var hb [8]byte
		if _, err := io.ReadFull(n.r, hb[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return Packet{}, io.EOF
			}
			return Packet{}, err
		}
		// The section header's type is palindromic, so it can be recognised
		// before we know the byte order.
		if binary.LittleEndian.Uint32(hb[:]) == ngSHB {
			if err := n.readSHB(hb); err != nil {
				return Packet{}, err
			}
			continue
		}
		if n.bo == nil {
			return Packet{}, errors.New("pcapng: block before section header")
		}
		typ := n.bo.Uint32(hb[0:])
		total := n.bo.Uint32(hb[4:])
		if total < 12 || total > maxBlock || total%4 != 0 {
			return Packet{}, fmt.Errorf("pcapng: bad block length %d", total)
		}
		body := make([]byte, total-12)
		if _, err := io.ReadFull(n.r, body); err != nil {
			return Packet{}, io.EOF
		}
		var trailer [4]byte
		if _, err := io.ReadFull(n.r, trailer[:]); err != nil {
			return Packet{}, io.EOF
		}
		switch typ {
		case ngIDB:
			n.readIDB(body)
		case ngEPB:
			return n.epb(body)
		case ngSPB:
			return n.spb(body)
		case ngPB:
			return n.pb(body)
		}
	}
}

func (n *ngReader) readSHB(hb [8]byte) error {
	var bom [4]byte
	if _, err := io.ReadFull(n.r, bom[:]); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(bom[:]) == ngByteOrderMag {
		n.bo = binary.LittleEndian
	} else if binary.BigEndian.Uint32(bom[:]) == ngByteOrderMag {
		n.bo = binary.BigEndian
	} else {
		return errors.New("pcapng: bad byte-order magic")
	}
	total := n.bo.Uint32(hb[4:])
	if total < 16 || total > maxBlock {
		return fmt.Errorf("pcapng: bad section header length %d", total)
	}
	if _, err := n.r.Discard(int(total) - 12); err != nil {
		return err
	}
	n.ifaces = n.ifaces[:0] // interface IDs are per section
	return nil
}

func (n *ngReader) readIDB(b []byte) {
	if len(b) < 8 {
		return
	}
	ifc := ngIface{link: layers.LinkType(n.bo.Uint16(b[0:])), snap: n.bo.Uint32(b[4:]), tsPerSec: 1e6}
	opts := b[8:]
	for len(opts) >= 4 {
		code := n.bo.Uint16(opts[0:])
		l := int(n.bo.Uint16(opts[2:]))
		if code == 0 || 4+l > len(opts) {
			break
		}
		if code == 9 && l >= 1 { // if_tsresol
			v := opts[4]
			if v&0x80 == 0 {
				ifc.tsPerSec = math.Pow10(int(v))
			} else {
				ifc.tsPerSec = math.Pow(2, float64(v&0x7f))
			}
		}
		pad := (4 - l%4) % 4
		opts = opts[4+l+pad:]
	}
	n.ifaces = append(n.ifaces, ifc)
}

func (n *ngReader) iface(id uint32) ngIface {
	if int(id) < len(n.ifaces) {
		return n.ifaces[id]
	}
	return ngIface{link: layers.LinkTypeEthernet, tsPerSec: 1e6}
}

func (n *ngReader) ts(ifc ngIface, hi, lo uint32) time.Time {
	raw := uint64(hi)<<32 | uint64(lo)
	secs := raw / uint64(ifc.tsPerSec)
	rem := raw % uint64(ifc.tsPerSec)
	ns := int64(float64(rem) * 1e9 / ifc.tsPerSec)
	return time.Unix(int64(secs), ns).UTC()
}

func (n *ngReader) epb(b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, errors.New("pcapng: short enhanced packet block")
	}
	ifc := n.iface(n.bo.Uint32(b[0:]))
	capLen := n.bo.Uint32(b[12:])
	orig := n.bo.Uint32(b[16:])
	if int(capLen) > len(b)-20 {
		capLen = uint32(len(b) - 20)
	}
	return Packet{Data: b[20 : 20+capLen], Timestamp: n.ts(ifc, n.bo.Uint32(b[4:]), n.bo.Uint32(b[8:])), LinkType: ifc.link, OrigLen: int(orig)}, nil
}

func (n *ngReader) spb(b []byte) (Packet, error) {
	if len(b) < 4 {
		return Packet{}, errors.New("pcapng: short simple packet block")
	}
	ifc := n.iface(0)
	orig := n.bo.Uint32(b[0:])
	capLen := uint32(len(b) - 4)
	if orig < capLen {
		capLen = orig
	}
	if ifc.snap > 0 && capLen > ifc.snap {
		capLen = ifc.snap
	}
	// SPBs carry no timestamp.
	return Packet{Data: b[4 : 4+capLen], LinkType: ifc.link, OrigLen: int(orig)}, nil
}

func (n *ngReader) pb(b []byte) (Packet, error) {
	if len(b) < 20 {
		return Packet{}, errors.New("pcapng: short packet block")
	}
	ifc := n.iface(uint32(n.bo.Uint16(b[0:])))
	capLen := n.bo.Uint32(b[12:])
	if int(capLen) > len(b)-20 {
		capLen = uint32(len(b) - 20)
	}
	return Packet{Data: b[20 : 20+capLen], Timestamp: n.ts(ifc, n.bo.Uint32(b[4:]), n.bo.Uint32(b[8:])), LinkType: ifc.link, OrigLen: int(n.bo.Uint32(b[16:]))}, nil
}

// ----------------------------------------------------------------- writer

// Writer writes a classic little-endian, nanosecond pcap. Used by tests and
// fixture generators.
type Writer struct {
	w io.Writer
}

// NewWriter writes the global header.
func NewWriter(w io.Writer, link layers.LinkType) (*Writer, error) {
	var h [24]byte
	binary.LittleEndian.PutUint32(h[0:], magicNano)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 262144)
	binary.LittleEndian.PutUint32(h[20:], uint32(link))
	if _, err := w.Write(h[:]); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

// WritePacket appends one record (orig_len = captured length).
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	return w.WritePacketOrig(ts, data, len(data))
}

// WritePacketOrig appends one record whose wire length was origLen (snaplen
// fixtures: data is the truncated capture, origLen the real packet size).
func (w *Writer) WritePacketOrig(ts time.Time, data []byte, origLen int) error {
	if origLen < len(data) {
		origLen = len(data)
	}
	var h [16]byte
	binary.LittleEndian.PutUint32(h[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(h[4:], uint32(ts.Nanosecond()))
	binary.LittleEndian.PutUint32(h[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(h[12:], uint32(origLen))
	if _, err := w.w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}

// NGWriter writes little-endian pcapng: one section, any number of
// interfaces with their own link type and timestamp resolution, and
// Enhanced Packet Blocks. Used by the synthetic corpus generator.
type NGWriter struct {
	w      io.Writer
	ifaces []uint32 // ticks per second per interface
}

// NewNGWriter writes the Section Header Block.
func NewNGWriter(w io.Writer) (*NGWriter, error) {
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b[0:], 0x0A0D0D0A)
	binary.LittleEndian.PutUint32(b[4:], 28)
	binary.LittleEndian.PutUint32(b[8:], 0x1A2B3C4D)
	binary.LittleEndian.PutUint16(b[12:], 1)
	binary.LittleEndian.PutUint16(b[14:], 0)
	binary.LittleEndian.PutUint64(b[16:], ^uint64(0)) // section length unknown
	binary.LittleEndian.PutUint32(b[24:], 28)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	return &NGWriter{w: w}, nil
}

// AddInterface writes an Interface Description Block and returns its id.
// tsresolPow10 is the if_tsresol exponent (6 = µs, 9 = ns).
func (n *NGWriter) AddInterface(link layers.LinkType, snaplen uint32, tsresolPow10 uint8) (uint32, error) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], 1)
	binary.LittleEndian.PutUint32(b[4:], 32)
	binary.LittleEndian.PutUint16(b[8:], uint16(link))
	binary.LittleEndian.PutUint32(b[12:], snaplen)
	binary.LittleEndian.PutUint16(b[16:], 9) // if_tsresol
	binary.LittleEndian.PutUint16(b[18:], 1)
	b[20] = tsresolPow10
	// b[24:28] = opt_endofopt (zero)
	binary.LittleEndian.PutUint32(b[28:], 32)
	if _, err := n.w.Write(b); err != nil {
		return 0, err
	}
	tps := uint32(1)
	for i := uint8(0); i < tsresolPow10; i++ {
		tps *= 10
	}
	n.ifaces = append(n.ifaces, tps)
	return uint32(len(n.ifaces) - 1), nil
}

// WritePacket writes an Enhanced Packet Block on interface id.
func (n *NGWriter) WritePacket(id uint32, ts time.Time, data []byte, origLen int) error {
	if int(id) >= len(n.ifaces) {
		return fmt.Errorf("pcapng: no interface %d", id)
	}
	if origLen < len(data) {
		origLen = len(data)
	}
	tps := uint64(n.ifaces[id])
	raw := uint64(ts.Unix())*tps + uint64(ts.Nanosecond())*tps/1e9
	pad := (4 - len(data)%4) % 4
	total := 32 + len(data) + pad
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], 6)
	binary.LittleEndian.PutUint32(b[4:], uint32(total))
	binary.LittleEndian.PutUint32(b[8:], id)
	binary.LittleEndian.PutUint32(b[12:], uint32(raw>>32))
	binary.LittleEndian.PutUint32(b[16:], uint32(raw))
	binary.LittleEndian.PutUint32(b[20:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[24:], uint32(origLen))
	copy(b[28:], data)
	binary.LittleEndian.PutUint32(b[total-4:], uint32(total))
	_, err := n.w.Write(b)
	return err
}
