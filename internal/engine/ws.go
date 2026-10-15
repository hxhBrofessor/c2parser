package engine

import (
	"encoding/binary"
	"time"

	"c2parser/internal/stats"
)

// ------------------------------------------------------------- WebSocket
//
// After "101 Switching Protocols" + "Upgrade: websocket" the connection
// carries RFC 6455 frames. Client→server frames are masked. Messages are
// re-assembled from continuation frames and analysed like HTTP bodies
// (randomness, Havoc/Mythic framing) with their own timing series, which is
// how Mythic's websocket profile (poll mode, 10 s ± 37%) shows up.

const maxWSMessage = 4 << 20

type wsParser struct {
	buf     []byte
	msg     []byte
	msgLen  int64
	opcode  byte
	started time.Time
	frame   int64
}

func (w *wsParser) feed(e *Engine, c *tcpConn, client bool, data []byte, ts time.Time, frame int64) {
	w.buf = append(w.buf, data...)
	for {
		b := w.buf
		if len(b) < 2 {
			return
		}
		fin := b[0]&0x80 != 0
		op := b[0] & 0x0f
		masked := b[1]&0x80 != 0
		l := int64(b[1] & 0x7f)
		p := 2
		switch l {
		case 126:
			if len(b) < 4 {
				return
			}
			l, p = int64(binary.BigEndian.Uint16(b[2:])), 4
		case 127:
			if len(b) < 10 {
				return
			}
			l, p = int64(binary.BigEndian.Uint64(b[2:])), 10
		}
		if l < 0 || l > 64<<20 {
			w.buf = nil // not WebSocket after all
			return
		}
		var key [4]byte
		if masked {
			if len(b) < p+4 {
				return
			}
			copy(key[:], b[p:p+4])
			p += 4
		}
		if int64(len(b)-p) < l {
			return
		}
		payload := b[p : p+int(l)]
		if masked {
			for i := range payload {
				payload[i] ^= key[i&3]
			}
		}
		w.buf = b[p+int(l):]
		if op >= 0x8 { // control frames: close/ping/pong
			continue
		}
		if op != 0 { // first frame of a message
			w.opcode, w.msg, w.msgLen, w.started, w.frame = op, w.msg[:0], 0, ts, frame
		}
		w.msgLen += int64(len(payload))
		if len(w.msg) < maxWSMessage {
			w.msg = append(w.msg, payload...)
		}
		if fin {
			e.onWSMessage(c, client, w.msg, w.msgLen, w.started, w.frame)
			w.msg = w.msg[:0]
		}
	}
}

type wsStats struct {
	clientMsgs, serverMsgs int
	clientT, clientS       []float64
	bytesUp, bytesDown     int64
	random                 int
	mythic, havoc          int
	frames                 []int64
	push                   bool // server-push mode (Accept-Type: Push)
}

func (e *Engine) onWSMessage(c *tcpConn, client bool, msg []byte, n int64, ts time.Time, frame int64) {
	ch := e.httpChan(c, c.lastHost)
	if ch.ws == nil {
		ch.ws = &wsStats{}
	}
	w := ch.ws
	w.push = w.push || c.wsPush
	if client {
		w.clientMsgs++
		w.bytesUp += n
		if e.room(len(w.clientT)) {
			w.clientT = append(w.clientT, e.rel(ts))
			w.clientS = append(w.clientS, float64(n))
		}
	} else {
		w.serverMsgs++
		w.bytesDown += n
	}
	// Assess the message, or the longest base64 run inside it (Mythic wraps
	// its base64 message in JSON: {"client":true,"data":"…","tag":""}).
	a := stats.AssessBytes(msg)
	if a.Score < 0.8 {
		if run := longestB64(msg); len(run) >= 64 {
			if d, _ := decodeB64(string(run)); d != nil {
				if da := stats.AssessBytes(d); da.Score > a.Score {
					a = da
				}
			}
		}
	}
	if a.Score >= 0.8 && a.N >= 64 {
		w.random++
	}
	hit := false
	if mythicInText(msg) > 0 {
		w.mythic++
		hit = true
	}
	if h := containsC2Magic(msg); h > 0 {
		w.havoc += h
		hit = true
	}
	if hit && len(w.frames) < 10 {
		w.frames = append(w.frames, frame)
	}
}

func longestB64(b []byte) []byte {
	var best []byte
	for _, r := range b64Run.FindAll(b, 16) {
		if len(r) > len(best) {
			best = r
		}
	}
	return best
}

// ------------------------------------------------------- raw TCP scanner
//
// Streams that are neither HTTP, TLS, SMB nor DNS (e.g. Mythic's tcp P2P
// profile on a random port, Havoc/Sliver TCP pivots, custom implants) get a
// bounded scan for known C2 framing and a randomness profile.

const rawScanLimit = 1 << 20

type rawHalf struct {
	e       *Engine
	c       *tcpConn
	client  bool
	scanned int
	carry   []byte
}

func (h *rawHalf) gap()            { h.carry = nil }
func (h *rawHalf) close(time.Time) {}

func (h *rawHalf) feed(data []byte, _ time.Time, frame int64) {
	if h.scanned >= rawScanLimit {
		return
	}
	h.scanned += len(data)
	buf := append(h.carry, data...)
	r := h.c.ch.rawAgg()
	r.hist.Add(data)
	// count only matches that aren't wholly inside the carried-over tail
	if n := containsC2Magic(buf) - containsC2Magic(h.carry); n > 0 {
		r.havoc += n
		r.frame(frame)
	}
	if n := mythicInText(buf) - mythicInText(h.carry); n > 0 {
		r.mythic += n
		r.frame(frame)
	}
	// keep a tail so framing split across segments is still found
	if len(buf) > 256 {
		h.carry = append(h.carry[:0], buf[len(buf)-256:]...)
	} else {
		h.carry = append(h.carry[:0], buf...)
	}
}

type rawAgg struct {
	havoc, mythic int
	hist          stats.Histogram
	frames        []int64
}

func (r *rawAgg) frame(f int64) {
	if len(r.frames) < 10 {
		r.frames = append(r.frames, f)
	}
}

func (ch *channel) rawAgg() *rawAgg {
	if ch.raw == nil {
		ch.raw = &rawAgg{}
	}
	return ch.raw
}
