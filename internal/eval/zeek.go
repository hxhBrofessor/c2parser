package eval

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"c2parser/internal/engine"
)

// Zeek conn.log reading and the UID label join (v10a 1.2). The readers
// take TSV (Zeek's default, with #fields headers) or JSON lines, plain or
// gzipped, and also CSV for label files. Column names come from Columns,
// so nothing about the TQH-C2 schema is hard-coded.

// Record is one row as column → value.
type Record map[string]string

// maxLine bounds one log line (a Zeek row is far shorter).
const maxLine = 1 << 20

// ReadRecords calls fn for each data row of a Zeek TSV, JSON-lines or CSV
// stream, plain or gzipped. It stops at the first error fn returns.
func ReadRecords(r io.Reader, fn func(Record) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, 64<<10)
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	var (
		fields  []string
		sep     = "\t"
		unset   = "-"
		empty   = "(empty)"
		format  string // tsv | json | csv
		csvHead []string
		line    int
	)
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		if format == "" {
			switch {
			case b[0] == '#':
				format = "tsv"
			case b[0] == '{':
				format = "json"
			default:
				format = "csv"
			}
		}
		switch format {
		case "tsv":
			if b[0] == '#' {
				hdr := string(b[1:])
				if v, ok := strings.CutPrefix(hdr, "separator "); ok {
					v = strings.TrimSpace(v)
					if strings.HasPrefix(v, `\x`) && len(v) == 4 {
						if n, err := strconv.ParseUint(v[2:], 16, 8); err == nil {
							v = string(rune(n))
						}
					}
					if v != "" {
						sep = v
					}
					continue
				}
				k, v, _ := strings.Cut(hdr, sep)
				switch k {
				case "fields":
					fields = strings.Split(v, sep)
				case "unset_field":
					unset = v
				case "empty_field":
					empty = v
				}
				continue
			}
			if fields == nil {
				return fmt.Errorf("line %d: data before #fields", line)
			}
			vals := strings.Split(string(b), sep)
			rec := make(Record, len(fields))
			for i, f := range fields {
				if i < len(vals) && vals[i] != unset && vals[i] != empty {
					rec[f] = vals[i]
				}
			}
			if err := fn(rec); err != nil {
				return err
			}
		case "json":
			var raw map[string]any
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber()
			if err := d.Decode(&raw); err != nil {
				return fmt.Errorf("line %d: %w", line, err)
			}
			rec := make(Record, len(raw))
			for k, v := range raw {
				switch x := v.(type) {
				case string:
					rec[k] = x
				case json.Number:
					rec[k] = x.String()
				case bool:
					rec[k] = strconv.FormatBool(x)
				case nil:
				default:
					jb, _ := json.Marshal(x)
					rec[k] = string(jb)
				}
			}
			if err := fn(rec); err != nil {
				return err
			}
		case "csv":
			cr := csv.NewReader(bytes.NewReader(b))
			cr.FieldsPerRecord = -1
			vals, err := cr.Read()
			if err != nil {
				return fmt.Errorf("line %d: %w", line, err)
			}
			if csvHead == nil {
				csvHead = vals
				continue
			}
			rec := make(Record, len(csvHead))
			for i, f := range csvHead {
				if i < len(vals) && vals[i] != "" {
					rec[f] = vals[i]
				}
			}
			if err := fn(rec); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("line %d: %w", line+1, err)
	}
	return nil
}

// ZeekConn is one conn.log row.
type ZeekConn struct {
	UID      string
	TS       float64
	Proto    string
	OrigH    netip.Addr
	OrigP    uint16
	RespH    netip.Addr
	RespP    uint16
	Duration float64
	Label    string // from the conn.log's label column, if any
}

// zeekTime parses a Zeek ts: epoch seconds (TSV, JSON default) or an
// ISO 8601 string (JSON with LogAscii::json_timestamps = JSON::TS_ISO8601).
func zeekTime(s string) (float64, error) {
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, errors.New("non-finite ts")
		}
		return f, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, fmt.Errorf("ts %q", s)
	}
	return float64(t.UnixNano()) / 1e9, nil
}

// ParseConn converts a record using the column map.
func ParseConn(r Record, c Columns) (ZeekConn, error) {
	var z ZeekConn
	var err error
	z.UID = r[c.UID]
	if z.UID == "" {
		return z, errors.New("no uid")
	}
	if z.TS, err = zeekTime(r[c.TS]); err != nil {
		return z, err
	}
	if z.OrigH, err = netip.ParseAddr(r[c.OrigH]); err != nil {
		return z, fmt.Errorf("orig_h: %w", err)
	}
	if z.RespH, err = netip.ParseAddr(r[c.RespH]); err != nil {
		return z, fmt.Errorf("resp_h: %w", err)
	}
	p, err := strconv.ParseUint(r[c.OrigP], 10, 16)
	if err != nil {
		return z, fmt.Errorf("orig_p: %w", err)
	}
	z.OrigP = uint16(p)
	if p, err = strconv.ParseUint(r[c.RespP], 10, 16); err != nil {
		return z, fmt.Errorf("resp_p: %w", err)
	}
	z.RespP = uint16(p)
	z.OrigH, z.RespH = z.OrigH.Unmap(), z.RespH.Unmap()
	z.Proto = strings.ToLower(r[c.Proto])
	if d := r[c.Duration]; d != "" {
		z.Duration, _ = strconv.ParseFloat(d, 64)
	}
	z.Label = r[c.Label]
	return z, nil
}

// ReadConnLog reads every row of one conn.log file. Rows that do not
// parse (missing UID, bad address) are counted and skipped.
func ReadConnLog(path string, c Columns) (conns []ZeekConn, bad int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	err = ReadRecords(f, func(r Record) error {
		z, e := ParseConn(r, c)
		if e != nil {
			bad++
			return nil
		}
		conns = append(conns, z)
		return nil
	})
	return conns, bad, err
}

// JoinStats is the outcome of a UID join.
type JoinStats struct {
	Zeek          int     `json:"zeek_conns"`
	Matched       int     `json:"matched"`
	UnmatchedZeek int     `json:"unmatched_zeek"`
	UnmatchedC2P  int     `json:"unmatched_c2parser"`
	Ambiguous     int     `json:"ambiguous"`
	BadRows       int     `json:"bad_rows,omitempty"`
	Rate          float64 `json:"match_rate"` // matched / zeek
	Positives     int     `json:"positive_conns"`
	PosMatched    int     `json:"positive_matched"`
}

// joinTolerance is the start-time tolerance (v10a 1.2: ±1 s).
var joinTolerance = 1.0

type tupleKey struct {
	proto      string
	a, b       netip.Addr
	aPort, bPP uint16
}

func mkTuple(proto string, a netip.Addr, ap uint16, b netip.Addr, bp uint16) tupleKey {
	if b.Less(a) || a == b && bp < ap {
		a, ap, b, bp = b, bp, a, ap
	}
	return tupleKey{proto, a, b, ap, bp}
}

// Join matches Zeek connections to c2parser's: the same 5-tuple in either
// direction and a start within ±joinTolerance. A Zeek row with no
// candidate is unmatched-zeek; with several, or whose only candidate
// another row also claims, ambiguous. c2parser connections nobody
// matched are unmatched-c2parser. matched maps UID → record index.
func Join(zs []ZeekConn, cs []engine.ConnRecord) (st JoinStats, matched map[string]int) {
	idx := map[tupleKey][]int{}
	for i, c := range cs {
		a, err1 := netip.ParseAddr(c.Client)
		b, err2 := netip.ParseAddr(c.Server)
		if err1 != nil || err2 != nil {
			continue
		}
		k := mkTuple(c.Proto, a, c.ClientPort, b, c.ServerPort)
		idx[k] = append(idx[k], i)
	}
	st.Zeek = len(zs)
	claim := map[int][]int{} // record → zeek rows with it as sole candidate
	single := make([]int, len(zs))
	for zi, z := range zs {
		single[zi] = -1
		proto := z.Proto
		if proto != "tcp" && proto != "udp" {
			st.UnmatchedZeek++
			continue
		}
		var cand []int
		for _, ci := range idx[mkTuple(proto, z.OrigH, z.OrigP, z.RespH, z.RespP)] {
			if math.Abs(cs[ci].Start-z.TS) <= joinTolerance {
				cand = append(cand, ci)
			}
		}
		switch len(cand) {
		case 0:
			st.UnmatchedZeek++
		case 1:
			single[zi] = cand[0]
			claim[cand[0]] = append(claim[cand[0]], zi)
		default:
			st.Ambiguous++
		}
	}
	matched = map[string]int{}
	used := map[int]bool{}
	for zi, ci := range single {
		if ci < 0 {
			continue
		}
		if len(claim[ci]) > 1 {
			st.Ambiguous++
			continue
		}
		matched[zs[zi].UID] = ci
		used[ci] = true
		st.Matched++
	}
	st.UnmatchedC2P = len(cs) - len(used)
	if st.Zeek > 0 {
		st.Rate = float64(st.Matched) / float64(st.Zeek)
	}
	return st, matched
}

// defaultPositive are label values read as C2 when Labels.Positive is empty.
var defaultPositive = []string{"c2", "malicious", "malware", "1", "true"}

func positiveSet(vals []string) map[string]bool {
	if len(vals) == 0 {
		vals = defaultPositive
	}
	m := map[string]bool{}
	for _, v := range vals {
		m[strings.ToLower(strings.TrimSpace(v))] = true
	}
	return m
}

// zeekLabels is a capture's resolved UID join: positive endpoints and
// per-row metadata from the label file.
type zeekLabels struct {
	stats     JoinStats
	endpoints []Endpoint
	meta      map[string]map[string]int // field → value → positive rows
}

// loadZeekLabels reads the conn.log(s) and label file and joins them to
// res.Conns.
func loadZeekLabels(l *Labels, cols Columns, conns []engine.ConnRecord) (*zeekLabels, error) {
	files, err := expand(l.ConnLog)
	if err != nil {
		return nil, err
	}
	var zs []ZeekConn
	bad := 0
	for _, f := range files {
		z, b, err := ReadConnLog(f, cols)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		zs, bad = append(zs, z...), bad+b
	}
	pos := positiveSet(l.Positive)
	isPos := map[string]bool{}
	out := &zeekLabels{meta: map[string]map[string]int{}}
	note := func(field, v string) {
		if field == "" || v == "" {
			return
		}
		if out.meta[field] == nil {
			out.meta[field] = map[string]int{}
		}
		out.meta[field][v]++
	}
	if l.LabelFile != "" {
		f, err := os.Open(l.LabelFile)
		if err != nil {
			return nil, err
		}
		err = ReadRecords(f, func(r Record) error {
			uid := r[cols.UID]
			if uid == "" || !pos[strings.ToLower(strings.TrimSpace(r[cols.Label]))] {
				return nil
			}
			isPos[uid] = true
			note("framework", r[cols.Framework])
			note("transport", r[cols.Transport])
			note("sleep", r[cols.Sleep])
			note("jitter", r[cols.Jitter])
			return nil
		})
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", l.LabelFile, err)
		}
	} else {
		for _, z := range zs {
			if pos[strings.ToLower(strings.TrimSpace(z.Label))] {
				isPos[z.UID] = true
			}
		}
	}
	st, matched := Join(zs, conns)
	st.BadRows = bad
	seen := map[Endpoint]bool{}
	for _, z := range zs {
		if !isPos[z.UID] {
			continue
		}
		st.Positives++
		ci, ok := matched[z.UID]
		if !ok {
			continue
		}
		st.PosMatched++
		ep := Endpoint{Client: conns[ci].Client, Server: conns[ci].Server}
		if !seen[ep] {
			seen[ep] = true
			out.endpoints = append(out.endpoints, ep)
		}
	}
	sort.Slice(out.endpoints, func(i, j int) bool {
		a, b := out.endpoints[i], out.endpoints[j]
		return a.Client+a.Server < b.Client+b.Server
	})
	out.stats = st
	return out, nil
}

// majority returns the most common value of a metadata field.
func (z *zeekLabels) majority(field string) string {
	best, n := "", 0
	for v, c := range z.meta[field] {
		if c > n || c == n && v < best {
			best, n = v, c
		}
	}
	return best
}
