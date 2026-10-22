package engine

import "testing"

// Q-07 / CAND2: request carrier tokens are unescaped per location.
// Query values are already url.ParseQuery-decoded, so they must not be
// unescaped again (a second pass turns a base64 '+' into a space). Path,
// cookie and custom-header values are url.PathUnescape-decoded (%XX decoded,
// literal '+' kept); a bad escape leaves the value untouched.
func TestQ07UnescapeRequestToken(t *testing.T) {
	cases := []struct{ loc, in, want string }{
		{"query", "aa+bb//cc", "aa+bb//cc"},        // raw: no second unescape
		{"query:d", "aa+bb//cc", "aa+bb//cc"},      // raw
		{"query:d", "aa bb", "aa bb"},              // ParseQuery already mapped '+'→space; left as-is
		{"cookie:sid", "aa%2Bbb%2Fcc", "aa+bb/cc"}, // PathUnescape decodes %XX
		{"cookie:sid", "aa+bb/cc", "aa+bb/cc"},     // literal '+' kept (QueryUnescape would corrupt)
		{"header:x-session-data", "aa%2Bbb", "aa+bb"},
		{"header:x-session-data", "aa+bb", "aa+bb"},
		{"path", "aa%2Bbb%2Fcc", "aa+bb/cc"},
		{"path", "aa+bb", "aa+bb"},
		{"path", "bad%ZZescape", "bad%ZZescape"}, // bad escape: raw value kept
		{"cookie:sid", "pct%2", "pct%2"},         // truncated escape: raw
	}
	for _, c := range cases {
		if got := unescapeRequestToken(c.loc, c.in); got != c.want {
			t.Errorf("unescapeRequestToken(%q, %q) = %q, want %q", c.loc, c.in, got, c.want)
		}
	}
}
