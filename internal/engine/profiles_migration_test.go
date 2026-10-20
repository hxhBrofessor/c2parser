package engine

import (
	"testing"

	"c2parser/data"
)

func TestCovenantMigrationRefusesNonConsumableProfile(t *testing.T) {
	p, err := data.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := covenantHTTPItems(p); err != nil {
		t.Fatalf("approved legacy profile rejected: %v", err)
	}
	p.Frameworks[0].FieldGroups["http"] = func() data.FieldGroup {
		g := p.Frameworks[0].FieldGroups["http"]
		g.Verify = true
		return g
	}()
	if _, err := covenantHTTPItems(p); err == nil {
		t.Fatal("verify:true Covenant rows were accepted for runtime scoring")
	}
}

func TestCovenantMigratedPredicatesRetainExactMatching(t *testing.T) {
	e := New(Config{})
	positiveReq := &httpMsg{req: true, method: "GET", uri: "/en-us/index.html?x=1", hdr: map[string]string{
		"user-agent": covenantUA, "cookie": "SESSIONID=1552332971750-extra",
	}, frame: 11}
	positiveResp := &httpMsg{req: false, hdr: map[string]string{"server": "Microsoft-IIS/7.5"}, head: []byte("x<title>Hello World!</title>y"), frame: 12}
	ch := &httpChannel{}
	e.matchFrameworkDefaults(ch, positiveReq)
	e.matchFrameworkDefaults(ch, positiveResp)
	got := ch.fw["Covenant"]
	if got == nil || len(got.feats) != 5 {
		t.Fatalf("expected URI, UA, cookie and response feature matches, got %#v", got)
	}
	for _, feature := range []string{"URI /en-us/index.html", "Chrome/41.0.2228.0 User-Agent", "Cookie SESSIONID=1552332971750", "Server: Microsoft-IIS/7.5", "Hello World! response template"} {
		if _, ok := got.feats[feature]; !ok {
			t.Errorf("missing exact Covenant feature %q", feature)
		}
	}

	negative := []struct {
		name string
		msg  *httpMsg
	}{
		{"path case", &httpMsg{req: true, uri: "/EN-us/index.html", hdr: map[string]string{}, frame: 1}},
		{"user-agent case", &httpMsg{req: true, hdr: map[string]string{"user-agent": "mozilla/5.0"}, frame: 2}},
		{"cookie case", &httpMsg{req: true, hdr: map[string]string{"cookie": "sessionid=1552332971750"}, frame: 3}},
		{"body prefix", &httpMsg{req: true, head: []byte("x=i=a19ea23062db990386a3a478cb89d52e&data="), hdr: map[string]string{}, frame: 4}},
		{"server case", &httpMsg{hdr: map[string]string{"server": "microsoft-iis/7.5"}, frame: 5}},
		{"response case", &httpMsg{head: []byte("<TITLE>Hello World!</TITLE>"), hdr: map[string]string{}, frame: 6}},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			separate := &httpChannel{}
			e.matchFrameworkDefaults(separate, tc.msg)
			if separate.fw["Covenant"] != nil {
				t.Fatalf("unexpected case-normalized match: %#v", separate.fw["Covenant"])
			}
		})
	}
}
