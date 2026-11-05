package api

import (
	"errors"
	"strings"
	"testing"

	observatoryService "github.com/xtls/xray-core/app/observatory/command"
)

func files(m map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if s, ok := m[name]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("no such file")
	}
}

func TestBuildProbeRequestByTag(t *testing.T) {
	req, err := buildProbeRequest([]string{"cf_22"}, "", "https://example.com/generate_204", "get", 5, 2000, 100, files(nil))
	if err != nil {
		t.Fatal(err)
	}
	if req.Tag != "cf_22" || req.Outbound != nil || req.Method != "GET" || req.Samples != 5 ||
		req.TimeoutMs != 2000 || req.IntervalMs != 100 || req.Destination != "https://example.com/generate_204" {
		t.Fatalf("unexpected request %v", req)
	}
}

func TestBuildProbeRequestFromFile(t *testing.T) {
	fs := files(map[string]string{
		"list.json":   `{"outbounds":[{"tag":"t","protocol":"freedom","settings":{}}]}`,
		"single.json": "// a comment\n{\"tag\":\"t\",\"protocol\":\"freedom\",\"settings\":{}} // tail",
		"two.json":    `{"outbounds":[{"tag":"a","protocol":"freedom"},{"tag":"b","protocol":"freedom"}]}`,
		"empty.json":  `{"outbounds":[]}`,
		"bad.json":    `{"tag":"t","protocol":"no-such-protocol"}`,
		"broken.json": `{"tag":`,
	})
	for _, name := range []string{"list.json", "single.json"} {
		req, err := buildProbeRequest(nil, name, "", "", 0, 0, 0, fs)
		if err != nil {
			t.Fatalf("%s: %s", name, err)
		}
		if req.Tag != "" || req.Outbound == nil || req.Outbound.Tag != "t" || req.Outbound.ProxySettings == nil {
			t.Fatalf("%s: unexpected request %v", name, req)
		}
	}
	for _, name := range []string{"two.json", "empty.json", "bad.json", "broken.json", "missing.json"} {
		if _, err := buildProbeRequest(nil, name, "", "", 0, 0, 0, fs); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestBuildProbeRequestArgs(t *testing.T) {
	fs := files(map[string]string{"x.json": `{"protocol":"freedom"}`})
	cases := map[string]func() error{
		"nothing":   func() error { _, err := buildProbeRequest(nil, "", "", "", 0, 0, 0, fs); return err },
		"both":      func() error { _, err := buildProbeRequest([]string{"a"}, "x.json", "", "", 0, 0, 0, fs); return err },
		"two tags":  func() error { _, err := buildProbeRequest([]string{"a", "b"}, "", "", "", 0, 0, 0, fs); return err },
		"ftp":       func() error { _, err := buildProbeRequest([]string{"a"}, "", "ftp://x/", "", 0, 0, 0, fs); return err },
		"method":    func() error { _, err := buildProbeRequest([]string{"a"}, "", "", "POST", 0, 0, 0, fs); return err },
		"samples":   func() error { _, err := buildProbeRequest([]string{"a"}, "", "", "", 11, 0, 0, fs); return err },
		"timeout":   func() error { _, err := buildProbeRequest([]string{"a"}, "", "", "", 0, 30001, 0, fs); return err },
		"interval":  func() error { _, err := buildProbeRequest([]string{"a"}, "", "", "", 0, 0, 5001, fs); return err },
		"empty tag": func() error { _, err := buildProbeRequest([]string{""}, "", "", "", 0, 0, 0, fs); return err },
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestProbeJSONFormat(t *testing.T) {
	got, err := probeJSON(&observatoryService.ProbeOutboundResponse{
		Tag:         "cf_22",
		Destination: "https://example.com/generate_204",
		Method:      "HEAD",
		Samples: []*observatoryService.ProbeSample{
			{Ok: true, RttMs: 123, HttpStatus: 204},
			{Ok: true, RttMs: 0, HttpStatus: 204},
			{Ok: false, Error: "timeout"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"tag":"cf_22","destination":"https://example.com/generate_204","method":"HEAD","samples":[` +
		`{"ok":true,"rttMs":123,"httpStatus":204},{"ok":true,"rttMs":0,"httpStatus":204},{"ok":false,"error":"timeout"}]}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}

	got, _ = probeJSON(&observatoryService.ProbeOutboundResponse{Method: "HEAD", Warnings: []string{"w"}})
	want = `{"tag":"","destination":"","method":"HEAD","samples":[],"warnings":["w"]}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestProbeText(t *testing.T) {
	text := probeText(&observatoryService.ProbeOutboundResponse{
		Method: "HEAD", Destination: "https://example.com/",
		Samples: []*observatoryService.ProbeSample{{Ok: true, RttMs: 640, HttpStatus: 204}, {Error: "refused"}},
	})
	for _, s := range []string{"(new outbound)", "640 ms", "HTTP 204", "refused", "1 of 2 answered"} {
		if !strings.Contains(text, s) {
			t.Errorf("no %q in\n%s", s, text)
		}
	}
}

func TestProbeCallTimeout(t *testing.T) {
	if d := probeCallTimeout(&observatoryService.ProbeOutboundRequest{Samples: 1, TimeoutMs: 1000}); d.Seconds() < 11 || d.Seconds() > 12 {
		t.Errorf("timeout %s", d)
	}
	if d := probeCallTimeout(&observatoryService.ProbeOutboundRequest{Samples: 10}); d.Seconds() != 130 {
		t.Errorf("timeout %s, want the 130s cap", d)
	}
}
