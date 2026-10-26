package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadIPList(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ips.txt")
	data := "10.10.10.10\n\n  10.10.10.11  \r\n# comment\n2001:db8::1\n"
	if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readIPList(file)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.10.10.10", "10.10.10.11", "2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readIPList = %v, want %v", got, want)
	}

	empty := filepath.Join(t.TempDir(), "empty.txt")
	os.WriteFile(empty, []byte("\n# only comment\n"), 0o600)
	if _, err := readIPList(empty); err == nil {
		t.Error("expected error for empty list")
	}
}

func outboundFromJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := decodeJSONNumber([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAddressPath(t *testing.T) {
	cases := map[string]string{
		`{"settings":{"vnext":[{"address":"a.example","port":443}]}}`: "settings.vnext.0.address",
		`{"settings":{"servers":[{"address":"a.example"}]}}`:          "settings.servers.0.address",
		`{"settings":{"address":"a.example","port":443}}`:             "settings.address",
		`{"protocol":"freedom"}`:                                      "settings.address",
	}
	for in, want := range cases {
		if got := addressPath(outboundFromJSON(t, in)); got != want {
			t.Errorf("addressPath(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestSetAddressKeepsServerName(t *testing.T) {
	ob := outboundFromJSON(t, `{"tag":"cf_22","settings":{"vnext":[{"address":"1.1.1.1","port":443}]},
		"streamSettings":{"tlsSettings":{"serverName":"www.example.com"}}}`)
	path := addressPath(ob)
	ob, err := setPath(ob, strings.Split(path, "."), "10.10.10.10")
	if err != nil {
		t.Fatal(err)
	}
	m := ob.(map[string]any)
	addr := m["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"]
	if addr != "10.10.10.10" {
		t.Errorf("address = %v", addr)
	}
	sni := m["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["serverName"]
	if sni != "www.example.com" {
		t.Errorf("serverName changed: %v", sni)
	}
}

func resetCheckConfigFlags() {
	configFiles = nil
	configDir = ""
}

func TestCheckConfigFiles(t *testing.T) {
	defer resetCheckConfigFlags()

	// split config: all files in name order
	dir := t.TempDir()
	for _, n := range []string{"03_routing.json", "00_log.json", "06_outbounds.json", "notes.txt"} {
		os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600)
	}
	resetCheckConfigFlags()
	configDir = dir
	got, err := checkConfigFiles()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "00_log.json"),
		filepath.Join(dir, "03_routing.json"),
		filepath.Join(dir, "06_outbounds.json"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("split: %v, want %v", got, want)
	}

	// single file in dir
	one := t.TempDir()
	os.WriteFile(filepath.Join(one, "config.json"), []byte("{}"), 0o600)
	resetCheckConfigFlags()
	configDir = one
	if got, err := checkConfigFiles(); err != nil || len(got) != 1 {
		t.Errorf("single: %v, %v", got, err)
	}

	// -c file without -confdir does not use the default dir
	resetCheckConfigFlags()
	configFiles.Set(filepath.Join(one, "config.json"))
	if got, err := checkConfigFiles(); err != nil || len(got) != 1 || configDir != "" {
		t.Errorf("-c: %v, %v, dir %q", got, err, configDir)
	}

	// empty and missing dirs are errors, never stdin
	resetCheckConfigFlags()
	configDir = t.TempDir()
	if _, err := checkConfigFiles(); err == nil {
		t.Error("expected error for empty dir")
	}
	resetCheckConfigFlags()
	configDir = filepath.Join(dir, "missing")
	if _, err := checkConfigFiles(); err == nil {
		t.Error("expected error for missing dir")
	}
}

func TestKeepOutbounds(t *testing.T) {
	var doc1, doc2 map[string]any
	decodeJSONNumber([]byte(`{"outbounds":[
		{"tag":"direct","protocol":"freedom"},
		{"tag":"cf_22","streamSettings":{"sockopt":{"dialerProxy":"chain1-fragment"}}},
		{"tag":"cf_23","streamSettings":{"sockopt":{"dialerProxy":"chain2-fragment"}}}
	]}`), &doc1)
	decodeJSONNumber([]byte(`{"log":{},"outbounds":[
		{"tag":"chain1-fragment","streamSettings":{"sockopt":{"dialerProxy":"direct"}}},
		{"tag":"chain2-fragment"},
		{"tag":"block"}
	]}`), &doc2)
	docs := []map[string]any{doc1, doc2}
	kept, err := keepOutbounds(docs, "cf_22")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"direct", "cf_22", "chain1-fragment"}; !reflect.DeepEqual(kept, want) {
		t.Errorf("kept %v, want %v", kept, want)
	}
	if n := len(doc2["outbounds"].([]any)); n != 1 {
		t.Errorf("doc2 has %d outbounds, want 1", n)
	}

	var doc3 map[string]any
	decodeJSONNumber([]byte(`{"outbounds":[{"tag":"f_1","proxySettings":{"tag":"nope"}}]}`), &doc3)
	if _, err := keepOutbounds([]map[string]any{doc3}, "f_1"); err == nil {
		t.Error("expected error for missing proxySettings outbound")
	}
}
