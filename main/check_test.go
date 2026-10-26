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
