package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	. "github.com/xtls/xray-core/infra/conf"
)

func TestPortListUnmarshalBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		want    []PortRange
		wantErr bool
	}{
		{"number upper boundary", `65535`, []PortRange{{From: 65535, To: 65535}}, false},
		{"string upper boundary", `"65535"`, []PortRange{{From: 65535, To: 65535}}, false},
		{"number above boundary", `65536`, nil, true},
		{"number that would wrap to one", `65537`, nil, true},
		{"number uint32 maximum", `4294967295`, nil, true},
		{"string above boundary", `"65536"`, nil, true},
		{"number above uint32", `4294967296`, nil, true},
		{"negative number", `-1`, nil, true},
		{"fractional number", `1.5`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var list PortList
			err := json.Unmarshal([]byte(tc.input), &list)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("json.Unmarshal(%s) accepted an invalid port: %+v", tc.input, list.Range)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, list.Range); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortListUnmarshalPreservesAcceptedForms(t *testing.T) {
	t.Setenv("XRAY_TEST_PORT_LIST", "443")
	for _, tc := range []struct {
		name  string
		input string
		want  []PortRange
	}{
		{"number zero", `0`, nil},
		{"null", `null`, nil},
		{"empty string", `""`, nil},
		{"string zero", `"0"`, []PortRange{{From: 0, To: 0}}},
		{"number one", `1`, []PortRange{{From: 1, To: 1}}},
		{"list and range", `" 80, 443-445 "`, []PortRange{{From: 80, To: 80}, {From: 443, To: 445}}},
		{"environment", `"env:XRAY_TEST_PORT_LIST"`, []PortRange{{From: 443, To: 443}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var list PortList
			if err := json.Unmarshal([]byte(tc.input), &list); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, list.Range); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortListInvalidNumberPreservesExistingRanges(t *testing.T) {
	want := []PortRange{{From: 80, To: 80}}
	list := PortList{Range: append([]PortRange(nil), want...)}
	if err := json.Unmarshal([]byte(`65536`), &list); err == nil {
		t.Fatal("expected an invalid port error")
	}
	if diff := cmp.Diff(want, list.Range); diff != "" {
		t.Fatal(diff)
	}
}
