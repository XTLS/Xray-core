package geodata

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commongeodata "github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestUpdateRollbackRestoresMatchers(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("xray.location.asset", dir)
	encode := func(message proto.Message) []byte {
		t.Helper()
		data, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ipData := func(code string, lastByte byte) []byte {
		return encode(&commongeodata.GeoIPList{Entry: []*commongeodata.GeoIP{{
			Code: code, Cidr: []*commongeodata.CIDR{{Ip: []byte{192, 0, 2, lastByte}, Prefix: 32}},
		}}})
	}
	siteData := func(code, domain string) []byte {
		return encode(&commongeodata.GeoSiteList{Entry: []*commongeodata.GeoSite{{
			Code: code, Domain: []*commongeodata.Domain{{Type: commongeodata.Domain_Full, Value: domain}},
		}}})
	}
	oldIP, oldSite := ipData("TEST", 1), siteData("TEST", "before.example")
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ip.dat", oldIP)
	write("site.dat", oldSite)
	ipRules, err := commongeodata.ParseIPRules([]string{"ext:ip.dat:TEST"})
	if err != nil {
		t.Fatal(err)
	}
	ipMatcher, err := commongeodata.IPReg.BuildIPMatcher(ipRules)
	if err != nil {
		t.Fatal(err)
	}
	domainRules, err := commongeodata.ParseDomainRules([]string{"ext:site.dat:TEST"}, commongeodata.Domain_Full)
	if err != nil {
		t.Fatal(err)
	}
	domainMatcher, err := commongeodata.DomainReg.BuildDomainMatcher(domainRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, ipCode, siteCode                      string
		wantError, ipUpdated, siteUpdated, reversed bool
	}{
		{"missing GeoSite category", "TEST", "OTHER", true, true, false, false},
		{"missing GeoIP category", "OTHER", "TEST", true, false, true, false},
		{"both categories missing", "OTHER", "OTHER", true, false, false, false},
		{"successful update", "TEST", "TEST", false, true, true, false},
		{"missing GeoSite category reversed", "TEST", "OTHER", true, true, false, true},
		{"missing GeoIP category reversed", "OTHER", "TEST", true, false, true, true},
		{"both categories missing reversed", "OTHER", "OTHER", true, false, false, true},
		{"successful update reversed", "TEST", "TEST", false, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write("ip.dat", oldIP)
			write("site.dat", oldSite)
			if err := reload(); err != nil {
				t.Fatal(err)
			}
			newIP, newSite := ipData(tc.ipCode, 2), siteData(tc.siteCode, "after.example")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ip" {
					_, _ = w.Write(newIP)
				} else {
					_, _ = w.Write(newSite)
				}
			}))
			defer server.Close()
			assets := []*Asset{{Url: server.URL + "/ip", File: "ip.dat"}, {Url: server.URL + "/site", File: "site.dat"}}
			if tc.reversed {
				assets[0], assets[1] = assets[1], assets[0]
			}
			instance := &Instance{
				assets:     assets,
				downloader: &downloader{ctx: context.Background(), httpsClient: server.Client()},
			}
			err := instance.reloadWithUpdate()
			if (err != nil) != tc.wantError {
				t.Fatalf("update error = %v, want error: %t", err, tc.wantError)
			}
			if tc.wantError && !strings.Contains(err.Error(), "TEST") {
				t.Errorf("original missing-category error was lost: %v", err)
			}
			for name, expected := range map[string][]byte{"ip.dat": oldIP, "site.dat": oldSite} {
				if name == "ip.dat" && tc.ipUpdated {
					expected = append([]byte(luaGuardHeader), newIP...)
				} else if name == "site.dat" && tc.siteUpdated {
					expected = append([]byte(luaGuardHeader), newSite...)
				}
				actual, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Errorf("%s does not contain the expected asset after update: %v", name, err)
				}
			}
			if ipMatcher.Match(net.ParseIP("192.0.2.1")) == tc.ipUpdated || ipMatcher.Match(net.ParseIP("192.0.2.2")) != tc.ipUpdated {
				t.Error("live IP matcher differs from the assets left on disk")
			}
			if domainMatcher.MatchAny("before.example") == tc.siteUpdated || domainMatcher.MatchAny("after.example") != tc.siteUpdated {
				t.Error("live domain matcher differs from the assets left on disk")
			}
		})
	}
}
