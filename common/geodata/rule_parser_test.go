package geodata_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
)

func TestParseIPRules(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		rules := []string{
			"192.168.0.0/24",
			"192.168.0.1",
			"fe80::/64",
			"fe80::",
		}

		_, err := geodata.ParseIPRules(rules)
		if err != nil {
			t.Fatalf("Failed to parse ip rules, got %s", err)
		}
	})

	t.Run("geoip", func(t *testing.T) {
		if _, err := os.Stat(filepath.Join("..", "..", "resources", "geoip.dat")); err != nil {
			t.Skip("geoip.dat not found")
		}
		t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

		rules := []string{
			"geoip:us",
			"geoip:cn",
			"geoip:!cn",
			"ext:geoip.dat:!cn",
			"ext:geoip.dat:ca",
			"ext-ip:geoip.dat:!cn",
			"ext-ip:geoip.dat:!ca",
		}

		_, err := geodata.ParseIPRules(rules)
		if err != nil {
			t.Fatalf("Failed to parse ip rules, got %s", err)
		}
	})
}

func TestParseDomainRules(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		rules := []string{
			"domain:google.com",
			"full:www.example.com",
			"keyword:example",
			"regexp:.*\\.example\\.com$",
		}

		_, err := geodata.ParseDomainRules(rules, geodata.Domain_Domain)
		if err != nil {
			t.Fatalf("Failed to parse domain rules, got %s", err)
		}
	})

	t.Run("geosite", func(t *testing.T) {
		if _, err := os.Stat(filepath.Join("..", "..", "resources", "geosite.dat")); err != nil {
			t.Skip("geosite.dat not found")
		}
		t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

		rules := []string{
			"geosite:cn",
			"geosite:geolocation-!cn",
			"geosite:cn@!cn",
			"ext:geosite.dat:geolocation-!cn",
			"ext:geosite.dat:cn@!cn",
			"ext-site:geosite.dat:geolocation-!cn",
			"ext-site:geosite.dat:cn@!cn",
		}

		_, err := geodata.ParseDomainRules(rules, geodata.Domain_Domain)
		if err != nil {
			t.Fatalf("Failed to parse domain rules, got %s", err)
		}
	})
}
