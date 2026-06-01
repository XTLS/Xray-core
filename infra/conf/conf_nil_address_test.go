package conf

import "testing"

func TestHysteriaClientConfigMissingAddress(t *testing.T) {
	// "version": 2 without "address" must return an error, not panic.
	c := &HysteriaClientConfig{Version: 2}
	if _, err := c.Build(); err == nil {
		t.Error("expected an error for missing address, got nil")
	}
}

func TestFakeDNSPostProcessingMissingServerAddress(t *testing.T) {
	// A DNS server entry without "address" must not panic during config
	// post-processing; the descriptive error is emitted later by Build().
	config := &Config{
		DNSConfig: &DNSConfig{
			Servers: []*NameServerConfig{{Port: 53}},
		},
	}
	if err := (FakeDNSPostProcessingStage{}).Process(config); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
