package net

import "testing"

func TestProcessAttributionUsesDestination(t *testing.T) {
	storeProcessAttribution("udp", "192.0.2.1", 43210, "198.51.100.1", 53, 1234, "proc", "/tmp/proc")

	pid, name, path, found := lookupProcessAttribution("udp", "192.0.2.1", 43210, "198.51.100.1", 53)
	if !found {
		t.Fatal("process attribution entry not found")
	}
	if pid != 1234 || name != "proc" || path != "/tmp/proc" {
		t.Fatalf("attribution entry = (%d, %q, %q), want (1234, \"proc\", \"/tmp/proc\")", pid, name, path)
	}

	if _, _, _, found := lookupProcessAttribution("udp", "192.0.2.1", 43210, "203.0.113.1", 53); found {
		t.Fatal("process attribution matched a different destination")
	}
}

func TestProcessAttributionCanonicalizesIP(t *testing.T) {
	storeProcessAttribution("tcp", "::ffff:192.0.2.2", 44321, "::ffff:198.51.100.2", 443, 5678, "proc2", "/tmp/proc2")

	_, _, _, found := lookupProcessAttribution("tcp", "192.0.2.2", 44321, "198.51.100.2", 443)
	if !found {
		t.Fatal("process attribution did not canonicalize IPv4-mapped addresses")
	}
}
