package net

import "testing"

func TestRegisterProcessFinder(t *testing.T) {
	t.Cleanup(func() { RegisterProcessFinder(nil) })

	calls := 0
	RegisterProcessFinder(func(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, error) {
		calls++
		if network != "tcp" || srcIP != "192.0.2.1" || srcPort != 1234 || destIP != "192.0.2.2" || destPort != 443 {
			t.Errorf("endpoints = %s %s:%d -> %s:%d", network, srcIP, srcPort, destIP, destPort)
		}
		return 42, "process", "/path/process", nil
	})
	pid, name, path, err := FindProcess("tcp", "192.0.2.1", 1234, "192.0.2.2", 443)
	if err != nil || pid != 42 || name != "process" || path != "/path/process" {
		t.Fatalf("FindProcess() = %d, %q, %q, %v", pid, name, path, err)
	}
	if calls != 1 {
		t.Fatalf("FindProcess() called the registered finder %d times, want 1", calls)
	}

	// 192.0.2.1 is not a local address. The lookup of the platform returns an error for it.
	RegisterProcessFinder(nil)
	pid, name, path, err = FindProcess("tcp", "192.0.2.1", 1234, "192.0.2.2", 443)
	if err == nil {
		t.Fatalf("FindProcess() without a registered finder = %d, %q, %q", pid, name, path)
	}
	if calls != 1 {
		t.Fatalf("FindProcess() called the removed finder: %d calls in total, want 1", calls)
	}
}
