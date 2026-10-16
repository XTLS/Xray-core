package stats

import "testing"

func TestInboundOnlineName(t *testing.T) {
	for _, pair := range [][2]string{{"alice", "in-443"}, {"user>>>online", "in>>>tag"}, {"тест", "профиль"}} {
		email, tag, ok := ParseInboundOnlineName(InboundOnlineName(pair[0], pair[1]))
		if !ok || email != pair[0] || tag != pair[1] {
			t.Fatalf("round trip: %q %q %v", email, tag, ok)
		}
	}
	for _, invalid := range []string{"user>>>alice>>>online", InboundOnlinePrefix, InboundOnlinePrefix + "***>>>aaa", InboundOnlineName("", "in")} {
		if _, _, ok := ParseInboundOnlineName(invalid); ok {
			t.Fatalf("accepted malformed name %q", invalid)
		}
	}
}
