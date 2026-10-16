package stats

import (
	"encoding/base64"
	"strings"
)

// InboundOnlinePrefix separates connection attribution from the legacy user
// online maps. Neither credentials nor the existing traffic counter names change.
const InboundOnlinePrefix = "inbound-user>>>"

func InboundOnlineName(email, tag string) string {
	return InboundOnlinePrefix + base64.RawURLEncoding.EncodeToString([]byte(email)) + ">>>" + base64.RawURLEncoding.EncodeToString([]byte(tag))
}

func ParseInboundOnlineName(name string) (email, tag string, ok bool) {
	rest, ok := strings.CutPrefix(name, InboundOnlinePrefix)
	if !ok {
		return "", "", false
	}
	user, inbound, ok := strings.Cut(rest, ">>>")
	if !ok {
		return "", "", false
	}
	u, err := base64.RawURLEncoding.DecodeString(user)
	if err != nil {
		return "", "", false
	}
	t, err := base64.RawURLEncoding.DecodeString(inbound)
	if err != nil || len(u) == 0 || len(t) == 0 {
		return "", "", false
	}
	return string(u), string(t), true
}
