package splithttp

import (
	"net/http"
	"strconv"
	"strings"
)

// Per-request path randomization (operator supplied).
//
// When the session and seq are carried off-path (cookie / header / query), the
// URL path is free decoration: the server only checks
// strings.HasPrefix(reqPath, configPath) and ignores everything after the
// configured base path. If the operator sets pathPool, each request appends a
// randomly chosen entry to the base path, so the transport stops sending every
// request to one fixed path. A "*" inside an entry is replaced with a random
// decimal number, so a short list can cover id / cursor style paths
// (e.g. "items/*", "users/*/feed").
//
// No pool is shipped by default. A fixed list baked into the binary would just
// become a new shared signature; the operator picks entries that match the
// traffic they want to blend into.

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	s, ok := randStringFromCharset(6, "0123456789")
	if !ok {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v % n
}

// pathMetaIsOffPath reports whether both session and seq are carried somewhere
// other than the path, which leaves the path free to decorate.
func (c *Config) pathMetaIsOffPath() bool {
	return c.GetNormalizedSessionPlacement() != PlacementPath &&
		c.GetNormalizedSeqPlacement() != PlacementPath
}

// DecorateRequestPath appends a random entry from PathPool to req.URL.Path.
// It is a no-op when no pool is configured.
func (c *Config) DecorateRequestPath(req *http.Request) {
	if len(c.PathPool) == 0 {
		return
	}
	seg := c.PathPool[randIntn(len(c.PathPool))]
	for strings.Contains(seg, "*") {
		seg = strings.Replace(seg, "*", strconv.Itoa(1000+randIntn(900000)), 1)
	}
	seg = strings.TrimPrefix(seg, "/")
	base := req.URL.Path
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	req.URL.Path = base + seg
}
