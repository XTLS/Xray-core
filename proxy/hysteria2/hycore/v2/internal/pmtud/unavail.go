//go:build !linux && !windows && !darwin

package pmtud

// quic-go's MTU detection is enabled by default on all platforms.
// However, it only actually sets the DF bit on 3 supported platforms (Windows, macOS, Linux).
// As a result, on other platforms, probe packets that should never be fragmented will still
// be fragmented and transmitted. So we're only enabling it for platforms where we've verified
// its functionality for now.

const (
	DisablePathMTUDiscovery = true
)
