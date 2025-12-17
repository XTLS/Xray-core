package splithttp

import (
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func xhttpDownloadEnableDNSPin(downloadCfg *internet.StreamConfig) bool {
	if downloadCfg == nil {
		return false
	}
	if downloadCfg.Address == nil {
		return true
	}
	if dom, ok := downloadCfg.Address.Address.(*net.IPOrDomain_Domain); ok {
		return dom.Domain == "" || strings.EqualFold(dom.Domain, "same")
	}
	return false
}

// xhttpApplyDownloadSameAddress mutates memory2.Destination when downloadSettings.address is
// missing/""/"same", inheriting the primary destination's address while keeping the download
// port (or falling back to primary port).
func xhttpApplyDownloadSameAddress(primary net.Destination, downloadCfg *internet.StreamConfig, memory2 *internet.MemoryStreamConfig) {
	if !xhttpDownloadEnableDNSPin(downloadCfg) {
		return
	}
	if memory2 == nil {
		return
	}

	// Figure out the desired port (downloadCfg.Port wins if provided).
	port := primary.Port
	if downloadCfg != nil && downloadCfg.Port != 0 {
		port = net.Port(downloadCfg.Port)
	}

	if memory2.Destination == nil {
		memory2.Destination = &net.Destination{Address: primary.Address, Port: port, Network: net.Network_TCP}
		return
	}

	if memory2.Destination.Address.Family().IsDomain() {
		dom := memory2.Destination.Address.Domain()
		if dom == "" || strings.EqualFold(dom, "same") {
			*memory2.Destination = net.Destination{Address: primary.Address, Port: port, Network: net.Network_TCP}
		}
	}
}


