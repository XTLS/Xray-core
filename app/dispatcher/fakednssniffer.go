package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
)

// newFakeDNSSniffer Create a Fake DNS metadata sniffer
func newFakeDNSSniffer(ctx context.Context) (protocolSnifferWithMetadata, error) {
	var fakeDNSEngine dns.FakeDNSEngine
	err := core.RequireFeatures(ctx, func(fdns dns.FakeDNSEngine) {
		fakeDNSEngine = fdns
	})
	if err != nil {
		return protocolSnifferWithMetadata{}, err
	}
	if fakeDNSEngine == nil {
		errNotInit := newError("FakeDNSEngine is not initialized, but such a sniffer is used").AtError()
		return protocolSnifferWithMetadata{}, errNotInit
	}
	return protocolSnifferWithMetadata{protocolSniffer: func(ctx context.Context, bytes []byte) (SniffResult, error) {
		Target := session.OutboundFromContext(ctx).Target
		if Target.Network == net.Network_TCP || Target.Network == net.Network_UDP {
			domainFromFakeDNS := fakeDNSEngine.GetDomainFromFakeDNS(Target.Address)
			if domainFromFakeDNS != "" {
				newError("fake dns got domain: ", domainFromFakeDNS, " for ip: ", Target.Address.String()).WriteToLog(session.ExportIDToError(ctx))
				return &fakeDNSSniffResult{domainName: domainFromFakeDNS}, nil
			}
		}
		return nil, common.ErrNoClue
	}, metadataSniffer: true}, nil
}

type fakeDNSSniffResult struct {
	domainName string
}

func (fakeDNSSniffResult) Protocol() string {
	return "fakedns"
}

func (f fakeDNSSniffResult) Domain() string {
	return f.domainName
}
