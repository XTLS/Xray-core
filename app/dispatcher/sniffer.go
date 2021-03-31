package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/bittorrent"
	"github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/protocol/tls"
)

type SniffResult interface {
	Protocol() string
	Domain() string
}

type domainSniffer func(context.Context, []byte) (SniffResult, error)

type protocolSniffer func(context.Context, []byte) (SniffResult, error)

type snifferWithMetadata struct {
	domainSniffer   domainSniffer
	protocolSniffer protocolSniffer
	// A Metadata sniffer will be invoked on connection establishment only, with nil body,
	// for both TCP and UDP connections
	// It will not be shown as a traffic type for routing unless there is no other successful sniffing.
	metadataSniffer bool
}

type Sniffer struct {
	sniffer []snifferWithMetadata
}

func NewSniffer(ctx context.Context) *Sniffer {
	ret := &Sniffer{
		sniffer: []snifferWithMetadata{
			{func(c context.Context, b []byte) (SniffResult, error) { return http.SniffDomainHTTP(b) }, func(c context.Context, b []byte) (SniffResult, error) { return http.SniffProtocolHTTP(b) }, false},
			{func(c context.Context, b []byte) (SniffResult, error) { return tls.SniffDomainTLS(b) }, func(c context.Context, b []byte) (SniffResult, error) { return tls.SniffProtocolTLS(b) }, false},
			{func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffDomainBittorrent(b) }, func(c context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffProtocolBittorrent(b) }, false},
		},
	}
	if sniffer, err := newFakeDNSSniffer(ctx); err == nil {
		ret.sniffer = append(ret.sniffer, sniffer)
	}
	return ret
}

var errUnknownContent = newError("unknown content")

func (s *Sniffer) Sniff(c context.Context, payload []byte, shouldSniffDomain bool) (SniffResult, error) {
	var pendingSniffer []snifferWithMetadata
	for _, si := range s.sniffer {
		sd := si.domainSniffer
		sp := si.protocolSniffer

		if si.metadataSniffer {
			continue
		}

		var result SniffResult
		var err error
		if shouldSniffDomain {
			result, err = sd(c, payload)
		} else {
			result, err = sp(c, payload)
		}
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func (s *Sniffer) SniffMetadata(c context.Context) (SniffResult, error) {
	var pendingSniffer []snifferWithMetadata
	for _, si := range s.sniffer {
		sd := si.domainSniffer

		if !si.metadataSniffer {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}

		result, err := sd(c, nil)
		if err == common.ErrNoClue {
			pendingSniffer = append(pendingSniffer, si)
			continue
		}

		if err == nil && result != nil {
			return result, nil
		}
	}

	if len(pendingSniffer) > 0 {
		s.sniffer = pendingSniffer
		return nil, common.ErrNoClue
	}

	return nil, errUnknownContent
}

func CompositeResult(domainResult SniffResult, protocolResult SniffResult) SniffResult {
	return &compositeResult{domainResult: domainResult, protocolResult: protocolResult}
}

type compositeResult struct {
	domainResult   SniffResult
	protocolResult SniffResult
}

func (c compositeResult) Protocol() string {
	return c.protocolResult.Protocol()
}

func (c compositeResult) Domain() string {
	return c.domainResult.Domain()
}

func (c compositeResult) ProtocolForDomainResult() string {
	return c.domainResult.Protocol()
}

type SnifferResultComposite interface {
	ProtocolForDomainResult() string
}
