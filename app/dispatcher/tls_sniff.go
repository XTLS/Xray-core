package dispatcher

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

const (
	maxPendingTLSSniffs = 1024
	maxTLSSniffBytes    = 64 * 1024
)

var errSniffingRejected = errors.New("TLS sniffing incomplete; refusing to route")

type tlsSniffResult struct {
	result  SniffResult
	err     error
	cache   buf.MultiBuffer
	readErr error
}

func (d *DefaultDispatcher) sniff(ctx context.Context, reader *cachedReader, request session.SniffingRequest, destination net.Destination) (SniffResult, error) {
	if request.TLSSniffingTimeout == 0 || destination.Network != net.Network_TCP || destination.Port != 443 || !destination.Address.Family().IsIP() {
		return sniffer(ctx, reader, request.MetadataOnly, destination.Network)
	}
	// A usable FakeDNS mapping already supplies the domain needed for routing.
	if metadata, err := NewSniffer(ctx).SniffMetadata(ctx); err == nil && d.shouldOverride(ctx, metadata, request, destination) {
		return sniffer(ctx, reader, request.MetadataOnly, destination.Network)
	}
	if d.pendingTLSSniffs.Add(1) > maxPendingTLSSniffs {
		d.pendingTLSSniffs.Add(-1)
		return nil, errors.New("too many pending TLS sniffs").Base(errSniffingRejected)
	}
	ctx, cancel := context.WithTimeout(ctx, request.TLSSniffingTimeout)
	defer cancel()
	done := make(chan tlsSniffResult)
	go func() {
		// Retain the slot until the reader exits, even if its owner is slow to close it.
		defer d.pendingTLSSniffs.Add(-1)
		result := readTLSSniff(ctx, reader.reader)
		defer func() { buf.ReleaseMulti(result.cache) }()
		select {
		case done <- result:
			result.cache = nil
		case <-ctx.Done():
		}
	}()
	select {
	case <-ctx.Done():
		return nil, errors.New(ctx.Err()).Base(errSniffingRejected)
	case result := <-done:
		if ctx.Err() != nil {
			buf.ReleaseMulti(result.cache)
			return nil, errors.New(ctx.Err()).Base(errSniffingRejected)
		}
		reader.cache = result.cache
		reader.readErr = result.readErr
		return result.result, result.err
	}
}

func readTLSSniff(ctx context.Context, reader buf.Reader) (out tlsSniffResult) {
	sniffer := NewSniffer(ctx)
	metadata, metadataErr := sniffer.SniffMetadata(ctx)
	var payload []byte
	emptyReads := 0
	for {
		if ctx.Err() != nil {
			out.err = errSniffingRejected
			return
		}
		mb, readErr := reader.ReadMultiBuffer()
		out.readErr = readErr
		if mb.IsEmpty() {
			emptyReads++
		} else {
			emptyReads = 0
		}
		for _, b := range mb {
			if b == nil {
				continue
			}
			payload = append(payload, b.BytesTo(min(b.Len(), int32(maxTLSSniffBytes-len(payload))))...)
			// Coalesce small reads so a byte-at-a-time peer cannot retain one buffer per byte.
			out.cache = buf.MergeBytes(out.cache, b.Bytes())
		}
		buf.ReleaseMulti(mb)
		if len(payload) > 0 {
			result, err := sniffer.Sniff(ctx, payload, net.Network_TCP)
			if err != common.ErrNoClue && err != protocol.ErrProtoNeedMoreData {
				if metadataErr == nil {
					if err == nil {
						result = CompositeResult(metadata, result)
					} else {
						result, err = metadata, nil
					}
				}
				out.result, out.err = result, err
				return
			}
		}
		if readErr != nil || len(payload) == maxTLSSniffBytes || emptyReads >= 64 {
			if readErr == nil {
				if len(payload) == maxTLSSniffBytes {
					readErr = errors.New("TLS sniffing prefix limit reached")
				} else {
					readErr = io.ErrNoProgress
				}
			}
			out.err = errors.New(readErr).Base(errSniffingRejected)
			return
		}
	}
}
