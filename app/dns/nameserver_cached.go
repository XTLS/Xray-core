package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/features/dns"
)

type CachedNameserver interface {
	getCacheController() *CacheController

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, domain string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	cache := s.getCacheController()
	fqdn := Fqdn(domain)

	if !cache.disableCache {
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if !go_errors.Is(err, errRecordNotFound) {
				log.Record(&log.DNSLog{Server: cache.name, Domain: domain, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
				return ips, ttl, err
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", domain, " at ", cache.name)
	}

	sub4, sub6 := cache.registerSubscribers(fqdn, option)
	defer closeSubscribers(sub4, sub6)

	noResponseErrCh := make(chan error, 2)
	onEvent := func(sub *pubsub.Subscriber) (*IPRecord, error) {
		if sub == nil {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-noResponseErrCh:
			return nil, err
		case msg := <-sub.Wait():
			sub.Close()
			return msg.(*IPRecord), nil
		}
	}

	start := time.Now()
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)

	rec4, err4 := onEvent(sub4)
	rec6, err6 := onEvent(sub6)

	var errs []error
	if err4 != nil {
		errs = append(errs, err4)
	}
	if err6 != nil {
		errs = append(errs, err6)
	}

	ips, ttl, err := merge(option, rec4, rec6, errs...)
	log.Record(&log.DNSLog{Server: cache.name, Domain: domain, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	return ips, ttl, err
}

func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, uint32, error) {
	var allIPs []net.IP
	var rTTL uint32 = dns.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable && rec4 != nil {
		ips, ttl, err := rec4.getIPs()
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if option.IPv6Enable && rec6 != nil {
		ips, ttl, err := rec6.getIPs()
		if !mergeReq || go_errors.Is(err, errRecordNotFound) {
			return ips, ttl, err
		}
		if ttl < rTTL {
			rTTL = ttl
		}
		if len(ips) > 0 {
			allIPs = append(allIPs, ips...)
		} else {
			errs = append(errs, err)
		}
	}

	if len(allIPs) > 0 {
		return allIPs, rTTL, nil
	}
	if len(errs) == 2 && go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}
