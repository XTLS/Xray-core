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

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	cache := s.getCacheController()
	if !cache.disableCache {
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if !go_errors.Is(err, errRecordNotFound) {
				// errors.LogDebugInner(ctx, err, cache.name, " cache HIT ", fqdn, " -> ", ips)
				log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
				return ips, ttl, err
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", fqdn, " at ", cache.name)
	}

	return fetch(ctx, s, fqdn, option)
}

func fetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) ([]net.IP, uint32, error) {
	key := fqdn + "f"
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		key = key + "46"
	case option.IPv4Enable:
		key = key + "4"
	case option.IPv6Enable:
		key = key + "6"
	}

	v, _, _ := s.getCacheController().requestGroup.Do(key, func() (any, error) {
		return doFetch(ctx, s, fqdn, option), nil
	})
	ret := v.(result)

	return ret.ips, ret.ttl, ret.error
}

type result struct {
	ips []net.IP
	ttl uint32
	error
}

func doFetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) result {
	sub4, sub6 := s.getCacheController().registerSubscribers(fqdn, option)
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
			return msg.(*IPRecord), nil // should panic
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
	log.Record(&log.DNSLog{Server: s.getCacheController().name, Domain: fqdn, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	return result{ips, ttl, err}
}

func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, uint32, error) {
	var allIPs []net.IP
	var rTTL uint32 = dns.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := rec4.getIPs() // it's safe
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

	if option.IPv6Enable {
		ips, ttl, err := rec6.getIPs() // it's safe
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
