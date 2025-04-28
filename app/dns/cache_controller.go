package dns

import (
	"context"
	go_errors "errors"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
	"sync"
	"time"
)

type CacheController struct {
	sync.RWMutex
	ips          map[string]*record
	pub          *pubsub.Service
	cacheCleanup *task.Periodic
	name         string
	disableCache bool
}

func NewCacheController(name string, disableCache bool) *CacheController {
	c := &CacheController{
		name:         name,
		disableCache: disableCache,
		ips:          make(map[string]*record),
		pub:          pubsub.NewService(),
	}

	c.cacheCleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  c.CacheCleanup,
	}
	return c
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	now := time.Now()
	c.Lock()
	defer c.Unlock()

	if len(c.ips) == 0 {
		return errors.New("nothing to do. stopping...")
	}

	for domain, record := range c.ips {
		if record.A != nil && record.A.Expire.Before(now) {
			record.A = nil
		}
		if record.AAAA != nil && record.AAAA.Expire.Before(now) {
			record.AAAA = nil
		}

		if record.A == nil && record.AAAA == nil {
			errors.LogDebug(context.Background(), c.name, "cache cleanup ", domain)
			delete(c.ips, domain)
		} else {
			c.ips[domain] = record
		}
	}

	if len(c.ips) == 0 {
		c.ips = make(map[string]*record)
	}

	return nil
}

func (c *CacheController) updateIP(req *dnsRequest, ipRec *IPRecord) {
	elapsed := time.Since(req.start)

	c.Lock()
	rec, found := c.ips[req.domain]
	if !found {
		rec = &record{}
	}

	switch req.reqType {
	case dnsmessage.TypeA:
		rec.A = ipRec
	case dnsmessage.TypeAAAA:
		rec.AAAA = ipRec
	}

	errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", ipRec.IP, " ", elapsed)
	c.ips[req.domain] = rec

	switch req.reqType {
	case dnsmessage.TypeA:
		c.pub.Publish(req.domain+"4", nil)
		if !c.disableCache {
			_, _, err := rec.AAAA.getIPs()
			if !go_errors.Is(err, errRecordNotFound) {
				c.pub.Publish(req.domain+"6", nil)
			}
		}
	case dnsmessage.TypeAAAA:
		c.pub.Publish(req.domain+"6", nil)
		if !c.disableCache {
			_, _, err := rec.A.getIPs()
			if !go_errors.Is(err, errRecordNotFound) {
				c.pub.Publish(req.domain+"4", nil)
			}
		}
	}

	c.Unlock()
	common.Must(c.cacheCleanup.Start())
}

func (c *CacheController) findIPsForDomain(domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	c.RLock()
	record, found := c.ips[domain]
	c.RUnlock()

	if !found {
		return nil, 0, errRecordNotFound
	}

	var errs []error
	var allIPs []net.IP
	var rTTL uint32 = dns_feature.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable {
		ips, ttl, err := record.A.getIPs()
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
		ips, ttl, err := record.AAAA.getIPs()
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
	if go_errors.Is(errs[0], errs[1]) {
		return nil, rTTL, errs[0]
	}
	return nil, rTTL, errors.Combine(errs...)
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	// ipv4 and ipv6 belong to different subscription groups
	if option.IPv4Enable {
		sub4 = c.pub.Subscribe(domain + "4")
	}
	if option.IPv6Enable {
		sub6 = c.pub.Subscribe(domain + "6")
	}
	return
}

func closeSubscribers(sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	if sub4 != nil {
		sub4.Close()
	}
	if sub6 != nil {
		sub6.Close()
	}
}
