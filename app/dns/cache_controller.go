package dns

import (
	"context"
	go_errors "errors"
	"runtime"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	minSizeForEmptyRebuild  = 512
	shrinkAbsoluteThreshold = 10240
	shrinkRatioThreshold    = 0.65
	migrationBatchSize      = 4096
)

type CacheController struct {
	sync.RWMutex
	ips           map[string]*record
	dirtyips      map[string]*record
	pub           *pubsub.Service
	cacheCleanup  *task.Periodic
	name          string
	disableCache  bool
	highWatermark int
}

func NewCacheController(name string, disableCache bool) *CacheController {
	c := &CacheController{
		name:         name,
		disableCache: disableCache,
		ips:          make(map[string]*record),
		pub:          pubsub.NewService(),
	}

	c.cacheCleanup = &task.Periodic{
		Interval: 300 * time.Second,
		Execute:  c.CacheCleanup,
	}
	return c
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	expiredKeys, err := c.collectExpiredKeys()
	if err != nil {
		return err
	}
	if len(expiredKeys) == 0 {
		return nil
	}
	c.writeAndShrink(expiredKeys)
	return nil
}

func (c *CacheController) collectExpiredKeys() ([]string, error) {
	c.RLock()
	defer c.RUnlock()

	if len(c.ips) == 0 {
		return nil, errors.New("nothing to do. stopping...")
	}

	// skip collection if a migration is in progress
	if c.dirtyips != nil {
		return nil, nil
	}

	now := time.Now()
	expiredKeys := make([]string, 0, len(c.ips)/4) // pre-allocate

	for domain, rec := range c.ips {
		if (rec.A != nil && rec.A.Expire.Before(now)) ||
			(rec.AAAA != nil && rec.AAAA.Expire.Before(now)) {
			expiredKeys = append(expiredKeys, domain)
		}
	}

	return expiredKeys, nil
}

func (c *CacheController) writeAndShrink(expiredKeys []string) {
	c.Lock()
	defer c.Unlock()

	// double check to prevent upper call multiple cleanup tasks
	if c.dirtyips != nil {
		return
	}

	lenBefore := len(c.ips)
	if lenBefore > c.highWatermark {
		c.highWatermark = lenBefore
	}

	now := time.Now()
	for _, domain := range expiredKeys {
		rec := c.ips[domain]
		if rec == nil {
			continue
		}
		if rec.A != nil && rec.A.Expire.Before(now) {
			rec.A = nil
		}
		if rec.AAAA != nil && rec.AAAA.Expire.Before(now) {
			rec.AAAA = nil
		}
		if rec.A == nil && rec.AAAA == nil {
			delete(c.ips, domain)
		}
	}

	lenAfter := len(c.ips)

	if lenAfter == 0 {
		if c.highWatermark >= minSizeForEmptyRebuild {
			errors.LogDebug(context.Background(), c.name,
				" rebuilding empty cache map to reclaim memory.",
				" size_before_cleanup=", lenBefore,
				" peak_size_before_rebuild=", c.highWatermark,
			)

			c.ips = make(map[string]*record)
			c.highWatermark = 0
		}
		return
	}

	if reductionFromPeak := c.highWatermark - lenAfter; reductionFromPeak > shrinkAbsoluteThreshold &&
		float64(reductionFromPeak) > float64(c.highWatermark)*shrinkRatioThreshold {
		errors.LogDebug(context.Background(), c.name,
			" shrinking cache map to reclaim memory.",
			" new_size=", lenAfter,
			" peak_size_before_shrink=", c.highWatermark,
			" reduction_since_peak=", reductionFromPeak,
		)

		c.dirtyips = c.ips
		c.ips = make(map[string]*record, int(float64(lenAfter)*1.1))
		c.highWatermark = lenAfter
		go c.migrate()
	}

}

type migrationEntry struct {
	key   string
	value *record
}

func (c *CacheController) migrate() {
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), c.name, " panic during cache migration: ", r)
			c.Lock()
			c.dirtyips = nil
			// c.ips = make(map[string]*record)
			// c.highWatermark = 0
			c.Unlock()
		}
	}()

	c.RLock()
	dirtyips := c.dirtyips
	c.RUnlock()

	// double check to prevent upper call multiple cleanup tasks
	if dirtyips == nil {
		return
	}

	errors.LogDebug(context.Background(), c.name, " starting background cache migration for ", len(dirtyips), " items.")

	batch := make([]migrationEntry, 0, migrationBatchSize)
	for domain, recD := range dirtyips {
		batch = append(batch, migrationEntry{domain, recD})

		if len(batch) >= migrationBatchSize {
			c.flush(batch)
			batch = batch[:0]
			runtime.Gosched()
		}
	}
	if len(batch) > 0 {
		c.flush(batch)
	}

	c.Lock()
	c.dirtyips = nil
	c.Unlock()

	errors.LogDebug(context.Background(), c.name, " cache migration completed.")
}

func (c *CacheController) flush(batch []migrationEntry) {
	c.Lock()
	defer c.Unlock()

	for _, dirty := range batch {
		if cur := c.ips[dirty.key]; cur != nil {
			merge := &record{}
			if cur.A == nil {
				merge.A = dirty.value.A
			} else {
				merge.A = cur.A
			}
			if cur.AAAA == nil {
				merge.AAAA = dirty.value.AAAA
			} else {
				merge.AAAA = cur.AAAA
			}
			c.ips[dirty.key] = merge
		} else {
			c.ips[dirty.key] = dirty.value
		}
	}
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
		if !c.disableCache && rec.AAAA != nil {
			_, _, err := rec.AAAA.getIPs()
			if !go_errors.Is(err, errRecordNotFound) {
				c.pub.Publish(req.domain+"6", nil)
			}
		}
	case dnsmessage.TypeAAAA:
		c.pub.Publish(req.domain+"6", nil)
		if !c.disableCache && rec.A != nil {
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
	defer c.RUnlock()

	rec, found := c.ips[domain]
	if !found && c.dirtyips != nil {
		rec, found = c.dirtyips[domain]
	}
	if !found {
		return nil, 0, errRecordNotFound
	}

	var errs []error
	var allIPs []net.IP
	var rTTL uint32 = dns_feature.DefaultTTL

	mergeReq := option.IPv4Enable && option.IPv6Enable

	if option.IPv4Enable && rec.A != nil {
		ips, ttl, err := rec.A.getIPs()
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

	if option.IPv6Enable && rec.AAAA != nil {
		ips, ttl, err := rec.AAAA.getIPs()
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
