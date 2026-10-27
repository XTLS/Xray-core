package fakedns

import (
	"context"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/dns/fakedns/remote"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cache"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type Holder struct {
	domainToIP cache.Lru
	ipRange    *net.IPNet
	mu         sync.Mutex

	config *FakeDnsPool
}

func (fkdns *Holder) IsIPInIPPool(ip net.Address) bool {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	if ip.Family().IsDomain() {
		return false
	}
	return fkdns.ipRange != nil && fkdns.ipRange.Contains(ip.IP())
}

func (fkdns *Holder) GetFakeIPRanges() []string {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	if fkdns.ipRange == nil {
		return nil
	}
	return []string{fkdns.ipRange.String()}
}

func (fkdns *Holder) GetFakeIPForDomain3(domain string, ipv4, ipv6 bool) []net.Address {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	if fkdns.ipRange == nil {
		return nil
	}
	isIPv6 := fkdns.ipRange.IP.To4() == nil
	if (isIPv6 && ipv6) || (!isIPv6 && ipv4) {
		return fkdns.getFakeIPForDomain(domain)
	}
	return []net.Address{}
}

func (*Holder) Type() interface{} {
	return (*dns.FakeDNSEngine)(nil)
}

func (fkdns *Holder) Start() error {
	if fkdns.config != nil && fkdns.config.IpPool != "" && fkdns.config.LruSize != 0 {
		return fkdns.initializeFromConfig()
	}
	return errors.New("invalid fakeDNS setting")
}

func (fkdns *Holder) Close() error {
	// nothing to do for now, just wait GC
	return nil
}

func NewFakeDNSHolder() (*Holder, error) {
	var fkdns *Holder
	var err error

	if fkdns, err = NewFakeDNSHolderConfigOnly(nil); err != nil {
		return nil, errors.New("Unable to create Fake Dns Engine").Base(err)
	}
	err = fkdns.initialize(dns.FakeIPv4Pool, 65535)
	if err != nil {
		return nil, err
	}
	return fkdns, nil
}

func NewFakeDNSHolderConfigOnly(conf *FakeDnsPool) (*Holder, error) {
	return &Holder{config: conf}, nil
}

func (fkdns *Holder) initializeFromConfig() error {
	return fkdns.initialize(fkdns.config.IpPool, int(fkdns.config.LruSize))
}

func (fkdns *Holder) initialize(ipPoolCidr string, lruSize int) error {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	var ipRange *net.IPNet
	var err error

	if _, ipRange, err = net.ParseCIDR(ipPoolCidr); err != nil {
		return errors.New("Unable to parse CIDR for Fake DNS IP assignment").Base(err)
	}

	ones, bits := ipRange.Mask.Size()
	rooms := bits - ones
	if math.Log2(float64(lruSize)) >= float64(rooms) {
		return errors.New("LRU size is bigger than subnet size")
	}
	fkdns.domainToIP = cache.NewLru(lruSize)
	fkdns.ipRange = ipRange
	return nil
}

// GetFakeIPForDomain checks and generates a fake IP for a domain name
func (fkdns *Holder) GetFakeIPForDomain(domain string) []net.Address {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	return fkdns.getFakeIPForDomain(domain)
}

func (fkdns *Holder) getFakeIPForDomain(domain string) []net.Address {
	if fkdns.ipRange == nil {
		return nil
	}
	if v, ok := fkdns.domainToIP.Get(domain); ok {
		return []net.Address{v.(net.Address)}
	}
	currentTimeMillis := uint64(time.Now().UnixMilli())
	ones, bits := fkdns.ipRange.Mask.Size()
	rooms := bits - ones
	if rooms < 64 {
		currentTimeMillis %= (uint64(1) << rooms)
	}
	bigIntIP := big.NewInt(0).SetBytes(fkdns.ipRange.IP)
	bigIntIP = bigIntIP.Add(bigIntIP, new(big.Int).SetUint64(currentTimeMillis))
	var ip net.Address
	address := make([]byte, len(fkdns.ipRange.IP))
	for {
		ip = net.IPAddress(bigIntIP.FillBytes(address))

		// if we run for a long time, we may go back to beginning and start seeing the IP in use
		if _, ok := fkdns.domainToIP.PeekKeyFromValue(ip); !ok {
			break
		}

		bigIntIP = bigIntIP.Add(bigIntIP, big.NewInt(1))
		if bigIntIP.BitLen() > bits || !fkdns.ipRange.Contains(bigIntIP.FillBytes(address)) {
			bigIntIP = big.NewInt(0).SetBytes(fkdns.ipRange.IP)
		}
	}
	fkdns.domainToIP.Put(domain, ip)
	return []net.Address{ip}
}

// GetDomainFromFakeDNS checks if an IP is a fake IP and have corresponding domain name
func (fkdns *Holder) GetDomainFromFakeDNS(ip net.Address) string {
	fkdns.mu.Lock()
	if !ip.Family().IsIP() || fkdns.ipRange == nil || !fkdns.ipRange.Contains(ip.IP()) {
		fkdns.mu.Unlock()
		return ""
	}
	k, ok := fkdns.domainToIP.GetKeyFromValue(ip)
	fkdns.mu.Unlock()
	if ok {
		return k.(string)
	}
	// Log handlers may inspect the pool; do not invoke them under mu.
	errors.LogInfo(context.Background(), "A fake ip request to ", ip, ", however there is no matching domain name in fake DNS")
	return ""
}

type HolderMulti struct {
	holders []*Holder

	config *FakeDnsPoolMulti
}

func (h *HolderMulti) GetFakeIPRanges() []string {
	var pools []string
	for _, holder := range h.holders {
		ranges := holder.GetFakeIPRanges()
		if len(ranges) == 0 {
			return nil
		}
		pools = append(pools, ranges...)
	}
	return pools
}

func (h *HolderMulti) IsIPInIPPool(ip net.Address) bool {
	if ip.Family().IsDomain() {
		return false
	}
	for _, v := range h.holders {
		if v.IsIPInIPPool(ip) {
			return true
		}
	}
	return false
}

func (h *HolderMulti) GetFakeIPForDomain3(domain string, ipv4, ipv6 bool) []net.Address {
	var ret []net.Address
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain3(domain, ipv4, ipv6)...)
	}
	return ret
}

func (h *HolderMulti) GetFakeIPForDomain(domain string) []net.Address {
	var ret []net.Address
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain(domain)...)
	}
	return ret
}

func (h *HolderMulti) GetDomainFromFakeDNS(ip net.Address) string {
	for _, v := range h.holders {
		if domain := v.GetDomainFromFakeDNS(ip); domain != "" {
			return domain
		}
	}
	return ""
}

func (h *HolderMulti) Type() interface{} {
	return (*dns.FakeDNSEngine)(nil)
}

func (h *HolderMulti) Start() error {
	for _, v := range h.holders {
		if v.config != nil && v.config.IpPool != "" && v.config.LruSize != 0 {
			if err := v.Start(); err != nil {
				return errors.New("Cannot start all fake dns pools").Base(err)
			}
		} else {
			return errors.New("invalid fakeDNS setting")
		}
	}
	return nil
}

func (h *HolderMulti) Close() error {
	var errs []error
	for _, v := range h.holders {
		errs = append(errs, v.Close())
	}
	return errors.Combine(errs...)
}

func (h *HolderMulti) createHolderGroups() error {
	for _, v := range h.config.Pools {
		holder, err := NewFakeDNSHolderConfigOnly(v)
		if err != nil {
			return err
		}
		h.holders = append(h.holders, holder)
	}
	return nil
}

func NewFakeDNSHolderMulti(conf *FakeDnsPoolMulti) (*HolderMulti, error) {
	holderMulti := &HolderMulti{config: conf}
	if err := holderMulti.createHolderGroups(); err != nil {
		return nil, err
	}
	return holderMulti, nil
}

func init() {
	common.Must(common.RegisterConfig((*FakeDnsPool)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var f *Holder
		var err error
		if f, err = NewFakeDNSHolderConfigOnly(config.(*FakeDnsPool)); err != nil {
			return nil, err
		}
		return f, nil
	}))

	common.Must(common.RegisterConfig((*FakeDnsPoolMulti)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		cfg := config.(*FakeDnsPoolMulti)
		if cfg.Remote != nil {
			if len(cfg.Pools) != 0 {
				return nil, errors.New("remote FakeDNS cannot have local pools")
			}
			return remote.New(ctx, cfg.Remote.Address, cfg.Remote.Timeout)
		}
		var f *HolderMulti
		var err error
		if f, err = NewFakeDNSHolderMulti(config.(*FakeDnsPoolMulti)); err != nil {
			return nil, err
		}
		return f, nil
	}))
}
