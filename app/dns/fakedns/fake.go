package fakedns

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/cache"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type Holder struct {
	domainToIP cache.Lru
	ipRange    *net.IPNet
	mu         sync.RWMutex

	config *FakeDnsPool
}

func (fkdns *Holder) IsIPInIPPool(ip net.Address) bool {
	fkdns.mu.RLock()
	defer fkdns.mu.RUnlock()

	if fkdns.ipRange == nil {
		return false
	}

	if ip.Family().IsDomain() {
		return false
	}
	return fkdns.ipRange.Contains(ip.IP())
}

func (fkdns *Holder) GetFakeIPForDomain3(domain string, ipv4, ipv6 bool) []net.Address {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()

	if fkdns.ipRange == nil {
		return []net.Address{}
	}

	isIPv4 := fkdns.ipRange.IP.To4() != nil

	if (isIPv4 && ipv4) || (!isIPv4 && ipv6) {
		return fkdns.getFakeIPForDomainLocked(domain)
	}

	return []net.Address{}
}

func (*Holder) Type() interface{} {
	return (*dns.FakeDNSEngine)(nil)
}

func (fkdns *Holder) Start() error {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()

	if fkdns.config != nil && fkdns.config.IpPool != "" && fkdns.config.LruSize != 0 {
		return fkdns.initializeFromConfigLocked()
	}
	return errors.New("invalid Fake DNS setting")
}

func (fkdns *Holder) Close() error {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()

	fkdns.domainToIP = nil
	fkdns.ipRange = nil
	return nil
}

func NewFakeDNSHolder() (*Holder, error) {
	fkdns, err := NewFakeDNSHolderConfigOnly(nil)
	if err != nil {
		return nil, errors.New("Unable to create Fake DNS Engine").Base(err).AtError()
	}

	if err := fkdns.initialize(dns.FakeIPv4Pool, 65535); err != nil {
		return nil, err
	}
	return fkdns, nil
}

func NewFakeDNSHolderConfigOnly(conf *FakeDnsPool) (*Holder, error) {
	return &Holder{config: conf}, nil
}

func (fkdns *Holder) initializeFromConfigLocked() error {
	return fkdns.initialize(fkdns.config.IpPool, int(fkdns.config.LruSize))
}

func (fkdns *Holder) initialize(ipPoolCidr string, lruSize int) error {
	var ipRange *net.IPNet
	var err error

	if _, ipRange, err = net.ParseCIDR(ipPoolCidr); err != nil {
		return errors.New("Unable to parse CIDR for Fake DNS IP assignment").Base(err).AtError()
	}

	ones, bits := ipRange.Mask.Size()
	rooms := bits - ones

	if rooms < 64 {
		maxIPs := uint64(1) << rooms

		if maxIPs <= 3 {
			return errors.New("Subnet size is too small for Fake DNS").AtError()
		}

		safeLruLimit := maxIPs - 3

		if uint64(lruSize) >= safeLruLimit {
			lruSize = int(safeLruLimit)
		}
	}

	fkdns.domainToIP = cache.NewLru(lruSize)
	fkdns.ipRange = ipRange

	return nil
}

func (fkdns *Holder) getFakeIPForDomainLocked(domain string) []net.Address {
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
	ipLen := len(fkdns.ipRange.IP)
	buf := make([]byte, ipLen)

	one := big.NewInt(1)
	for {
		bigIntIP.FillBytes(buf)
		ip = net.IPAddress(buf)

		// if we run for a long time, we may go back to beginning and start seeing the IP in use
		if _, ok := fkdns.domainToIP.PeekKeyFromValue(ip); !ok {
			break
		}

		bigIntIP.Add(bigIntIP, one)
		bigIntIP.FillBytes(buf)
		if !fkdns.ipRange.Contains(buf) {
			bigIntIP.SetBytes(fkdns.ipRange.IP)
		}
	}

	fkdns.domainToIP.Put(domain, ip)
	return []net.Address{ip}
}

// GetFakeIPForDomain checks and generates a Fake DNS IP for a domain name
func (fkdns *Holder) GetFakeIPForDomain(domain string) []net.Address {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()

	if fkdns.ipRange == nil {
		return []net.Address{}
	}

	return fkdns.getFakeIPForDomainLocked(domain)
}

// GetDomainFromFakeDNS checks if an IP is a fake IP and have corresponding domain name
func (fkdns *Holder) GetDomainFromFakeDNS(ip net.Address) string {
	fkdns.mu.RLock()
	defer fkdns.mu.RUnlock()

	if fkdns.ipRange == nil || fkdns.domainToIP == nil {
		return ""
	}

	if !ip.Family().IsIP() || !fkdns.ipRange.Contains(ip.IP()) {
		return ""
	}
	if k, ok := fkdns.domainToIP.GetKeyFromValue(ip); ok {
		return k.(string)
	}

	errors.LogInfo(context.Background(), "A fake ip request to ", ip, ", however there is no matching domain name in Fake DNS")
	return ""
}

type HolderMulti struct {
	holders []*Holder
	config  *FakeDnsPoolMulti
	mu      sync.RWMutex
}

func (h *HolderMulti) IsIPInIPPool(ip net.Address) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

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
	h.mu.RLock()
	defer h.mu.RUnlock()

	ret := make([]net.Address, 0, len(h.holders))
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain3(domain, ipv4, ipv6)...)
	}
	return ret
}

func (h *HolderMulti) GetFakeIPForDomain(domain string) []net.Address {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ret := make([]net.Address, 0, len(h.holders))
	for _, v := range h.holders {
		ret = append(ret, v.GetFakeIPForDomain(domain)...)
	}
	return ret
}

func (h *HolderMulti) GetDomainFromFakeDNS(ip net.Address) string {
	h.mu.RLock()
	defer h.mu.RUnlock()

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
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, v := range h.holders {
		if err := v.Start(); err != nil {
			return errors.New("Cannot start Fake DNS pool").Base(err)
		}
	}
	return nil
}

func (h *HolderMulti) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var errs []error
	for _, v := range h.holders {
		if err := v.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	h.holders = nil

	if len(errs) > 0 {
		return errors.New("Cannot close all Fake DNS pools").Base(errs[0])
	}
	return nil
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
	holderMulti := &HolderMulti{
		holders: nil,
		config:  conf,
	}
	if err := holderMulti.createHolderGroups(); err != nil {
		return nil, err
	}
	return holderMulti, nil
}

func init() {
	common.Must(common.RegisterConfig((*FakeDnsPool)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewFakeDNSHolderConfigOnly(config.(*FakeDnsPool))
	}))

	common.Must(common.RegisterConfig((*FakeDnsPoolMulti)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewFakeDNSHolderMulti(config.(*FakeDnsPoolMulti))
	}))
}
