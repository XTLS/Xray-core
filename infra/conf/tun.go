package conf

import (
	"encoding/json"
	"net/netip"

	"github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/app/tun"
)

type TunConfig struct {
	InterfaceName          string                 `json:"interface_name,omitempty"`
	MTU                    uint32                 `json:"mtu,omitempty"`
	Inet4Address           Listable[ListenPrefix] `json:"inet4_address,omitempty"`
	Inet6Address           Listable[ListenPrefix] `json:"inet6_address,omitempty"`
	AutoRoute              bool                   `json:"auto_route,omitempty"`
	StrictRoute            bool                   `json:"strict_route,omitempty"`
	Inet4RouteAddress      Listable[ListenPrefix] `json:"inet4_route_address,omitempty"`
	Inet6RouteAddress      Listable[ListenPrefix] `json:"inet6_route_address,omitempty"`
	IncludeUID             Listable[uint32]       `json:"include_uid,omitempty"`
	IncludeUIDRange        Listable[string]       `json:"include_uid_range,omitempty"`
	ExcludeUID             Listable[uint32]       `json:"exclude_uid,omitempty"`
	ExcludeUIDRange        Listable[string]       `json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser     Listable[int]          `json:"include_android_user,omitempty"`
	IncludePackage         Listable[string]       `json:"include_package,omitempty"`
	ExcludePackage         Listable[string]       `json:"exclude_package,omitempty"`
	EndpointIndependentNat bool                   `json:"endpoint_independent_nat,omitempty"`
	UDPTimeout             int64                  `json:"udp_timeout,omitempty"`
	Stack                  string                 `json:"stack,omitempty"`

	AutoDetectInterface bool `json:"auto_detect_interface,omitempty"`
	OverrideAndroidVPN  bool `json:"override_android_vpn,omitempty"`
}

func (f *TunConfig) Build() (*tun.Config, error) {
	var config tun.Config
	config.InterfaceName = f.InterfaceName
	config.Mtu = f.MTU
	config.Inet4Address = common.Map(common.Map(f.Inet4Address, ListenPrefix.Build), netip.Prefix.String)
	config.Inet6Address = common.Map(common.Map(f.Inet6Address, ListenPrefix.Build), netip.Prefix.String)
	config.AutoRoute = f.AutoRoute
	config.StrictRoute = f.StrictRoute
	config.Inet4RouteAddress = common.Map(common.Map(f.Inet4RouteAddress, ListenPrefix.Build), netip.Prefix.String)
	config.Inet6RouteAddress = common.Map(common.Map(f.Inet6RouteAddress, ListenPrefix.Build), netip.Prefix.String)
	config.IncludeUid = f.IncludeUID
	config.IncludeUidRange = f.IncludeUIDRange
	config.ExcludeUid = f.ExcludeUID
	config.ExcludeUidRange = f.ExcludeUIDRange
	config.IncludeAndroidUser = common.Map(f.IncludeAndroidUser, func(it int) int32 {
		return int32(it)
	})
	config.IncludePackage = f.IncludePackage
	config.ExcludePackage = f.ExcludePackage
	config.EndpointIndependentNat = f.EndpointIndependentNat
	config.UdpTimeout = f.UDPTimeout
	config.Stack = f.Stack
	// for xray
	config.AutoDetectInterface = f.AutoDetectInterface
	config.OverrideAndroidVpn = f.OverrideAndroidVPN
	return &config, nil
}

type Listable[T comparable] []T

func (l Listable[T]) MarshalJSON() ([]byte, error) {
	arrayList := []T(l)
	if len(arrayList) == 1 {
		return json.Marshal(arrayList[0])
	}
	return json.Marshal(arrayList)
}

func (l *Listable[T]) UnmarshalJSON(content []byte) error {
	err := json.Unmarshal(content, (*[]T)(l))
	if err == nil {
		return nil
	}
	var singleItem T
	err = json.Unmarshal(content, &singleItem)
	if err != nil {
		return err
	}
	*l = []T{singleItem}
	return nil
}

type ListenPrefix netip.Prefix

func (p ListenPrefix) MarshalJSON() ([]byte, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return json.Marshal(nil)
	}
	return json.Marshal(prefix.String())
}

func (p *ListenPrefix) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p ListenPrefix) Build() netip.Prefix {
	return netip.Prefix(p)
}
