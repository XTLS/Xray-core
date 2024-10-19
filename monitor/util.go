package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/amirdlt/flex"
	. "github.com/amirdlt/flex/util"
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
	"go.mongodb.org/mongo-driver/mongo"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ctx                = context.TODO()
	getAddressInfoLock = &sync.Mutex{}
)

var i = &I{
	BasicInjector: &flex.BasicInjector{},
}

func AddressInfo(target, subTarget, type_ string, isServer bool) (Address, error) {
	var address string
	switch type_ {
	case "ipv4", "ipv6":
		address = target[:len(target)-3] + subTarget
	case "domain":
		address = strings.TrimPrefix(target, "*.")
		if subTarget != "" {
			address = fmt.Sprint(subTarget, ".", address)
		}
	default:
		return Address{}, errors.New("invalid type = " + type_)
	}

	res, err := http.Get(fmt.Sprint("http://ip-api.com/json/", address, "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"))
	i.ReportIfErr(err, "could not get the address info: address=", address)
	if err != nil {
		return Address{}, err
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK && res.StatusCode != 0 {
		return Address{}, errors.New(fmt.Sprint("bad response code of ip-api, status=", res.StatusCode))
	}

	var result AddressResponse
	if err = json.NewDecoder(res.Body).Decode(&result); err != nil {
		i.ReportIfErr(err, "could not parse get ip info api")
		return Address{}, err
	}

	addressRecord := Address{
		Target:       target,
		SubTargets:   Stream[string]{}.AppendIfNotEmpty(subTarget),
		Countries:    []string{fmt.Sprint(result.CountryCode, ":", result.Country)},
		UpdatedAt:    time.Now(),
		IsClient:     !isServer,
		IsServer:     isServer,
		Tags:         nil,
		Continents:   []string{fmt.Sprint(result.ContinentCode, ":", result.Continent)},
		Regions:      []string{fmt.Sprint(result.Region, ":", result.RegionName)},
		Cities:       Stream[string]{}.AppendIfNotEmpty(result.City),
		Districts:    Stream[string]{}.AppendIfNotEmpty(result.District),
		Zips:         Stream[string]{}.AppendIfNotEmpty(result.Zip),
		Coordination: []string{fmt.Sprint(result.Lat, ":", result.Lon)},
		Timezones:    Stream[string]{}.AppendIfNotEmpty(result.Timezone),
		Offsets:      []int{result.Offset},
		Currencies:   Stream[string]{}.AppendIfNotEmpty(result.Currency),
		Isps:         Stream[string]{}.AppendIfNotEmpty(result.ISP),
		Orgs:         Stream[string]{}.AppendIfNotEmpty(result.Org),
		ASs:          []string{fmt.Sprint(result.AS, ":", result.ASName)},
		Reverses:     Stream[string]{}.AppendIfNotEmpty(result.Reverse),
		IsMobile:     []bool{result.Mobile},
		IsProxy:      []bool{result.Proxy},
		ResolvedIps: Stream[string]{}.AppendIf(func(v string) bool {
			return type_ == "domain" && v != ""
		}, result.Query),
		Type:   type_,
		Status: result.Status,
	}

	time.Sleep(time.Millisecond * 100)

	return addressRecord, nil
}

func AddAddressInfoIfDoesNotExist(target, subTarget, type_ string, isServer bool) {
	getAddressInfoLock.Lock()
	defer getAddressInfoLock.Unlock()

	var addressRecord Address
	if err := i.AddressCol().FindOne(ctx, M{"_id": target}).Decode(&addressRecord); err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		i.ReportIfErr(err)
	} else if errors.Is(err, mongo.ErrNoDocuments) || addressRecord.Status != "success" {
		addr, err := AddressInfo(target, subTarget, type_, isServer)
		if err == nil {
			_, err = i.AddressCol().InsertOne(ctx, addr)
			i.ReportIfErr(err, "while getting address info")
		}
	} else if exist, err := i.AddressCol().Exists(ctx, M{"_id": target, "sub_targets": subTarget}); !exist && subTarget != "" && err == nil {
		addr, err := AddressInfo(target, subTarget, type_, isServer)
		if err == nil {
			addressRecord.Cities = addressRecord.Cities.AppendIfNotExistAndNotEmpty(addr.Cities...)
			addressRecord.ASs = addressRecord.ASs.AppendIfNotExistAndNotEmpty(addr.ASs...)
			addressRecord.Continents = addressRecord.Continents.AppendIfNotExistAndNotEmpty(addressRecord.Continents...)
			addressRecord.Countries = addressRecord.Countries.AppendIfNotExistAndNotEmpty(addressRecord.Countries...)
			addressRecord.Currencies = addressRecord.Currencies.AppendIfNotExistAndNotEmpty(addressRecord.Currencies...)
			addressRecord.Districts = addressRecord.Districts.AppendIfNotExistAndNotEmpty(addressRecord.Districts...)
			addressRecord.Isps = addressRecord.Isps.AppendIfNotExistAndNotEmpty(addressRecord.Isps...)
			addressRecord.Orgs = addressRecord.Orgs.AppendIfNotExistAndNotEmpty(addressRecord.Orgs...)
			addressRecord.SubTargets = addressRecord.SubTargets.AppendIfNotExist(subTarget)
			addressRecord.IsMobile = addressRecord.IsMobile.AppendIfNotExistAndNotEmpty(addressRecord.IsMobile...)
			addressRecord.IsProxy = addressRecord.IsProxy.AppendIfNotExistAndNotEmpty(addressRecord.IsProxy...)
			addressRecord.Coordination = addressRecord.Coordination.AppendIfNotExistAndNotEmpty(addressRecord.Coordination...)
			addressRecord.Regions = addressRecord.Regions.AppendIfNotExistAndNotEmpty(addressRecord.Regions...)
			addressRecord.Zips = addressRecord.Zips.AppendIfNotExistAndNotEmpty(addressRecord.Zips...)
			addressRecord.Reverses = addressRecord.Reverses.AppendIfNotExistAndNotEmpty(addressRecord.Reverses...)
			if isServer {
				addressRecord.IsServer = true
			} else {
				addressRecord.IsClient = true
			}

			if addressRecord.Type == "domain" {
				addressRecord.ResolvedIps = addressRecord.ResolvedIps.AppendIfNotExistAndNotEmpty(addressRecord.ResolvedIps...)
			}

			addressRecord.UpdatedAt = time.Now()
			_, err = i.AddressCol().UpdateOne(ctx, M{"_id": target}, M{"$set": addressRecord})
			i.ReportIfErr(err, "while updating an address record")
		}
	}
}

func ExtractDestinationAddress(header *protocol.RequestHeader) string {
	destination := header.Destination()

	var destinationAddress string
	if destination.Address.Family().IsIP() {
		destinationAddress = destination.Address.IP().String()
	} else {
		destinationAddress = destination.Address.Domain()
	}

	return strings.ToLower(strings.TrimSpace(destinationAddress))
}

func GenerateUUID(prefix string, v any) string {
	if v == nil {
		if prefix == "" {
			return uuid.New().String()
		}

		return fmt.Sprint(prefix, "--", uuid.New())
	}

	h, err := Hash(v, HashOptions{IgnoreZeroValue: true, SlicesAsSets: true})
	if err != nil {
		panic(err)
	}

	if prefix == "" {
		return uuid.NewHash(
			sha256.New(),
			[16]byte{},
			[]byte(fmt.Sprint(h)),
			4,
		).String()
	}

	return fmt.Sprint(prefix, "--", uuid.NewHash(
		sha256.New(),
		[16]byte{},
		[]byte(fmt.Sprint(h)),
		4,
	))
}

func Injector() *I {
	return i
}

func SplitAddress(address string) (string, string, string) {
	// Clean up the address
	address = strings.Trim(strings.TrimSpace(strings.ToLower(address)), "./,-()=+-!?@\"#$%^&*`~[]{};:")

	// Try parsing as IP first
	ip := net.ParseIP(address)
	if ip != nil {
		// Check if it's IPv6
		if ip.To4() == nil {
			// It's a pure IPv6 address
			parts := strings.Split(address, ":")
			if len(parts) == 8 {
				// Return first 6 parts and wildcard for last 2
				return strings.Join(parts[6:], ":"),
					strings.Join(parts[:6], ":") + ":*:*", "ipv6"
			}
		} else {
			// It's IPv4 or IPv4-mapped-IPv6
			ipv4 := ip.To4().String()
			parts := strings.Split(ipv4, ".")
			if len(parts) == 4 {
				// Return first 2 parts and wildcard for last 2
				return strings.Join(parts[2:], "."),
					strings.Join(parts[:2], ".") + ".*.*", "ipv4"
			}
		}
	}

	// Handle domain names
	parts := strings.Split(address, ".")
	if len(parts) <= 2 {
		// For domains like "example.com"
		return "", "*." + address, "domain"
	}

	// For domains with more parts
	domainSuffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if len(parts) == 3 {
		// For domains like "sub.example.com"
		return parts[0], "*." + domainSuffix, "domain"
	}

	// For domains with more than 3 parts
	prefix := strings.Join(parts[:len(parts)-2], ".")
	return prefix, "*." + domainSuffix, "domain"
}
