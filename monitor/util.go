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

func AddressInfo(address string, isServer bool) (Address, error) {
	res, err := http.Get(fmt.Sprint("http://ip-api.com/json/", address, "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"))
	i.ReportIfErr(err, "could not get the address info: address=", address)
	if err != nil {
		return Address{}, err
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK && res.StatusCode != 0 {
		return Address{}, errors.New(fmt.Sprint("bad response code of ip-api, status=", res.StatusCode))
	}

	var result Address
	if err = json.NewDecoder(res.Body).Decode(&result); err != nil {
		i.ReportIfErr(err, "could not parse get ip info api")
		return Address{}, err
	}

	result.Ip, result.Query = result.Query, address
	result.IsServer, result.IsClient = isServer, !isServer
	result.UpdatedAt = time.Now()

	return result, nil
}

func AddAddressInfoIfDoesNotExist(address string, isServer bool) {
	getAddressInfoLock.Lock()
	defer getAddressInfoLock.Unlock()

	if exists, err := i.AddressCol().Exists(ctx, M{"_id": address}); err != nil {
		i.ReportIfErr(err)
	} else if !exists {
		addr, err := AddressInfo(address, isServer)
		if err == nil {
			_, err = i.AddressCol().InsertOne(ctx, addr)
			i.ReportIfErr(err, "while getting address info")
		}
	} else if exists, _ := i.AddressCol().Exists(ctx, M{"_id": address, "is_server": isServer}); !exists {
		update := M{}
		if isServer {
			update["is_server"] = true
		} else {
			update["is_client"] = true
		}

		_, _ = i.AddressCol().UpdateOne(ctx, M{"_id": address}, M{"$set": update})
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
		return fmt.Sprint(prefix, "--", uuid.New())
	}

	h, err := Hash(v, HashOptions{IgnoreZeroValue: true, SlicesAsSets: true})
	if err != nil {
		panic(err)
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

func SplitAddress(address string) (string, string) {
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
				return strings.Join(parts[:6], ":"),
					strings.Join(parts[:6], ":") + ":*:*"
			}
		} else {
			// It's IPv4 or IPv4-mapped-IPv6
			ipv4 := ip.To4().String()
			parts := strings.Split(ipv4, ".")
			if len(parts) == 4 {
				// Return first 2 parts and wildcard for last 2
				return strings.Join(parts[:2], "."),
					strings.Join(parts[:2], ".") + ".*.*"
			}
		}
	}

	// Handle domain names
	parts := strings.Split(address, ".")
	if len(parts) <= 2 {
		// For domains like "example.com"
		return "", "*." + address
	}

	// For domains with more parts
	domainSuffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if len(parts) == 3 {
		// For domains like "sub.example.com"
		return parts[0], "*." + domainSuffix
	}

	// For domains with more than 3 parts
	prefix := strings.Join(parts[:len(parts)-2], ".")
	return prefix, "*." + domainSuffix
}
