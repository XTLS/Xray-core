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
	"net/http"
	"strings"
	"time"
)

var ctx = context.TODO()

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
