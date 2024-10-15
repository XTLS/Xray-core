package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/amirdlt/flex"
	. "github.com/amirdlt/flex/util"
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

func Injector() *I {
	return i
}
