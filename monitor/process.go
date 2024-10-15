package monitor

import (
	"github.com/xtls/xray-core/common/protocol"
	"go.mongodb.org/mongo-driver/bson"
	"reflect"
	"strings"
)

func Process(f any, args ...any) {
	defer func() {
		i.ReportIfErr(recover(), "while processing a job")
	}()

	funcValue := reflect.ValueOf(f)
	argsValues := make([]reflect.Value, len(args))
	for i, arg := range args {
		argsValues[i] = reflect.ValueOf(arg)
	}

	go funcValue.Call(argsValues)
}

func ProcessRequestHeader(requestHeader *protocol.RequestHeader) {
	defer func() {
		i.ReportIfErr(recover(), "while processing the request header")
	}()

	if requestHeader == nil || requestHeader.Command == protocol.RequestCommandMux {
		return
	}

	destinationAddress := extractDestinationAddress(requestHeader)
	if exists, err := i.AddressCol().Exists(ctx, bson.M{"query": destinationAddress}); err != nil {
		i.ReportIfErr(err)
	} else if !exists {
		if address, err := AddressInfo(destinationAddress, true); err == nil {
			_, err = i.AddressCol().InsertOne(ctx, address)
			i.ReportIfErr(err, "while inserting request header process info")
		} else {
			i.ReportIfErr(err)
		}
	}

	processWindow(destinationAddress)
}

func extractDestinationAddress(header *protocol.RequestHeader) string {
	destination := header.Destination()

	var destinationAddress string
	if destination.Address.Family().IsIP() {
		destinationAddress = destination.Address.IP().String()
	} else {
		destinationAddress = destination.Address.Domain()
	}

	return strings.ToLower(strings.TrimSpace(destinationAddress))
}

func processWindow(destinationAddress string) {

}
