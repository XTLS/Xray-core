package monitor

import (
	"github.com/xtls/xray-core/common/protocol"
	"reflect"
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

	if requestHeader == nil {
		return
	}

	requestHeader.Destination()

	_, err := i.DestinationCol().InsertOne(ctx, Destination{
		Port:               requestHeader.Port.Value(),
		Command:            requestHeader.Command,
		DestinationAddress: requestHeader.Destination().Address.IP().String(),
		DestinationPort:    uint16(requestHeader.Destination().Port),
		DestinationDomain:  requestHeader.Destination().Address.Domain(),
	})

	i.ReportIfErr(err, "while inserting request header process info")
}
