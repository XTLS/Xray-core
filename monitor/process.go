package monitor

import (
	"errors"
	. "github.com/amirdlt/flex/util"
	"github.com/xtls/xray-core/common/protocol"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"reflect"
	"strings"
	"sync"
	"time"
)

var userStatMutex = SynchronizedMap[string, *sync.Mutex]{}

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
	if requestHeader == nil || requestHeader.Command == protocol.RequestCommandMux {
		return
	}

	destinationAddress := extractDestinationAddress(requestHeader)
	AddAddressInfoIfDoesNotExist(destinationAddress, true)
}

func ProcessWindow(email,
	netType,
	source,
	target string,
	port uint16,
	uploadByteCount uint64,
	downloadByteCount uint64,
	duration time.Duration) {
	AddAddressInfoIfDoesNotExist(source, false)
	if !userStatMutex.ContainKey(email) {
		userStatMutex.Put(email, &sync.Mutex{})
	}

	userStatMutex.Get(email).Lock()

	var window Window
	if err := i.WindowCol().FindOne(ctx,
		M{"source": source, "target": target, "end_time": M{"$lte": time.Now()}}).Decode(&window); err == nil {
		if !window.DestinationPorts.Contains(port) {
			window.DestinationPorts.AppendIf(func(v uint16) bool {
				return !window.DestinationPorts.Contains(v)
			}, port)

			window.NetworkTypes.AppendIf(func(v string) bool {
				return !window.NetworkTypes.Contains(v)
			}, netType)

			if window.Users.ContainKey(email) {
				cs := window.Users[email]
				cs.Duration += duration
				cs.Count++
				cs.DownloadByteCount += downloadByteCount
				cs.UploadByteCount += uploadByteCount

				window.Users[email] = cs
			} else {
				window.Users[email] = CallStat{
					Count:             1,
					UploadByteCount:   uploadByteCount,
					DownloadByteCount: downloadByteCount,
					Duration:          duration,
				}
			}
		}
	} else if errors.Is(err, mongo.ErrNoDocuments) {
		window = Window{
			Source:    source,
			Target:    target,
			StartTime: time.Now(),
			EndTime:   time.Now().Add(c.WindowSize),
			Users: Map[string, CallStat]{email: CallStat{
				Count:             1,
				UploadByteCount:   uploadByteCount,
				DownloadByteCount: downloadByteCount,
				Duration:          duration,
			}},
			DestinationPorts: []uint16{port},
			NetworkTypes:     []string{netType},
		}
	} else {
		i.ReportIfErr(err)
		return
	}

	_, err := i.WindowCol().UpdateOne(ctx, M{}, M{"$set": window}, options.Update().SetUpsert(true))
	i.ReportIfErr(err)

	userStatMutex.Get(email).Unlock()
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
