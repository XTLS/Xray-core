package monitor

import (
	"errors"
	"fmt"
	. "github.com/amirdlt/flex/util"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet/stat"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"reflect"
	"sync"
	"time"
)

var (
	maxGoroutinesForProcess        = 20
	goroutineCountLimiterSemaphore = make(chan any, maxGoroutinesForProcess)
	userStatMutex                  = NewSynchronizedMap(Map[string, *sync.Mutex]{})
)

func Process(f any, args ...any) {
	defer func() {
		i.ReportIfErr(recover(), "while processing a job")
	}()

	funcValue := reflect.ValueOf(f)
	if funcValue.Kind() != reflect.Func {
		i.ReportIfErr(fmt.Errorf("provided argument is not a function: %T", f), "invalid function type")
		return
	}

	argsValues := make([]reflect.Value, len(args))
	for i, arg := range args {
		if arg == nil {
			argsValues[i] = reflect.Zero(funcValue.Type().In(i))
		} else {
			argsValues[i] = reflect.ValueOf(arg)
		}
	}

	goroutineCountLimiterSemaphore <- nil
	go func() {
		defer func() {
			i.ReportIfErr(recover(), "while executing a job")
			<-goroutineCountLimiterSemaphore
		}()

		if len(argsValues) != funcValue.Type().NumIn() {
			i.ReportIfErr(fmt.Errorf("mismatch in number of arguments: expected %d, got %d", funcValue.Type().NumIn(), len(argsValues)), "argument mismatch")
			return
		}

		funcValue.Call(argsValues)
	}()
}

func ProcessRequestHeader(requestHeader *protocol.RequestHeader) {
	if requestHeader == nil || requestHeader.Command == protocol.RequestCommandMux {
		return
	}

	destinationAddress := ExtractDestinationAddress(requestHeader)
	subTarget, target, type_ := SplitAddress(destinationAddress)
	AddAddressInfoIfDoesNotExist(target, subTarget, type_, true)
}

func ProcessWindow(email,
	netType,
	source,
	target string,
	port uint16,
	connection stat.Connection,
	duration time.Duration,
	streamErr error) {
	var subTarget string
	subTarget, target, _ = SplitAddress(target)
	subSource, sourceA, sourceAddrType := SplitAddress(source)
	AddAddressInfoIfDoesNotExist(sourceA, subSource, sourceAddrType, false)
	if !userStatMutex.ContainKey(source) {
		userStatMutex.Put(source, &sync.Mutex{})
	}

	userStatMutex.Get(source).Lock()

	hasStreamErr := streamErr != nil && streamErr.Error() != ""

	var downloadByteCount, uploadByteCount uint64
	if statConn, ok := connection.(*stat.CounterConnection); ok {
		downloadByteCount = uint64(statConn.WriteCounter.Value())
		uploadByteCount = uint64(statConn.ReadCounter.Value())
	}

	var window Window
	if err := i.WindowCol().FindOne(ctx,
		M{"target": target, "end_time": M{"$gte": time.Now()}}).Decode(&window); err == nil {
		window.DestinationPorts = window.DestinationPorts.AppendIf(func(v uint16) bool {
			return v != 0 && !window.DestinationPorts.Contains(v)
		}, port)

		window.NetworkTypes = window.NetworkTypes.AppendIf(func(v string) bool {
			return v != "" && !window.NetworkTypes.Contains(v)
		}, netType)

		window.SubTargets = window.SubTargets.AppendIf(func(v string) bool {
			return subTarget != "" && !window.SubTargets.Contains(v)
		}, subTarget)

		if hasStreamErr {
			errs := window.Errors.Find(func(v *XError) bool {
				return v != nil && v.Message == streamErr.Error()
			})

			if errs.IsEmpty() {
				window.Errors = window.Errors.Append(&XError{streamErr.Error(), 1})
			} else {
				errs[0].Count++
			}
		}

		user := window.Users.Find(func(v *CallStat) bool {
			return v != nil && v.Ip == source
		})

		if !user.IsEmpty() {
			cs := user[0]
			cs.Duration += duration
			cs.Count++
			cs.DownloadByteCount += downloadByteCount
			cs.UploadByteCount += uploadByteCount
			if hasStreamErr {
				cs.FailureCount++
			} else {
				cs.SuccessCount++
			}
		} else {
			var successCount uint64
			if !hasStreamErr {
				successCount = 1
			}

			window.Users = window.Users.Append(&CallStat{
				Count:             1,
				UploadByteCount:   uploadByteCount,
				DownloadByteCount: downloadByteCount,
				Duration:          duration,
				Ip:                source,
				Email:             email,
				SuccessCount:      successCount,
				FailureCount:      1 - successCount,
			})
		}
	} else if errors.Is(err, mongo.ErrNoDocuments) {
		var errs Stream[*XError]
		if hasStreamErr {
			errs = Stream[*XError]{&XError{streamErr.Error(), 1}}
		}

		var successCount uint64
		if !hasStreamErr {
			successCount = 1
		}

		subTargets := make([]string, 0)
		if subTarget != "" {
			subTargets = append(subTargets, subTarget)
		}

		window = Window{
			Target:    target,
			StartTime: time.Now(),
			EndTime:   time.Now().Add(c.WindowSize),
			Users: Stream[*CallStat]{&CallStat{
				Count:             1,
				UploadByteCount:   uploadByteCount,
				DownloadByteCount: downloadByteCount,
				Duration:          duration,
				Ip:                source,
				Email:             email,
				SuccessCount:      successCount,
				FailureCount:      1 - successCount,
			}},
			DestinationPorts: []uint16{port},
			NetworkTypes:     []string{netType},
			Errors:           errs,
			SubTargets:       subTargets,
		}

		window.Id = GenerateUUID("window", M{"target": target, "start_time": window.StartTime, "end_time": window.StartTime})
	} else {
		i.ReportIfErr(err)
		return
	}

	filter := M{}
	if window.Id != "" {
		filter["_id"] = window.Id
	}

	_, err := i.WindowCol().UpdateOne(ctx, filter, M{"$set": window}, options.Update().SetUpsert(true))
	i.ReportIfErr(err)

	userStatMutex.Get(source).Unlock()
}
