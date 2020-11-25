package all

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	logService "github.com/xtls/xray-core/v1/app/log/command"
	statsService "github.com/xtls/xray-core/v1/app/stats/command"
	"github.com/xtls/xray-core/v1/main/commands/base"
)

// cmdAPI calls an API in an Xray process
var cmdAPI = &base.Command{
	UsageLine: "{{.Exec}} api [-server 127.0.0.1:8080] <action> <parameter>",
	Short:     "Call an API in a Xray process",
	Long: `
Call an API in a Xray process, API calls in this command have a timeout to the server of 3 seconds.

The following methods are currently supported:

    LoggerService.RestartLogger
    StatsService.GetStats
    StatsService.QueryStats

Examples:

    {{.Exec}} api --server=127.0.0.1:8080 LoggerService.RestartLogger '' 
    {{.Exec}} api --server=127.0.0.1:8080 StatsService.QueryStats 'pattern: "" reset: false'
    {{.Exec}} api --server=127.0.0.1:8080 StatsService.GetStats 'name: "inbound>>>statin>>>traffic>>>downlink" reset: false'
    {{.Exec}} api --server=127.0.0.1:8080 StatsService.GetSysStats ''
	`,
}

func init() {
	cmdAPI.Run = executeAPI // break init loop
}

var (
	apiServerAddrPtr = cmdAPI.Flag.String("server", "127.0.0.1:8080", "")
)

func executeAPI(cmd *base.Command, args []string) {
	unnamedArgs := cmdAPI.Flag.Args()
	if len(unnamedArgs) < 2 {
		base.Fatalf("service name or request not specified.")
	}

	service, method := getServiceMethod(unnamedArgs[0])
	handler, found := serivceHandlerMap[strings.ToLower(service)]
	if !found {
		base.Fatalf("unknown service: %s", service)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *apiServerAddrPtr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		base.Fatalf("failed to dial %s", *apiServerAddrPtr)
	}
	defer conn.Close()

	response, err := handler(ctx, conn, method, unnamedArgs[1])
	if err != nil {
		base.Fatalf("failed to call service %s", unnamedArgs[0])
	}

	fmt.Println(response)
}

func getServiceMethod(s string) (string, string) {
	ss := strings.Split(s, ".")
	service := ss[0]
	var method string
	if len(ss) > 1 {
		method = ss[1]
	}
	return service, method
}

type serviceHandler func(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error)

var serivceHandlerMap = map[string]serviceHandler{
	"statsservice":  callStatsService,
	"loggerservice": callLogService,
}

func callLogService(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error) {
	client := logService.NewLoggerServiceClient(conn)

	switch strings.ToLower(method) {
	case "restartlogger":
		r := &logService.RestartLoggerRequest{}
		if err := proto.Unmarshal([]byte(request), r); err != nil {
			return "", err
		}
		resp, err := client.RestartLogger(ctx, r)
		if err != nil {
			return "", err
		}
		m, err := proto.Marshal(resp)
		if err != nil {
			return "", err
		}
		return string(m), nil
	default:
		return "", errors.New("Unknown method: " + method)
	}
}

func callStatsService(ctx context.Context, conn *grpc.ClientConn, method string, request string) (string, error) {
	client := statsService.NewStatsServiceClient(conn)

	switch strings.ToLower(method) {
	case "getstats":
		r := &statsService.GetStatsRequest{}
		if err := proto.Unmarshal([]byte(request), r); err != nil {
			return "", err
		}
		resp, err := client.GetStats(ctx, r)
		if err != nil {
			return "", err
		}
		m, err := proto.Marshal(resp)
		if err != nil {
			return "", err
		}
		return string(m), nil
	case "querystats":
		r := &statsService.QueryStatsRequest{}
		if err := proto.Unmarshal([]byte(request), r); err != nil {
			return "", err
		}
		resp, err := client.QueryStats(ctx, r)
		if err != nil {
			return "", err
		}
		m, err := proto.Marshal(resp)
		if err != nil {
			return "", err
		}
		return string(m), nil
	case "getsysstats":
		// SysStatsRequest is an empty message
		r := &statsService.SysStatsRequest{}
		resp, err := client.GetSysStats(ctx, r)
		if err != nil {
			return "", err
		}
		m, err := proto.Marshal(resp)
		if err != nil {
			return "", err
		}
		return string(m), nil
	default:
		return "", errors.New("Unknown method: " + method)
	}
}
