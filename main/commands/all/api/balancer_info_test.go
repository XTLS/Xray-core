package api

import (
	"context"
	"net"
	"slices"
	"testing"

	"google.golang.org/grpc"

	routerService "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/main/commands/base"
)

type balancerInfoRecorder struct {
	routerService.UnimplementedRoutingServiceServer
	tags chan string
}

func (s *balancerInfoRecorder) GetBalancerInfo(_ context.Context, request *routerService.GetBalancerInfoRequest) (*routerService.GetBalancerInfoResponse, error) {
	s.tags <- request.Tag
	return &routerService.GetBalancerInfoResponse{Balancer: &routerService.BalancerMsg{}}, nil
}

func TestBalancerInfoMultipleTags(t *testing.T) {
	serverAddr, timeout, jsonOutput := apiServerAddrPtr, apiTimeout, apiJSON
	t.Cleanup(func() { apiServerAddrPtr, apiTimeout, apiJSON = serverAddr, timeout, jsonOutput })
	for _, mode := range []string{"text", "json"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			recorder := &balancerInfoRecorder{tags: make(chan string, 2)}
			server := grpc.NewServer()
			routerService.RegisterRoutingServiceServer(server, recorder)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				server.Serve(listener)
			}()
			t.Cleanup(func() { server.Stop(); <-stopped })

			args := []string{"--server=" + listener.Addr().String()}
			if mode == "json" {
				args = append(args, "--json")
			}
			executeBalancerInfo(&base.Command{}, append(args, "a", "b"))
			var got []string
			for len(recorder.tags) > 0 {
				got = append(got, <-recorder.tags)
			}
			if !slices.Equal(got, []string{"a", "b"}) {
				t.Fatalf("queried tags = %v, want [a b]", got)
			}
		})
	}
}
