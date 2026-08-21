package proxyman_test

import (
	"reflect"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
)

func TestBuildSniffingRequestPortsExcluded(t *testing.T) {
	request, err := proxyman.BuildSniffingRequest(&proxyman.SniffingConfig{
		Enabled: true,
		PortsExcluded: &net.PortList{
			Range: []*net.PortRange{{From: 22, To: 22}, {From: 993, To: 995}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSniffingRequest() failed: %v", err)
	}

	want := net.MemoryPortList{{From: 22, To: 22}, {From: 993, To: 995}}
	if !reflect.DeepEqual(request.ExcludeForPort, want) {
		t.Fatalf("BuildSniffingRequest() gave ExcludeForPort %v, want %v", request.ExcludeForPort, want)
	}
}

func TestBuildSniffingRequestWithoutPortsExcluded(t *testing.T) {
	request, err := proxyman.BuildSniffingRequest(&proxyman.SniffingConfig{Enabled: true})
	if err != nil {
		t.Fatalf("BuildSniffingRequest() failed: %v", err)
	}
	if len(request.ExcludeForPort) != 0 {
		t.Fatalf("BuildSniffingRequest() gave ExcludeForPort %v, want empty", request.ExcludeForPort)
	}
}
