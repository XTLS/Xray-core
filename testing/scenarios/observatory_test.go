package scenarios

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/observatory"
	obscmd "github.com/xtls/xray-core/app/observatory/command"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	v2httptest "github.com/xtls/xray-core/testing/servers/http"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestObservatoryPerOutboundProbeURL exercises the per-outbound ProbeUrl
// override (config.proto field 6 / observer.go): two outbounds each expose
// their own "self" health-check endpoint, and the plain (non-burst)
// Observatory must probe each outbound against its own URL instead of the
// Observatory-level global one.
func TestObservatoryPerOutboundProbeURL(t *testing.T) {
	var hitsA, hitsB atomic.Int32

	portA := tcp.PickPort()
	mockA := &v2httptest.Server{
		Port: portA,
		PathHandler: map[string]http.HandlerFunc{
			"/ping-a": func(w http.ResponseWriter, r *http.Request) {
				hitsA.Add(1)
				w.WriteHeader(http.StatusNoContent)
			},
		},
	}
	_, err := mockA.Start()
	common.Must(err)
	defer mockA.Close()

	portB := tcp.PickPort()
	mockB := &v2httptest.Server{
		Port: portB,
		PathHandler: map[string]http.HandlerFunc{
			"/ping-b": func(w http.ResponseWriter, r *http.Request) {
				hitsB.Add(1)
				w.WriteHeader(http.StatusNoContent)
			},
		},
	}
	_, err = mockB.Start()
	common.Must(err)

	cmdPort := tcp.PickPort()

	config := &core.Config{
		App: []*serial.TypedMessage{
			// Dispatcher/inbound/outbound managers must be registered before
			// Observatory: Observer.New() resolves its outbound.Manager and
			// routing.Dispatcher dependencies via RequireFeatures, which only
			// resolves synchronously if they're already present — otherwise
			// the deferred callback fires after New() has already returned,
			// silently leaving the Observer's manager/dispatcher nil. This
			// matches the ordering infra/conf.Config.Build() always uses in
			// real JSON-driven configs.
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&observatory.Config{
				SubjectSelector: []string{"node-"},
				// Deliberately unroutable: if the per-outbound override were
				// ignored, both outbounds would be probed against this and
				// (wrongly) reported dead instead of using their own URL.
				ProbeUrl:          "http://127.0.0.1:1/should-never-be-hit",
				ProbeInterval:     int64(2 * time.Second),
				EnableConcurrency: true,
			}),
			serial.ToTypedMessage(&commander.Config{
				Tag:    "api",
				Listen: fmt.Sprintf("127.0.0.1:%d", cmdPort),
				Service: []*serial.TypedMessage{
					serial.ToTypedMessage(&obscmd.Config{}),
				},
			}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag:           "node-a",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
				ProbeUrl:      fmt.Sprintf("http://127.0.0.1:%d/ping-a", portA),
			},
			{
				Tag:           "node-b",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
				ProbeUrl:      fmt.Sprintf("http://127.0.0.1:%d/ping-b", portB),
			},
		},
	}

	servers, err := InitializeServerConfigs(config)
	common.Must(err)
	defer CloseAllServers(servers)

	cmdConn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", cmdPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	defer cmdConn.Close()
	obsClient := obscmd.NewObservatoryServiceClient(cmdConn)

	statusByTag := func() map[string]*observatory.OutboundStatus {
		resp, err := obsClient.GetOutboundStatus(context.Background(), &obscmd.GetOutboundStatusRequest{})
		common.Must(err)
		m := make(map[string]*observatory.OutboundStatus)
		for _, s := range resp.Status.Status {
			m[s.OutboundTag] = s
		}
		return m
	}

	// Wait for at least one probe cycle (interval is 2s).
	deadline := time.Now().Add(15 * time.Second)
	var status map[string]*observatory.OutboundStatus
	for time.Now().Before(deadline) {
		status = statusByTag()
		if status["node-a"] != nil && status["node-b"] != nil && status["node-a"].Alive && status["node-b"].Alive {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if status["node-a"] == nil || !status["node-a"].Alive {
		reason := ""
		if status["node-a"] != nil {
			reason = status["node-a"].LastErrorReason
		}
		t.Fatalf("node-a expected alive via its own probeUrl, got status %+v, reason: %s", status["node-a"], reason)
	}
	if status["node-b"] == nil || !status["node-b"].Alive {
		reason := ""
		if status["node-b"] != nil {
			reason = status["node-b"].LastErrorReason
		}
		t.Fatalf("node-b expected alive via its own probeUrl, got status %+v, reason: %s", status["node-b"], reason)
	}
	if hitsA.Load() == 0 {
		t.Error("expected node-a's own probe endpoint (/ping-a) to receive at least one request")
	}
	if hitsB.Load() == 0 {
		t.Error("expected node-b's own probe endpoint (/ping-b) to receive at least one request")
	}

	// Break node-a's own endpoint only; node-b must stay alive, proving the
	// two outbounds are health-checked independently rather than off one
	// shared URL.
	mockA.Close()

	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		status = statusByTag()
		if status["node-a"] != nil && !status["node-a"].Alive {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if status["node-a"] == nil || status["node-a"].Alive {
		t.Errorf("expected node-a to be marked dead after its own probe endpoint stopped, got %+v", status["node-a"])
	}
	if status["node-b"] == nil || !status["node-b"].Alive {
		t.Errorf("expected node-b to remain alive while only node-a's endpoint was down, got %+v", status["node-b"])
	}

	mockB.Close()
}
