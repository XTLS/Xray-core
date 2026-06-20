package metrics

import (
	"context"
	"encoding/json"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
)

func TestMetricsCanRestartInSameProcess(t *testing.T) {
	for i := 0; i < 2; i++ {
		server := startMetricsTestServer(t)
		readMetricsVars(t, server)
		readMetricsPprof(t, server)
		if err := server.Close(); err != nil {
			t.Fatalf("failed to close metrics server: %v", err)
		}
	}
}

func TestMetricsCanRunMultipleInstancesInSameProcess(t *testing.T) {
	server1 := startMetricsTestServer(t)
	t.Cleanup(func() {
		_ = server1.Close()
	})
	server2 := startMetricsTestServer(t)
	t.Cleanup(func() {
		_ = server2.Close()
	})

	readMetricsVars(t, server1)
	readMetricsVars(t, server2)
}

func TestMetricsListenOnlyWithoutTagDoesNotRegisterOutbound(t *testing.T) {
	listen := pickMetricsListenAddress(t)
	server := startMetricsTestServerWithMetricsConfig(t, &Config{
		Listen: listen,
	})
	t.Cleanup(func() {
		_ = server.Close()
	})

	response, err := http.Get("http://" + listen + "/debug/vars")
	if err != nil {
		t.Fatalf("failed to read listen-only metrics: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected listen-only metrics status: %d", response.StatusCode)
	}

	outboundManager := server.GetFeature(feature_outbound.ManagerType()).(feature_outbound.Manager)
	if handlers := outboundManager.ListHandlers(context.Background()); len(handlers) != 0 {
		t.Fatalf("listen-only metrics registered outbound handlers: got %d, want 0", len(handlers))
	}
}

func startMetricsTestServer(t *testing.T) *core.Instance {
	return startMetricsTestServerWithMetricsConfig(t, &Config{
		Tag: "metrics_out",
	})
}

func startMetricsTestServerWithMetricsConfig(t *testing.T, metricsConfig *Config) *core.Instance {
	t.Helper()

	server, err := core.New(metricsTestConfig(metricsConfig))
	if err != nil {
		t.Fatalf("failed to create metrics server: %v", err)
	}
	if err := server.Start(); err != nil {
		_ = server.Close()
		t.Fatalf("failed to start metrics server: %v", err)
	}
	return server
}

func metricsTestConfig(metricsConfig *Config) *core.Config {
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(metricsConfig),
		},
	}
}

func pickMetricsListenAddress(t *testing.T) string {
	t.Helper()

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to pick metrics listen address: %v", err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func readMetricsVars(t *testing.T, server *core.Instance) {
	t.Helper()

	recorder := httptest.NewRecorder()
	metricsHandler(t, server).httpHandler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/debug/vars", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected metrics vars status: %d", recorder.Code)
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode metrics vars: %v", err)
	}
	if _, found := payload["stats"]; !found {
		t.Fatal("metrics vars missing stats")
	}
	if _, found := payload["observatory"]; !found {
		t.Fatal("metrics vars missing observatory")
	}
}

func readMetricsPprof(t *testing.T, server *core.Instance) {
	t.Helper()

	recorder := httptest.NewRecorder()
	metricsHandler(t, server).httpHandler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected metrics pprof status: %d", recorder.Code)
	}
}

func metricsHandler(t *testing.T, server *core.Instance) *MetricsHandler {
	t.Helper()

	feature := server.GetFeature((*MetricsHandler)(nil))
	handler, ok := feature.(*MetricsHandler)
	if !ok || handler == nil {
		t.Fatal("metrics handler not registered")
	}
	return handler
}
