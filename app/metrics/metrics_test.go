package metrics

import (
	"encoding/json"
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

func startMetricsTestServer(t *testing.T) *core.Instance {
	t.Helper()

	server, err := core.New(metricsTestConfig())
	if err != nil {
		t.Fatalf("failed to create metrics server: %v", err)
	}
	if err := server.Start(); err != nil {
		_ = server.Close()
		t.Fatalf("failed to start metrics server: %v", err)
	}
	return server
}

func metricsTestConfig() *core.Config {
	return &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&Config{
				Tag: "metrics_out",
			}),
		},
	}
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
