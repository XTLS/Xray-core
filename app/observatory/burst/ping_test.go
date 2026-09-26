package burst

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPingClientMeasureDelayResponseValidation(t *testing.T) {
	tests := []struct {
		name                 string
		handler              http.HandlerFunc
		httpMethod           string
		expectedStatus       int32
		minimumResponseBytes int64
		wantError            string
	}{
		{
			name: "complete response",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusPartialContent)
				_, _ = writer.Write(bytes.Repeat([]byte("x"), 32*1024))
			},
			expectedStatus:       http.StatusPartialContent,
			minimumResponseBytes: 32 * 1024,
		},
		{
			name: "unexpected status",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write(bytes.Repeat([]byte("x"), 32*1024))
			},
			expectedStatus:       http.StatusOK,
			minimumResponseBytes: 32 * 1024,
			wantError:            "unexpected HTTP status",
		},
		{
			name: "response too short",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				_, _ = writer.Write(bytes.Repeat([]byte("x"), 1023))
			},
			expectedStatus:       http.StatusOK,
			minimumResponseBytes: 1024,
			wantError:            "response body too short",
		},
		{
			name: "truncated response",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Length", strconv.Itoa(2048))
				_, _ = writer.Write(bytes.Repeat([]byte("x"), 1024))
			},
			expectedStatus:       http.StatusOK,
			minimumResponseBytes: 1024,
			wantError:            "unexpected EOF",
		},
		{
			name: "legacy GET defaults accept any response",
			handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte("short"))
			},
		},
		{
			name:       "legacy HEAD defaults accept any response",
			httpMethod: http.MethodHead,
			handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()

			client := &pingClient{
				destination: server.URL,
				httpClient:  server.Client(),
			}
			httpMethod := test.httpMethod
			if httpMethod == "" {
				httpMethod = http.MethodGet
			}
			_, err := client.MeasureDelay(httpMethod, test.expectedStatus, test.minimumResponseBytes)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("MeasureDelay() returned an error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("MeasureDelay() error = %v, want an error containing %q", err, test.wantError)
			}
		})
	}
}

func TestPingClientMeasureDelayTimesOutWhileReadingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(bytes.Repeat([]byte("x"), 1024))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	client := &pingClient{
		destination: server.URL,
		httpClient:  &http.Client{Timeout: 100 * time.Millisecond},
	}
	start := time.Now()
	_, err := client.MeasureDelay(http.MethodGet, http.StatusOK, 2048)
	if err == nil {
		t.Fatal("MeasureDelay() succeeded while the response body was stalled")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("MeasureDelay() timed out after %v, want less than one second", elapsed)
	}
}

func TestPingClientMeasureDelayRejectsMinimumResponseBytesForHead(t *testing.T) {
	client := &pingClient{httpClient: http.DefaultClient}
	_, err := client.MeasureDelay(http.MethodHead, 0, 1)
	if err == nil || !strings.Contains(err.Error(), "requires GET") {
		t.Fatalf("MeasureDelay() error = %v, want an error requiring GET", err)
	}
}
