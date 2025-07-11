package tls_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/transport/internet/tls"
)

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "encryptedsni.com",
		EchConfigList: "udp://1.1.1.1",
	}
	// test concurrent Dial(to test cache problem)
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Add(1)
		go func() {
			TLSConfig := config.GetTLSConfig()
			TLSConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: TLSConfig,
				},
			}
			resp, err := client.Get("https://encryptedsni.com/cdn-cgi/trace")
			common.Must(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			common.Must(err)
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("ECH Dial success but SNI is not encrypted")
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
