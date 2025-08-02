package tls

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
)

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "encryptedsni.com+udp://1.1.1.1",
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
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
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
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load("encryptedsni.com|udp://1.1.1.1" + "|" + fmt.Sprintf("%p", config.EchSocketSettings))
	if !ok {
		t.Error("ECH config cache not found")

	}
	ok = echConfigCache.UpdateLock.TryLock()
	if !ok {
		t.Error("ECH config cache dead lock detected")
	}
	echConfigCache.UpdateLock.Unlock()
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
	}
}

func TestECHDialFail(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "udp://1.1.1.1",
	}
	TLSConfig := config.GetTLSConfig()
	TLSConfig.NextProtos = []string{"http/1.1"}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: TLSConfig,
		},
	}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	common.Must(err)
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	common.Must(err)
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load("cloudflare.com|udp://1.1.1.1" + "|" + fmt.Sprintf("%p", config.EchSocketSettings))
	if !ok {
		t.Error("ECH config cache not found")
	}
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
		return
	}
	if configRecord.err == nil {
		t.Error("unexpected nil error in ECH config record")
	}
}
