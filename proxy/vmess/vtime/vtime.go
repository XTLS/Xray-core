package vtime

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol/http"
)

var timeOffset atomic.Pointer[time.Duration]
var initOnce sync.Once

func updateTimeMonitor(ctx context.Context, domain string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
			err := updateTime(domain)
			if err != nil {
				errors.LogError(ctx, err)
			}
		}
	}
}

func updateTime(domain string) error {
	httpClient := http.NewClient()
	resp, err := httpClient.Get(domain)
	if err != nil {
		return errors.New("Failed to access monitor domain").Base(err)
	}
	timeHeader := resp.Header.Get("Date")
	remoteTime, err := time.Parse(time.RFC1123, timeHeader)
	if err != nil {
		return errors.New("Failed to parse time from monitor domain").Base(err)
	}
	localTime := time.Now()
	offset := remoteTime.Sub(localTime)
	if offset < 2*time.Second && offset > -2*time.Second {
		errors.LogWarning(context.Background(), "Time offset too small, ignoring:", offset)
		return nil
	}
	timeOffset.Store(&offset)
	return nil
}

func Now() time.Time {
	initOnce.Do(func() {
		timeOffset.Store(new(time.Duration))
		go func() {
			domain := platform.NewEnvFlag("xray.vmess.time.domain").GetValue(func() string { return "https://apple.com" })
			if domain == "" {
				errors.LogError(context.Background(), "vmess time domain is empty, skip time sync")
				return
			}
			err := updateTime(domain)
			if err != nil {
				errors.LogError(context.Background(), err)
			}
			errors.LogWarning(context.Background(), "Initial time offset for vmess:", timeOffset.Load())
			// only one sync should be enough, so disable periodic update for now
			//go updateTimeMonitor(context.TODO(), domain)
		}()
		runtime.Gosched()
	})
	offset := timeOffset.Load()
	return time.Now().Add(*offset)
}
