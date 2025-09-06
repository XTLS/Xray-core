package time

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/transport/internet"
)

var timeOffset atomic.Pointer[time.Duration]

func init() {
	timeOffset.Store(new(time.Duration))
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
}

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
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				return internet.DialSystem(ctx, dest, nil)
			},
		},
	}
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
	offset := timeOffset.Load()
	return time.Now().Add(*offset)
}
