package goolom

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/protect"
)

func (s *Session) processSendQueue(workerID int, sessionCloseCh <-chan struct{}) {
	for {
		select {
		case <-sessionCloseCh:
			return
		case <-s.closeCh:
			return
		case data := <-s.sendQueue:
			if len(data) > s.trafficShape.MaxMessageSize {
				logger.Debugf("oversized message size=%d limit=%d", len(data), s.trafficShape.MaxMessageSize)
				continue
			}

			waited, err := s.waitBufferedAmount(workerID, sessionCloseCh)
			if err != nil {
				return
			}
			if waited > 0 {
				logger.Verbosef("[WORKER-%d] Drained after %v", workerID, waited)
			}

			if err := s.dc.Send(data); err != nil {
				logger.Debugf("send error: %v", err)
				s.queueReconnect()
				return
			}

			if s.trafficShape.MinDelay > 0 {
				time.Sleep(s.calculateDelay())
			}
		}
	}
}

func (s *Session) waitBufferedAmount(workerID int, sessionCloseCh <-chan struct{}) (time.Duration, error) {
	start := time.Now()
	for s.dc.BufferedAmount() > defaultBufferHighWaterMark {
		select {
		case <-sessionCloseCh:
			return 0, ErrSessionClosed
		case <-s.closeCh:
			return 0, ErrPeerClosed
		case <-time.After(10 * time.Millisecond):
			if time.Since(start) > 5*time.Second {
				logger.Debugf("buffer wait timeout worker=%d", workerID)
				return time.Since(start), nil
			}
		}
	}
	return time.Since(start), nil
}

func (s *Session) calculateDelay() time.Duration {
	minDelay := s.trafficShape.MinDelay
	maxDelay := s.trafficShape.MaxDelay
	if maxDelay <= minDelay {
		return minDelay
	}
	return minDelay + time.Duration(rand.Int64N(int64(maxDelay-minDelay))) //nolint:gosec,lll // G404: non-cryptographic shaping randomness
}

func (s *Session) startTelemetry(ctx context.Context, serverHello map[string]any) {
	endpoint, interval, ok := parseTelemetryCfg(serverHello)
	if !ok {
		return
	}
	if !s.telemetryActive.CompareAndSwap(false, true) {
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.telemetryActive.Store(false)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.sendTelemetry(ctx, endpoint, "join")
		for {
			select {
			case <-ticker.C:
				s.sendTelemetry(ctx, endpoint, "stats")
			case <-s.telemetryCh:
				s.sendTelemetry(ctx, endpoint, "leave")
				return
			case <-s.closeCh:
				s.sendTelemetry(ctx, endpoint, "leave")
				return
			}
		}
	}()
}

func parseTelemetryCfg(serverHello map[string]any) (string, time.Duration, bool) {
	cfg, ok := serverHello["telemetryConfiguration"].(map[string]any)
	if !ok {
		return "", 0, false
	}
	endpoint, ok := cfg["logEndpoint"].(string)
	if !ok || endpoint == "" {
		endpoint, ok = cfg["endpoint"].(string)
		if !ok || endpoint == "" {
			endpoint, _ = cfg["url"].(string)
		}
	}
	if endpoint == "" {
		return "", 0, false
	}
	interval := defaultTelemetryInterval
	if raw, ok := cfg["sendingInterval"].(float64); ok && raw > 0 {
		interval = time.Duration(raw) * time.Millisecond
	}
	return endpoint, interval, true
}

func (s *Session) stopTelemetry() {
	if s.telemetryActive.Load() {
		select {
		case s.telemetryCh <- struct{}{}:
		default:
		}
	}
}

func (s *Session) sendTelemetry(ctx context.Context, endpoint, event string) {
	body, err := json.Marshal(map[string]any{
		"event":          event,
		"timestamp":      time.Now().UnixMilli(),
		"peerId":         s.peerID,
		"roomId":         s.roomID,
		"displayName":    s.name,
		"implementation": "browser",
		"dataChannel": map[string]any{
			"bufferedAmount": s.GetBufferedAmount(),
			"sendQueue":      len(s.sendQueue),
		},
	})
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		logger.Verbosef("Telemetry req error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
	if s.telemetryReferer != "" {
		req.Header.Set("Referer", s.telemetryReferer)
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Client-Instance-Id", uuid.New().String())
	req.Header.Set("X-Telemost-Client-Version", "187.1.0")
	req.Header.Set("Idempotency-Key", uuid.New().String())

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		logger.Verbosef("Telemetry send error: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

func goolomCapabilitiesOffer() map[string]any {
	return map[string]any{
		"offerAnswerMode":        []string{"SEPARATE"},
		"initialSubscriberOffer": []string{"ON_HELLO"},
		"slotsMode":              []string{"FROM_CONTROLLER"},
		"simulcastMode":          []string{"DISABLED", "STATIC"},
		"selfVadStatus":          []string{"FROM_SERVER", "FROM_CLIENT"},
		"dataChannelSharing":     []string{"TO_RTP"},
		"videoEncoderConfig":     []string{"NO_CONFIG", "ONLY_INIT_CONFIG", "RUNTIME_CONFIG"},
		"dataChannelVideoCodec":  []string{"VP8", "UNIQUE_CODEC_FROM_TRACK_DESCRIPTION"},
		"bandwidthLimitationReason": []string{
			"BANDWIDTH_REASON_DISABLED",
			"BANDWIDTH_REASON_ENABLED",
		},
		"sdkDefaultDeviceManagement": []string{
			"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED",
			"SDK_DEFAULT_DEVICE_MANAGEMENT_ENABLED",
		},
		"joinOrderLayout": []string{"JOIN_ORDER_LAYOUT_DISABLED", "JOIN_ORDER_LAYOUT_ENABLED"},
		"pinLayout":       []string{"PIN_LAYOUT_DISABLED"},
		"sendSelfViewVideoSlot": []string{
			"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED",
			"SEND_SELF_VIEW_VIDEO_SLOT_ENABLED",
		},
		"serverLayoutTransition": []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
		"sdkPublisherOptimizeBitrate": []string{
			"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED",
			"SDK_PUBLISHER_OPTIMIZE_BITRATE_FULL",
			"SDK_PUBLISHER_OPTIMIZE_BITRATE_ONLY_SELF",
		},
		"sdkNetworkLostDetection": []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
		"sdkNetworkPathMonitor":   []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
		"publisherVp9":            []string{"PUBLISH_VP9_DISABLED", "PUBLISH_VP9_ENABLED"},
		"svcMode":                 []string{"SVC_MODE_DISABLED", "SVC_MODE_L3T3", "SVC_MODE_L3T3_KEY"},
		"subscriberOfferAsyncAck": []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED", "SUBSCRIBER_OFFER_ASYNC_ACK_ENABLED"},
		"androidBluetoothRoutingFix": []string{
			"ANDROID_BLUETOOTH_ROUTING_FIX_DISABLED",
		},
		"fixedIceCandidatesPoolSize": []string{
			"FIXED_ICE_CANDIDATES_POOL_SIZE_DISABLED",
		},
		"sdkAndroidTelecomIntegration": []string{
			"SDK_ANDROID_TELECOM_INTEGRATION_DISABLED",
		},
		"setActiveCodecsMode": []string{
			"SET_ACTIVE_CODECS_MODE_DISABLED",
			"SET_ACTIVE_CODECS_MODE_VIDEO_ONLY",
		},
		"subscriberDtlsPassiveMode": []string{
			"SUBSCRIBER_DTLS_PASSIVE_MODE_DISABLED",
		},
		"publisherOpusDred": []string{
			"PUBLISHER_OPUS_DRED_DISABLED",
		},
		"publisherOpusLowBitrate": []string{
			"PUBLISHER_OPUS_LOW_BITRATE_DISABLED",
		},
		"sdkAndroidDestroySessionOnTaskRemoved": []string{
			"SDK_ANDROID_DESTROY_SESSION_ON_TASK_REMOVED_DISABLED",
		},
		"svcModes":                []string{"FALSE"},
		"reportTelemetryModes":    []string{"TRUE"},
		"keepDefaultDevicesModes": []string{"FALSE"},
	}
}
