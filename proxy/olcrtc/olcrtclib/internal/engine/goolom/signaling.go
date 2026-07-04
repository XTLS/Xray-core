package goolom

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
)

func (s *Session) sendHello() error {
	hello := map[string]any{
		keyUID: uuid.New().String(),
		"hello": map[string]any{
			"participantMeta": map[string]any{
				keyName:        s.name,
				"role":         "SPEAKER",
				keyDescription: "",
				"sendAudio":    false,
				"sendVideo":    s.hasLocalVideoTracks(),
			},
			"participantAttributes": map[string]any{
				keyName:        s.name,
				"role":         "SPEAKER",
				keyDescription: "",
			},
			"sendAudio":         false,
			"sendVideo":         s.hasLocalVideoTracks(),
			"sendSharing":       false,
			"participantId":     s.peerID,
			"roomId":            s.roomID,
			"serviceName":       "telemost",
			"credentials":       s.credentials,
			"capabilitiesOffer": goolomCapabilitiesOffer(),
			"sdkInfo": map[string]any{
				"implementation": "browser",
				"version":        "5.27.0",
				"userAgent":      "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
				"hwConcurrency":  runtime.NumCPU(),
			},
			"sdkInitializationId":    uuid.New().String(),
			"disablePublisher":       !s.hasLocalVideoTracks(),
			"disableSubscriber":      false,
			"disableSubscriberAudio": true,
		},
	}

	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if err := s.ws.WriteJSON(hello); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}
	return nil
}

func (s *Session) handleSignaling(ctx context.Context) {
	pubSent := false

	for {
		var msg map[string]any
		if err := s.ws.ReadJSON(&msg); err != nil {
			if !s.closed.Load() {
				logger.Debugf("ws read error: %v", err)
				s.queueReconnect()
			}
			return
		}
		s.updateWSDeadline()

		uid, _ := msg[keyUID].(string)
		s.handleMessageEvents(ctx, msg, uid)

		if isConferenceEndMessage(msg) {
			s.signalEnded("conference ended")
			return
		}

		if offer, ok := msg["subscriberSdpOffer"].(map[string]any); ok {
			if err := s.handleSdpOffer(offer, uid, !pubSent); err != nil {
				logger.Debugf("sdp offer error: %v", err)
				continue
			}
			pubSent = true
		}

		s.handleSignalingResponses(msg, uid)
	}
}

func (s *Session) handleMessageEvents(ctx context.Context, msg map[string]any, uid string) {
	if _, ok := msg["ack"]; ok {
		s.resolveAck(uid)
	}

	if serverHello, ok := msg["serverHello"].(map[string]any); ok {
		s.applyServerHelloConfig(serverHello)
		s.startTelemetry(ctx, serverHello)
		s.sendAck(uid)
	}

	s.handleCommonMessages(msg, uid)
}

func (s *Session) handleSignalingResponses(msg map[string]any, uid string) {
	if answer, ok := msg["publisherSdpAnswer"].(map[string]any); ok {
		s.handleSdpAnswer(answer, uid)
	}
	if cand, ok := msg["webrtcIceCandidate"].(map[string]any); ok {
		s.handleICE(cand)
	}
}

func (s *Session) updateWSDeadline() {
	s.wsMu.Lock()
	if s.ws != nil {
		_ = s.ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	}
	s.wsMu.Unlock()
}

func (s *Session) handleCommonMessages(msg map[string]any, uid string) {
	if _, ok := msg["updateDescription"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["upsertDescription"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["removeDescription"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["slotsConfig"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["slotsMeta"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["vadActivity"]; ok {
		s.sendAck(uid)
	}
	if _, ok := msg["ping"]; ok {
		s.sendPong(uid)
	}
	if _, ok := msg["pong"]; ok {
		s.sendAck(uid)
	}
}

func (s *Session) sendAck(uid string) {
	if uid == "" {
		return
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	_ = s.ws.WriteJSON(map[string]any{
		keyUID: uid,
		"ack": map[string]any{
			"status": map[string]any{"code": "OK"},
		},
	})
}

func (s *Session) sendPong(uid string) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	_ = s.ws.WriteJSON(map[string]any{
		keyUID:  uid,
		"pong":  map[string]any{},
	})
}

func (s *Session) registerAckWaiter(uid string) chan struct{} {
	ch := make(chan struct{})
	s.ackMu.Lock()
	s.ackWaiters[uid] = ch
	s.ackMu.Unlock()
	return ch
}

func (s *Session) removeAckWaiter(uid string) {
	s.ackMu.Lock()
	delete(s.ackWaiters, uid)
	s.ackMu.Unlock()
}

func (s *Session) waitForAck(uid string, ch <-chan struct{}, timeout time.Duration) bool {
	if uid == "" {
		return false
	}
	defer s.removeAckWaiter(uid)

	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	case <-s.closeCh:
		return false
	}
}

func (s *Session) resolveAck(uid string) {
	if uid == "" {
		return
	}
	s.ackMu.Lock()
	ch := s.ackWaiters[uid]
	if ch != nil {
		delete(s.ackWaiters, uid)
		close(ch)
	}
	s.ackMu.Unlock()
}

func (s *Session) sendLeave(uid string) bool {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	if s.ws == nil {
		return false
	}
	leave := map[string]any{
		keyUID:  uid,
		"leave": map[string]any{},
	}
	if err := s.ws.WriteJSON(leave); err != nil {
		return false
	}
	return true
}

func (s *Session) keepAlive(keepAliveCh <-chan struct{}) {
	wsTicker := time.NewTicker(30 * time.Second)
	defer wsTicker.Stop()
	appTicker := time.NewTicker(5 * time.Second)
	defer appTicker.Stop()

	for {
		select {
		case <-wsTicker.C:
			if !s.sendWSPing() {
				return
			}
		case <-appTicker.C:
			if !s.sendAppPing() {
				return
			}
		case <-keepAliveCh:
			return
		case <-s.closeCh:
			return
		}
	}
}

func (s *Session) sendWSPing() bool {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.ws != nil {
		if err := s.ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
			logger.Debugf("ws ping error: %v", err)
			s.queueReconnect()
			return false
		}
	}
	return true
}

func (s *Session) sendAppPing() bool {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.ws != nil {
		if err := s.ws.WriteJSON(map[string]any{
			keyUID: uuid.New().String(),
			"ping": map[string]any{},
		}); err != nil {
			logger.Debugf("app ping error: %v", err)
			s.queueReconnect()
			return false
		}
	}
	return true
}

func isConferenceEndMessage(msg map[string]any) bool {
	for _, key := range []string{"conferenceClosed", "conferenceEnded", "roomClosed", "roomEnded", "callEnded"} {
		if _, ok := msg[key]; ok {
			return true
		}
	}
	if raw, ok := msg["conference"].(map[string]any); ok {
		if state, _ := raw["state"].(string); isEndedState(state) {
			return true
		}
	}
	if raw, ok := msg["conferenceState"].(map[string]any); ok {
		if state, _ := raw["state"].(string); isEndedState(state) {
			return true
		}
	}
	return false
}

func isEndedState(state string) bool {
	switch strings.ToLower(state) {
	case "closed", "ended", "finished", stateTerminated:
		return true
	default:
		return false
	}
}
