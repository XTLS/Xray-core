package goolom

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/logger"
	"github.com/pion/webrtc/v4"
)

func (s *Session) setupDataChannelHandlers(dcReady chan struct{}, sessionCloseCh chan struct{}) {
	s.dc.OnOpen(func() {
		numWorkers := 4
		for i := range numWorkers {
			s.wg.Add(1)
			go func(workerID int) {
				defer s.wg.Done()
				s.processSendQueue(workerID, sessionCloseCh)
			}(i)
		}
		close(dcReady)
	})

	s.dc.OnClose(s.onDataChannelClose)
	s.dc.OnMessage(s.onDataChannelMessage)

	s.pcSub.OnDataChannel(func(dc *webrtc.DataChannel) {
		if s.onData != nil {
			dc.OnMessage(s.onDataChannelMessage)
		}
	})
}

func (s *Session) onDataChannelClose() {
	if !s.closed.Load() {
		s.queueReconnect()
	}
}

func (s *Session) onDataChannelMessage(msg webrtc.DataChannelMessage) {
	if s.onData != nil && len(msg.Data) > 0 {
		s.onData(msg.Data)
	}
}

func (s *Session) handleSdpOffer(offer map[string]any, uid string, sendPub bool) error {
	sdp, _ := offer["sdp"].(string)
	pcSeq, _ := offer["pcSeq"].(float64)

	if err := s.pcSub.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdp,
	}); err != nil {
		return fmt.Errorf("set remote desc: %w", err)
	}

	answer, err := s.pcSub.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}

	if err := s.pcSub.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local desc: %w", err)
	}

	s.wsMu.Lock()
	_ = s.ws.WriteJSON(map[string]any{
		keyUID: uuid.New().String(),
		"subscriberSdpAnswer": map[string]any{
			keyPcSeq: int(pcSeq),
			"sdp":    answer.SDP,
		},
	})
	s.wsMu.Unlock()

	s.sendAck(uid)

	if s.onData == nil {
		if err := s.sendSetSlots(); err != nil {
			logger.Debugf("setSlots error: %v", err)
		}
	}

	if !sendPub {
		return nil
	}

	time.Sleep(300 * time.Millisecond)

	pubOffer, err := s.pcPub.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create pub offer: %w", err)
	}
	if err := s.pcPub.SetLocalDescription(pubOffer); err != nil {
		return fmt.Errorf("set local pub desc: %w", err)
	}

	s.wsMu.Lock()
	_ = s.ws.WriteJSON(map[string]any{
		keyUID: uuid.New().String(),
		"publisherSdpOffer": map[string]any{
			keyPcSeq: 1,
			"sdp":    pubOffer.SDP,
			"tracks": s.publisherTrackDescriptions(),
		},
	})
	s.wsMu.Unlock()
	return nil
}

func (s *Session) handleSdpAnswer(answer map[string]any, uid string) {
	sdp, _ := answer["sdp"].(string)
	if err := s.pcPub.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdp,
	}); err != nil {
		logger.Debugf("SetRemoteDescription error: %v", err)
	}
	s.sendAck(uid)
}

func (s *Session) handleICE(cand map[string]any) {
	candStr, _ := cand["candidate"].(string)
	target, _ := cand["target"].(string)
	sdpMid, _ := cand["sdpMid"].(string)
	sdpMLineIndex, _ := cand["sdpMlineIndex"].(float64)

	parts := strings.Fields(candStr)
	if len(parts) < 8 {
		return
	}

	init := webrtc.ICECandidateInit{
		Candidate:     candStr,
		SDPMid:        &sdpMid,
		SDPMLineIndex: func() *uint16 { v := uint16(sdpMLineIndex); return &v }(),
	}
	switch target {
	case "SUBSCRIBER":
		_ = s.pcSub.AddICECandidate(init)
	case "PUBLISHER":
		_ = s.pcPub.AddICECandidate(init)
	}
}

func (s *Session) setupICEHandlers() {
	s.pcSub.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		s.wsMu.Lock()
		_ = s.ws.WriteJSON(map[string]any{
			keyUID: uuid.New().String(),
			"webrtcIceCandidate": map[string]any{
				"candidate":     init.Candidate,
				"sdpMid":        init.SDPMid,
				"sdpMlineIndex": init.SDPMLineIndex,
				"target":        "SUBSCRIBER",
				keyPcSeq:        1,
			},
		})
		s.wsMu.Unlock()
	})

	s.pcPub.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		s.wsMu.Lock()
		_ = s.ws.WriteJSON(map[string]any{
			keyUID: uuid.New().String(),
			"webrtcIceCandidate": map[string]any{
				"candidate":     init.Candidate,
				"sdpMid":        init.SDPMid,
				"sdpMlineIndex": init.SDPMLineIndex,
				"target":        "PUBLISHER",
				keyPcSeq:        1,
			},
		})
		s.wsMu.Unlock()
	})
}

func (s *Session) sendSetSlots() error {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	// Goolom only forwards as many remote videos as the subscriber asks for via
	// setSlots. Request a generous count so each subscriber sees every active
	// publisher in the room.
	slots := make([]map[string]int, 0, 8)
	for range 8 {
		slots = append(slots, map[string]int{"width": 1280, "height": 720})
	}
	if err := s.ws.WriteJSON(map[string]any{
		keyUID: uuid.New().String(),
		"setSlots": map[string]any{
			"slots":              slots,
			"audioSlotsCount":    0,
			"key":                1,
			"shutdownAllVideo":   nil,
			"withSelfView":       false,
			"selfViewVisibility": "ON_LOADING_THEN_SHOW",
			"gridConfig":         map[string]any{},
		},
	}); err != nil {
		return fmt.Errorf("write set slots: %w", err)
	}
	return nil
}

func (s *Session) publisherTrackDescriptions() []map[string]any {
	if s.pcPub == nil {
		return nil
	}
	tracks := make([]map[string]any, 0)
	for _, transceiver := range s.pcPub.GetTransceivers() {
		sender := transceiver.Sender()
		if sender == nil {
			continue
		}
		track := sender.Track()
		if track == nil {
			continue
		}
		kind := "VIDEO"
		if track.Kind() == webrtc.RTPCodecTypeAudio {
			kind = "AUDIO"
		}
		tracks = append(tracks, map[string]any{
			"mid":            transceiver.Mid(),
			"transceiverMid": transceiver.Mid(),
			"kind":           kind,
			"priority":       0,
			"label":          track.ID(),
			"codecs":         map[string]any{},
			"groupId":        1,
			keyDescription:   "",
		})
	}
	return tracks
}

// isICEURL reports whether url is a usable ICE server URL. It keeps every
// standard ICE scheme - STUN and TURN alike. Earlier code stripped turn:/
// turns: relays and kept only STUN, which left clients behind symmetric or
// CGNAT carriers (e.g. mobile Tele2) with no working candidate pair: the
// server-reflexive path comes up for a few seconds, then ICE consent can no
// longer be refreshed without a relay and the SFU tears the session down
// (issue #95). Keeping the advertised TURN relays restores a stable path.
func isICEURL(url string) bool {
	return strings.HasPrefix(url, "stun:") ||
		strings.HasPrefix(url, "stuns:") ||
		strings.HasPrefix(url, "turn:") ||
		strings.HasPrefix(url, "turns:")
}

func parseICEURLs(server map[string]any) []string {
	var urls []string
	switch rawURLs := server["urls"].(type) {
	case []any:
		for _, rawURL := range rawURLs {
			if url, ok := rawURL.(string); ok && isICEURL(url) {
				urls = append(urls, url)
			}
		}
	case []string:
		for _, url := range rawURLs {
			if isICEURL(url) {
				urls = append(urls, url)
			}
		}
	}
	return urls
}

func parseICEServer(rawServer any) (webrtc.ICEServer, bool) {
	server, ok := rawServer.(map[string]any)
	if !ok {
		return webrtc.ICEServer{}, false
	}
	urls := parseICEURLs(server)
	if len(urls) == 0 {
		return webrtc.ICEServer{}, false
	}
	ice := webrtc.ICEServer{URLs: urls}
	if username, ok := server["username"].(string); ok {
		ice.Username = username
	}
	if credential, ok := server["credential"].(string); ok {
		ice.Credential = credential
	}
	return ice, true
}

func (s *Session) applyServerHelloConfig(serverHello map[string]any) {
	rawCfg, ok := serverHello["rtcConfiguration"].(map[string]any)
	if !ok {
		return
	}
	rawServers, ok := rawCfg["iceServers"].([]any)
	if !ok || len(rawServers) == 0 {
		return
	}
	iceServers := make([]webrtc.ICEServer, 0, len(rawServers))
	for _, rawServer := range rawServers {
		if ice, ok := parseICEServer(rawServer); ok {
			iceServers = append(iceServers, ice)
		}
	}
	if len(iceServers) == 0 {
		return
	}
	cfg := webrtc.Configuration{
		ICEServers:   iceServers,
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlan,
	}
	if s.pcSub != nil {
		_ = s.pcSub.SetConfiguration(cfg)
	}
	if s.pcPub != nil {
		_ = s.pcPub.SetConfiguration(cfg)
	}
}
