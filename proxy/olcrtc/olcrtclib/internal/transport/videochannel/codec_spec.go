package videochannel

import (
	"errors"
	"strings"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
)

// ErrUnexpectedFrameSize is returned when the raw frame size does not match expectations.
var ErrUnexpectedFrameSize = errors.New("unexpected encoder frame size")

// codecSpec describes a video codec used by videochannel: its WebRTC
// capability and the depacketizer for inbound RTP streams.
type codecSpec struct {
	mimeType     string
	capability   webrtc.RTPCodecCapability
	depacketizer func() rtp.Depacketizer
}

// codecSpecForCarrier returns the codec used to negotiate outbound video for
// the given carrier. Currently every carrier uses VP8.
func codecSpecForCarrier(_ string) codecSpec {
	return vp8CodecSpec()
}

// codecSpecForMime returns the codec spec matching a WebRTC MIME type
// reported by the remote peer.
func codecSpecForMime(mimeType string) (codecSpec, bool) {
	switch strings.ToLower(mimeType) {
	case strings.ToLower(webrtc.MimeTypeH264):
		return h264CodecSpec(), true
	case strings.ToLower(webrtc.MimeTypeVP9):
		return vp9CodecSpec(), true
	case strings.ToLower(webrtc.MimeTypeVP8):
		return vp8CodecSpec(), true
	default:
		return codecSpec{}, false
	}
}

func h264CodecSpec() codecSpec {
	return codecSpec{
		mimeType: webrtc.MimeTypeH264,
		capability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeH264,
			ClockRate: 90000,
		},
		depacketizer: func() rtp.Depacketizer { return &codecs.H264Packet{} },
	}
}

func vp9CodecSpec() codecSpec {
	return codecSpec{
		mimeType: webrtc.MimeTypeVP9,
		capability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP9,
			ClockRate: 90000,
		},
		depacketizer: func() rtp.Depacketizer { return &codecs.VP9Packet{} },
	}
}

func vp8CodecSpec() codecSpec {
	return codecSpec{
		mimeType: webrtc.MimeTypeVP8,
		capability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		depacketizer: func() rtp.Depacketizer { return &codecs.VP8Packet{} },
	}
}
