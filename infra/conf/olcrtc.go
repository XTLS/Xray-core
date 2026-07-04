package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/olcrtc"
	"google.golang.org/protobuf/proto"
)

// OLCRTCVP8Config tunes the vp8channel transport.
type OLCRTCVP8Config struct {
	FPS       int32 `json:"fps"`
	BatchSize int32 `json:"batchSize"`
}

// OLCRTCSEIConfig tunes the seichannel transport.
type OLCRTCSEIConfig struct {
	FPS          int32 `json:"fps"`
	BatchSize    int32 `json:"batchSize"`
	FragmentSize int32 `json:"fragmentSize"`
	AckTimeoutMs int32 `json:"ackTimeoutMs"`
}

// OLCRTCVideoConfig tunes the videochannel transport.
type OLCRTCVideoConfig struct {
	Width      int32  `json:"width"`
	Height     int32  `json:"height"`
	FPS        int32  `json:"fps"`
	Bitrate    string `json:"bitrate"`
	HW         string `json:"hw"`
	QRSize     int32  `json:"qrSize"`
	QRRecovery string `json:"qrRecovery"`
	Codec      string `json:"codec"`
	TileModule int32  `json:"tileModule"`
	TileRS     int32  `json:"tileRs"`
}

// olcrtcCommon holds the fields shared by the olcrtc inbound and outbound JSON
// configs.
type olcrtcCommon struct {
	Provider  string `json:"provider"`
	Transport string `json:"transport"`
	RoomID    string `json:"roomId"`
	Key       string `json:"key"`
	DNSServer string `json:"dnsServer"`
	AuthToken string `json:"authToken"`

	Engine string `json:"engine"`
	URL    string `json:"url"`
	Token  string `json:"token"`

	VP8   *OLCRTCVP8Config   `json:"vp8"`
	SEI   *OLCRTCSEIConfig   `json:"sei"`
	Video *OLCRTCVideoConfig `json:"video"`

	LivenessInterval   string `json:"livenessInterval"`
	LivenessTimeout    string `json:"livenessTimeout"`
	LivenessFailures   int32  `json:"livenessFailures"`
	MaxSessionDuration string `json:"maxSessionDuration"`
}

// OLCRTCServerConfig is the JSON config for the olcrtc inbound (server).
type OLCRTCServerConfig struct {
	olcrtcCommon
}

// OLCRTCClientConfig is the JSON config for the olcrtc outbound (client).
type OLCRTCClientConfig struct {
	olcrtcCommon
	DeviceID     string `json:"deviceId"`
	DeviceIDPath string `json:"deviceIdPath"`
}

func (c *olcrtcCommon) validate() error {
	if c.Provider == "" {
		return errors.New("olcrtc: provider is required (jitsi, telemost, wbstream or none)")
	}
	if c.Transport == "" {
		return errors.New("olcrtc: transport is required (datachannel, vp8channel, seichannel or videochannel)")
	}
	if c.Key == "" {
		return errors.New("olcrtc: key is required (64 hex chars)")
	}
	return nil
}

func (c *olcrtcCommon) vp8() (int32, int32) {
	if c.VP8 == nil {
		return 0, 0
	}
	return c.VP8.FPS, c.VP8.BatchSize
}

func (c *olcrtcCommon) sei() (int32, int32, int32, int32) {
	if c.SEI == nil {
		return 0, 0, 0, 0
	}
	return c.SEI.FPS, c.SEI.BatchSize, c.SEI.FragmentSize, c.SEI.AckTimeoutMs
}

func (c *olcrtcCommon) video() OLCRTCVideoConfig {
	if c.Video == nil {
		return OLCRTCVideoConfig{}
	}
	return *c.Video
}

// Build implements Buildable.
func (c *OLCRTCServerConfig) Build() (proto.Message, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	vfps, vbatch := c.vp8()
	sfps, sbatch, sfrag, sack := c.sei()
	v := c.video()
	return &olcrtc.ServerConfig{
		Provider:           c.Provider,
		Transport:          c.Transport,
		RoomId:             c.RoomID,
		Key:                c.Key,
		DnsServer:          c.DNSServer,
		AuthToken:          c.AuthToken,
		Engine:             c.Engine,
		Url:                c.URL,
		Token:              c.Token,
		Vp8Fps:             vfps,
		Vp8BatchSize:       vbatch,
		SeiFps:             sfps,
		SeiBatchSize:       sbatch,
		SeiFragmentSize:    sfrag,
		SeiAckTimeoutMs:    sack,
		VideoWidth:         v.Width,
		VideoHeight:        v.Height,
		VideoFps:           v.FPS,
		VideoBitrate:       v.Bitrate,
		VideoHw:            v.HW,
		VideoQrSize:        v.QRSize,
		VideoQrRecovery:    v.QRRecovery,
		VideoCodec:         v.Codec,
		VideoTileModule:    v.TileModule,
		VideoTileRs:        v.TileRS,
		LivenessInterval:   c.LivenessInterval,
		LivenessTimeout:    c.LivenessTimeout,
		LivenessFailures:   c.LivenessFailures,
		MaxSessionDuration: c.MaxSessionDuration,
	}, nil
}

// Build implements Buildable.
func (c *OLCRTCClientConfig) Build() (proto.Message, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	vfps, vbatch := c.vp8()
	sfps, sbatch, sfrag, sack := c.sei()
	v := c.video()
	return &olcrtc.ClientConfig{
		Provider:           c.Provider,
		Transport:          c.Transport,
		RoomId:             c.RoomID,
		Key:                c.Key,
		DnsServer:          c.DNSServer,
		AuthToken:          c.AuthToken,
		Engine:             c.Engine,
		Url:                c.URL,
		Token:              c.Token,
		Vp8Fps:             vfps,
		Vp8BatchSize:       vbatch,
		SeiFps:             sfps,
		SeiBatchSize:       sbatch,
		SeiFragmentSize:    sfrag,
		SeiAckTimeoutMs:    sack,
		VideoWidth:         v.Width,
		VideoHeight:        v.Height,
		VideoFps:           v.FPS,
		VideoBitrate:       v.Bitrate,
		VideoHw:            v.HW,
		VideoQrSize:        v.QRSize,
		VideoQrRecovery:    v.QRRecovery,
		VideoCodec:         v.Codec,
		VideoTileModule:    v.TileModule,
		VideoTileRs:        v.TileRS,
		LivenessInterval:   c.LivenessInterval,
		LivenessTimeout:    c.LivenessTimeout,
		LivenessFailures:   c.LivenessFailures,
		MaxSessionDuration: c.MaxSessionDuration,
		DeviceId:           c.DeviceID,
		DeviceIdPath:       c.DeviceIDPath,
	}, nil
}
