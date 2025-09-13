// Package sush implements the Sush proxy protocol for Xray-core
package sush

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

const (
	// Version represents the Sush protocol version
	Version = "1.0.0"
)

// InboundConfig represents the inbound configuration for Sush
type InboundConfig struct {
	Users           []*User               `protobuf:"bytes,1,rep,name=clients,proto3" json:"clients,omitempty"`
	Fallbacks       []*Fallback           `protobuf:"bytes,2,rep,name=fallbacks,proto3" json:"fallbacks,omitempty"`
	TrafficShaping  *TrafficShapingConfig `protobuf:"bytes,3,opt,name=traffic_shaping,json=trafficShaping,proto3" json:"traffic_shaping,omitempty"`
	HandshakeConfig *HandshakeConfig      `protobuf:"bytes,4,opt,name=handshake_config,json=handshakeConfig,proto3" json:"handshake_config,omitempty"`
}

// OutboundConfig represents the outbound configuration for Sush
type OutboundConfig struct {
	Vnext []*ServerEndpoint `protobuf:"bytes,1,rep,name=vnext,proto3" json:"vnext,omitempty"`
}

// User represents a Sush user
type User struct {
	Id     string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Level  uint32 `protobuf:"varint,2,opt,name=level,proto3" json:"level,omitempty"`
	Policy string `protobuf:"bytes,3,opt,name=policy,proto3" json:"policy,omitempty"`
	Psk    string `protobuf:"bytes,4,opt,name=psk,proto3" json:"psk,omitempty"`
}

// Fallback represents fallback configuration
type Fallback struct {
	Dest string   `protobuf:"bytes,1,opt,name=dest,proto3" json:"dest,omitempty"`
	Alpn []string `protobuf:"bytes,2,rep,name=alpn,proto3" json:"alpn,omitempty"`
	Path string   `protobuf:"bytes,3,opt,name=path,proto3" json:"path,omitempty"`
	Name string   `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
}

// ServerEndpoint represents a server endpoint
type ServerEndpoint struct {
	Address string  `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port    uint32  `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Users   []*User `protobuf:"bytes,3,rep,name=users,proto3" json:"users,omitempty"`
}

// HandshakeConfig contains HTTP handshake customization settings
type HandshakeConfig struct {
	// Custom HTTP headers to avoid fingerprinting
	Headers          map[string]string `protobuf:"bytes,1,rep,name=headers,proto3" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	UserAgent        string            `protobuf:"bytes,2,opt,name=user_agent,json=userAgent,proto3" json:"user_agent,omitempty"`
	Host             string            `protobuf:"bytes,3,opt,name=host,proto3" json:"host,omitempty"`
	Method           string            `protobuf:"bytes,4,opt,name=method,proto3" json:"method,omitempty"`
	Path             string            `protobuf:"bytes,5,opt,name=path,proto3" json:"path,omitempty"`
	HttpVersion      string            `protobuf:"bytes,6,opt,name=http_version,json=httpVersion,proto3" json:"http_version,omitempty"`
	ConnectionHeader string            `protobuf:"bytes,7,opt,name=connection_header,json=connectionHeader,proto3" json:"connection_header,omitempty"`
}

// TrafficShapingConfig contains traffic shaping parameters
type TrafficShapingConfig struct {
	EnableMorphing  bool    `protobuf:"varint,1,opt,name=enable_morphing,json=enableMorphing,proto3" json:"enable_morphing,omitempty"`
	Profile         string  `protobuf:"bytes,2,opt,name=profile,proto3" json:"profile,omitempty"`
	MinPacketSize   int32   `protobuf:"varint,3,opt,name=min_packet_size,json=minPacketSize,proto3" json:"min_packet_size,omitempty"`
	MaxPacketSize   int32   `protobuf:"varint,4,opt,name=max_packet_size,json=maxPacketSize,proto3" json:"max_packet_size,omitempty"`
	MinDelayMs      int64   `protobuf:"varint,5,opt,name=min_delay_ms,json=minDelayMs,proto3" json:"min_delay_ms,omitempty"`
	MaxDelayMs      int64   `protobuf:"varint,6,opt,name=max_delay_ms,json=maxDelayMs,proto3" json:"max_delay_ms,omitempty"`
	BurstMultiplier float64 `protobuf:"fixed64,7,opt,name=burst_multiplier,json=burstMultiplier,proto3" json:"burst_multiplier,omitempty"`
	DirectionBias   float64 `protobuf:"fixed64,8,opt,name=direction_bias,json=directionBias,proto3" json:"direction_bias,omitempty"`
	JitterPercent   float64 `protobuf:"fixed64,9,opt,name=jitter_percent,json=jitterPercent,proto3" json:"jitter_percent,omitempty"`
}

// Account represents a Sush account
type Account struct {
	Id           string            `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Policy       string            `protobuf:"bytes,2,opt,name=policy,proto3" json:"policy,omitempty"`
	CustomParams map[string]string `protobuf:"bytes,3,rep,name=custom_params,json=customParams,proto3" json:"custom_params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}
