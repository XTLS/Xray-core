package conf

import (
	"encoding/json"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

type NoOpConnectionAuthenticator struct{}

func (NoOpConnectionAuthenticator) Build() (proto.Message, error) {
	return new(noop.ConnectionConfig), nil
}

type AuthenticatorRequest struct {
	Version string                 `json:"version"`
	Method  string                 `json:"method"`
	Path    StringList             `json:"path"`
	Headers map[string]*StringList `json:"headers"`
}

func sortMapKeys(m map[string]*StringList) []string {
	var keys []string
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (v *AuthenticatorRequest) Build() (*http.RequestConfig, error) {
	config := &http.RequestConfig{
		Uri: []string{"/"},
		Header: []*http.Header{
			{
				Name:  "Host",
				Value: []string{"www.baidu.com", "www.bing.com"},
			},
			{
				Name:  "User-Agent",
				Value: []string{utils.ChromeUA},
			},
			{
				Name:  "Sec-CH-UA",
				Value: []string{utils.ChromeUACH},
			},
			{
				Name:  "Sec-CH-UA-Mobile",
				Value: []string{"?0"},
			},
			{
				Name:  "Sec-CH-UA-Platform",
				Value: []string{"Windows"},
			},
			{
				Name:  "Sec-Fetch-Mode",
				Value: []string{"no-cors", "cors", "same-origin"},
			},
			{
				Name:  "Sec-Fetch-Dest",
				Value: []string{"empty"},
			},
			{
				Name:  "Sec-Fetch-Site",
				Value: []string{"none"},
			},
			{
				Name:  "Sec-Fetch-User",
				Value: []string{"?1"},
			},
			{
				Name:  "Accept-Encoding",
				Value: []string{"gzip, deflate"},
			},
			{
				Name:  "Connection",
				Value: []string{"keep-alive"},
			},
			{
				Name:  "Pragma",
				Value: []string{"no-cache"},
			},
		},
	}

	if len(v.Version) > 0 {
		config.Version = &http.Version{Value: v.Version}
	}

	if len(v.Method) > 0 {
		config.Method = &http.Method{Value: v.Method}
	}

	if len(v.Path) > 0 {
		config.Uri = append([]string(nil), v.Path...)
	}

	if len(v.Headers) > 0 {
		config.Header = make([]*http.Header, 0, len(v.Headers))
		headerNames := sortMapKeys(v.Headers)
		for _, key := range headerNames {
			value := v.Headers[key]
			if value == nil {
				return nil, errors.New("empty HTTP header value: " + key).AtError()
			}
			config.Header = append(config.Header, &http.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}

	return config, nil
}

type AuthenticatorResponse struct {
	Version string                 `json:"version"`
	Status  string                 `json:"status"`
	Reason  string                 `json:"reason"`
	Headers map[string]*StringList `json:"headers"`
}

func (v *AuthenticatorResponse) Build() (*http.ResponseConfig, error) {
	config := &http.ResponseConfig{
		Header: []*http.Header{
			{
				Name:  "Content-Type",
				Value: []string{"application/octet-stream", "video/mpeg"},
			},
			{
				Name:  "Transfer-Encoding",
				Value: []string{"chunked"},
			},
			{
				Name:  "Connection",
				Value: []string{"keep-alive"},
			},
			{
				Name:  "Pragma",
				Value: []string{"no-cache"},
			},
			{
				Name:  "Cache-Control",
				Value: []string{"private", "no-cache"},
			},
		},
	}

	if len(v.Version) > 0 {
		config.Version = &http.Version{Value: v.Version}
	}

	if len(v.Status) > 0 || len(v.Reason) > 0 {
		config.Status = &http.Status{
			Code:   "200",
			Reason: "OK",
		}
		if len(v.Status) > 0 {
			config.Status.Code = v.Status
		}
		if len(v.Reason) > 0 {
			config.Status.Reason = v.Reason
		}
	}

	if len(v.Headers) > 0 {
		config.Header = make([]*http.Header, 0, len(v.Headers))
		headerNames := sortMapKeys(v.Headers)
		for _, key := range headerNames {
			value := v.Headers[key]
			if value == nil {
				return nil, errors.New("empty HTTP header value: " + key).AtError()
			}
			config.Header = append(config.Header, &http.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}

	return config, nil
}

type Authenticator struct {
	Request  AuthenticatorRequest  `json:"request"`
	Response AuthenticatorResponse `json:"response"`
}

func (v *Authenticator) Build() (proto.Message, error) {
	config := new(http.Config)
	requestConfig, err := v.Request.Build()
	if err != nil {
		return nil, err
	}
	config.Request = requestConfig

	responseConfig, err := v.Response.Build()
	if err != nil {
		return nil, err
	}
	config.Response = responseConfig

	return config, nil
}

var tcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
	"none": func() interface{} { return new(NoOpConnectionAuthenticator) },
	"http": func() interface{} { return new(Authenticator) },
}, "type", "")

type TCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol"`
}

// Build implements Buildable.
func (c *TCPConfig) Build() (proto.Message, error) {
	config := new(tcp.Config)
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := tcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, errors.New("invalid TCP header config").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, errors.New("invalid TCP header config").Base(err).AtError()
		}
		config.HeaderSettings = serial.ToTypedMessage(ts)
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type SplitHTTPConfig struct {
	Host                 string            `json:"host"`
	Path                 string            `json:"path"`
	Mode                 string            `json:"mode"`
	Headers              map[string]string `json:"headers"`
	XPaddingBytes        Int32Range        `json:"xPaddingBytes"`
	XPaddingObfsMode     bool              `json:"xPaddingObfsMode"`
	XPaddingKey          string            `json:"xPaddingKey"`
	XPaddingHeader       string            `json:"xPaddingHeader"`
	XPaddingPlacement    string            `json:"xPaddingPlacement"`
	XPaddingMethod       string            `json:"xPaddingMethod"`
	UplinkHTTPMethod     string            `json:"uplinkHTTPMethod"`
	SessionIDPlacement   string            `json:"sessionIDPlacement"`
	SessionIDKey         string            `json:"sessionIDKey"`
	SessionIDTable       string            `json:"sessionIDTable"`
	SessionIDLength      Int32Range        `json:"sessionIDLength"`
	SeqPlacement         string            `json:"seqPlacement"`
	SeqKey               string            `json:"seqKey"`
	UplinkDataPlacement  string            `json:"uplinkDataPlacement"`
	UplinkDataKey        string            `json:"uplinkDataKey"`
	UplinkChunkSize      Int32Range        `json:"uplinkChunkSize"`
	NoGRPCHeader         bool              `json:"noGRPCHeader"`
	NoSSEHeader          bool              `json:"noSSEHeader"`
	ScMaxEachPostBytes   Int32Range        `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs Int32Range        `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64             `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs Int32Range        `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int32             `json:"serverMaxHeaderBytes"`
	Xmux                 XmuxConfig        `json:"xmux"`
	DownloadSettings     *StreamConfig     `json:"downloadSettings"`
	Extra                json.RawMessage   `json:"extra"`
}

type XmuxConfig struct {
	MaxConcurrency   Int32Range `json:"maxConcurrency"`
	MaxConnections   Int32Range `json:"maxConnections"`
	CMaxReuseTimes   Int32Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes Int32Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs Int32Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64      `json:"hKeepAlivePeriod"`
}

func newRangeConfig(input Int32Range) *splithttp.RangeConfig {
	return &splithttp.RangeConfig{
		From: input.From,
		To:   input.To,
	}
}

// Build implements Buildable.
func (c *SplitHTTPConfig) Build() (proto.Message, error) {
	if c.Extra != nil {
		var extra SplitHTTPConfig
		if err := json.Unmarshal(c.Extra, &extra); err != nil {
			return nil, errors.New(`Failed to unmarshal "extra".`).Base(err)
		}
		extra.Host = c.Host
		extra.Path = c.Path
		extra.Mode = c.Mode
		c = &extra
	}

	switch c.Mode {
	case "":
		c.Mode = "auto"
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, errors.New("unsupported mode: " + c.Mode)
	}

	// Priority (client): host > serverName > address
	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, errors.New(`"headers" can't contain "host"`)
		}
	}

	if c.XPaddingBytes != (Int32Range{}) && (c.XPaddingBytes.From <= 0 || c.XPaddingBytes.To <= 0) {
		return nil, errors.New("xPaddingBytes cannot be disabled")
	}

	if c.XPaddingKey == "" {
		c.XPaddingKey = "x_padding"
	}

	if c.XPaddingHeader == "" {
		c.XPaddingHeader = "X-Padding"
	}

	switch c.XPaddingPlacement {
	case "":
		c.XPaddingPlacement = "queryInHeader"
	case "cookie", "header", "query", "queryInHeader":
	default:
		return nil, errors.New("unsupported padding placement: " + c.XPaddingPlacement)
	}

	switch c.XPaddingMethod {
	case "":
		c.XPaddingMethod = "repeat-x"
	case "repeat-x", "tokenish":
	default:
		return nil, errors.New("unsupported padding method: " + c.XPaddingMethod)
	}

	switch c.UplinkDataPlacement {
	case "":
		c.UplinkDataPlacement = splithttp.PlacementAuto
	case splithttp.PlacementAuto, splithttp.PlacementBody:
	case splithttp.PlacementCookie, splithttp.PlacementHeader:
		if c.Mode != "packet-up" {
			return nil, errors.New("UplinkDataPlacement can be " + c.UplinkDataPlacement + " only in packet-up mode")
		}
	default:
		return nil, errors.New("unsupported uplink data placement: " + c.UplinkDataPlacement)
	}

	if c.UplinkHTTPMethod == "" {
		c.UplinkHTTPMethod = "POST"
	}
	c.UplinkHTTPMethod = strings.ToUpper(c.UplinkHTTPMethod)

	if c.UplinkHTTPMethod == "GET" && c.Mode != "packet-up" {
		return nil, errors.New("uplinkHTTPMethod can be GET only in packet-up mode")
	}

	switch c.SessionIDPlacement {
	case "":
		c.SessionIDPlacement = "path"
	case "path", "cookie", "header", "query":
	default:
		return nil, errors.New("unsupported session placement: " + c.SessionIDPlacement)
	}

	switch c.SeqPlacement {
	case "":
		c.SeqPlacement = "path"
	case "path", "cookie", "header", "query":
	default:
		return nil, errors.New("unsupported seq placement: " + c.SeqPlacement)
	}

	if c.SessionIDPlacement != "path" && c.SessionIDKey == "" {
		switch c.SessionIDPlacement {
		case "cookie", "query":
			c.SessionIDKey = "x_session"
		case "header":
			c.SessionIDKey = "X-Session"
		}
	}

	if c.SessionIDTable != "" {
		if predefined, ok := splithttp.PredefinedTable[c.SessionIDTable]; ok {
			c.SessionIDTable = predefined
		}
		room := roomSize(len(c.SessionIDTable), c.SessionIDLength.From, c.SessionIDLength.To)
		// 2.1B possiblities should be enough
		if room.Cmp(big.NewInt(2<<30)) < 0 {
			return nil, errors.New("sessionIDTable or sessionIDLength is too small")
		}
		if c.SessionIDLength.From <= 0 {
			return nil, errors.New("sessionIDLength.from must be greater than 0")
		}
		for i := 0; i < len(c.SessionIDTable); i++ {
			if c.SessionIDTable[i] >= 0x80 {
				return nil, errors.New("sessionIDTable must contain only ASCII characters")
			}
		}
	}

	if c.SeqPlacement != "path" && c.SeqKey == "" {
		switch c.SeqPlacement {
		case "cookie", "query":
			c.SeqKey = "x_seq"
		case "header":
			c.SeqKey = "X-Seq"
		}
	}

	if c.UplinkDataPlacement != splithttp.PlacementBody && c.UplinkDataKey == "" {
		switch c.UplinkDataPlacement {
		case splithttp.PlacementCookie:
			c.UplinkDataKey = "x_data"
		case splithttp.PlacementAuto, splithttp.PlacementHeader:
			c.UplinkDataKey = "X-Data"
		}
	}

	if c.ServerMaxHeaderBytes < 0 {
		return nil, errors.New("invalid negative value of maxHeaderBytes")
	}

	if c.Xmux.MaxConnections.To > 0 && c.Xmux.MaxConcurrency.To > 0 {
		return nil, errors.New("maxConnections cannot be specified together with maxConcurrency")
	}
	if c.Xmux == (XmuxConfig{}) {
		c.Xmux.MaxConnections.From = 6
		c.Xmux.MaxConnections.To = 6
		c.Xmux.HMaxRequestTimes.From = 600
		c.Xmux.HMaxRequestTimes.To = 900
		c.Xmux.HMaxReusableSecs.From = 1800
		c.Xmux.HMaxReusableSecs.To = 3000
	}

	config := &splithttp.Config{
		Host:                 c.Host,
		Path:                 c.Path,
		Mode:                 c.Mode,
		Headers:              c.Headers,
		XPaddingBytes:        newRangeConfig(c.XPaddingBytes),
		XPaddingObfsMode:     c.XPaddingObfsMode,
		XPaddingKey:          c.XPaddingKey,
		XPaddingHeader:       c.XPaddingHeader,
		XPaddingPlacement:    c.XPaddingPlacement,
		XPaddingMethod:       c.XPaddingMethod,
		UplinkHTTPMethod:     c.UplinkHTTPMethod,
		SessionIDPlacement:   c.SessionIDPlacement,
		SeqPlacement:         c.SeqPlacement,
		SessionIDKey:         c.SessionIDKey,
		SeqKey:               c.SeqKey,
		UplinkDataPlacement:  c.UplinkDataPlacement,
		UplinkDataKey:        c.UplinkDataKey,
		UplinkChunkSize:      newRangeConfig(c.UplinkChunkSize),
		NoGRPCHeader:         c.NoGRPCHeader,
		NoSSEHeader:          c.NoSSEHeader,
		ScMaxEachPostBytes:   newRangeConfig(c.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: newRangeConfig(c.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:   c.ScMaxBufferedPosts,
		ScStreamUpServerSecs: newRangeConfig(c.ScStreamUpServerSecs),
		ServerMaxHeaderBytes: c.ServerMaxHeaderBytes,
		SessionIDTable:       c.SessionIDTable,
		SessionIDLength:      newRangeConfig(c.SessionIDLength),
		Xmux: &splithttp.XmuxConfig{
			MaxConcurrency:   newRangeConfig(c.Xmux.MaxConcurrency),
			MaxConnections:   newRangeConfig(c.Xmux.MaxConnections),
			CMaxReuseTimes:   newRangeConfig(c.Xmux.CMaxReuseTimes),
			HMaxRequestTimes: newRangeConfig(c.Xmux.HMaxRequestTimes),
			HMaxReusableSecs: newRangeConfig(c.Xmux.HMaxReusableSecs),
			HKeepAlivePeriod: c.Xmux.HKeepAlivePeriod,
		},
	}

	if c.DownloadSettings != nil {
		if c.Mode == "stream-one" {
			return nil, errors.New(`Can not use "downloadSettings" in "stream-one" mode.`)
		}
		var err error
		if config.DownloadSettings, err = c.DownloadSettings.Build(); err != nil {
			return nil, errors.New(`Failed to build "downloadSettings".`).Base(err)
		}
	}

	return config, nil
}

func roomSize(tableSize int, min, max int32) *big.Int {
	base := big.NewInt(int64(tableSize))
	sum := new(big.Int)
	term := new(big.Int)
	for k := min; k <= max; k++ {
		term.Exp(base, big.NewInt(int64(k)), nil)
		sum.Add(sum, term)
	}
	return sum
}

type KCPConfig struct {
	Mtu              *uint32 `json:"mtu"`
	Tti              *uint32 `json:"tti"`
	UpCap            *uint32 `json:"uplinkCapacity"`
	DownCap          *uint32 `json:"downlinkCapacity"`
	CwndMultiplier   *uint32 `json:"cwndMultiplier"`
	MaxSendingWindow *uint32 `json:"maxSendingWindow"`

	HeaderConfig json.RawMessage `json:"header"`
	Seed         *string         `json:"seed"`
}

// Build implements Buildable.
func (c *KCPConfig) Build() (proto.Message, error) {
	config := common.Must2(internet.CreateTransportConfig(kcp.ProtocolName)).(*kcp.Config)

	if c.Mtu != nil {
		config.Mtu = *c.Mtu
	}
	if c.Tti != nil {
		config.Tti = *c.Tti
	}
	if c.UpCap != nil {
		config.UplinkCapacity = *c.UpCap
	}
	if c.DownCap != nil {
		config.DownlinkCapacity = *c.DownCap
	}
	if c.CwndMultiplier != nil {
		config.CwndMultiplier = *c.CwndMultiplier
	}
	if c.MaxSendingWindow != nil {
		config.MaxSendingWindow = *c.MaxSendingWindow
	}

	if config.Mtu < 21 {
		return nil, errors.New("MTU must be at least 21")
	}
	if config.Tti < 10 || config.Tti > 1000 {
		return nil, errors.New("TTI must be between 10 and 1000")
	}
	if config.CwndMultiplier < 1 {
		return nil, errors.New("CwndMultiplier must be at least 1")
	}
	if config.GetSendingBufferSize() == 0 {
		return nil, errors.New("MaxSendingWindow must be at least ", config.Mtu)
	}

	return config, nil
}

type GRPCConfig struct {
	Authority           string `json:"authority"`
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`
}

func (g *GRPCConfig) Build() (proto.Message, error) {
	if g.IdleTimeout <= 0 {
		g.IdleTimeout = 0
	}
	if g.HealthCheckTimeout <= 0 {
		g.HealthCheckTimeout = 0
	}
	if g.InitialWindowsSize < 0 {
		// default window size of gRPC-go
		g.InitialWindowsSize = 0
	}

	return &grpc.Config{
		Authority:           g.Authority,
		ServiceName:         g.ServiceName,
		MultiMode:           g.MultiMode,
		IdleTimeout:         g.IdleTimeout,
		HealthCheckTimeout:  g.HealthCheckTimeout,
		PermitWithoutStream: g.PermitWithoutStream,
		InitialWindowsSize:  g.InitialWindowsSize,
		UserAgent:           g.UserAgent,
	}, nil
}

type WebSocketConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
	HeartbeatPeriod     uint32            `json:"heartbeatPeriod"`
}

// Build implements Buildable.
func (c *WebSocketConfig) Build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			Ed, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(Ed)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	// Priority (client): host > serverName > address
	for k, v := range c.Headers {
		if strings.ToLower(k) == "host" {
			errors.PrintDeprecatedFeatureWarning(`"host" in "headers"`, `independent "host"`)
			if c.Host == "" {
				c.Host = v
			}
			delete(c.Headers, k)
		}
	}
	config := &websocket.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
		HeartbeatPeriod:     c.HeartbeatPeriod,
	}
	return config, nil
}

type HttpUpgradeConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
}

// Build implements Buildable.
func (c *HttpUpgradeConfig) Build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			Ed, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(Ed)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	// Priority (client): host > serverName > address
	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, errors.New(`"headers" can't contain "host"`)
		}
	}
	config := &httpupgrade.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
	}
	return config, nil
}

const (
	Byte     = 1
	Kilobyte = 1024 * Byte
	Megabyte = 1024 * Kilobyte
	Gigabyte = 1024 * Megabyte
	Terabyte = 1024 * Gigabyte
)

type Bandwidth string

func (b Bandwidth) Bps() (uint64, error) {
	s := strings.TrimSpace(strings.ToLower(string(b)))
	if s == "" {
		return 0, nil
	}

	idx := len(s)
	for i, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			idx = i
			break
		}
	}

	numStr := s[:idx]
	unit := strings.TrimSpace(s[idx:])

	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, err
	}

	mul := uint64(1)
	switch unit {
	case "", "b", "bps":
		mul = Byte
	case "k", "kb", "kbps":
		mul = Kilobyte
	case "m", "mb", "mbps":
		mul = Megabyte
	case "g", "gb", "gbps":
		mul = Gigabyte
	case "t", "tb", "tbps":
		mul = Terabyte
	default:
		return 0, errors.New("unsupported unit: " + unit)
	}

	return uint64(val*float64(mul)) / 8, nil
}

type Masquerade struct {
	Type string `json:"type"`

	Dir string `json:"dir"`

	Url         string `json:"url"`
	RewriteHost bool   `json:"rewriteHost"`
	Insecure    bool   `json:"insecure"`

	Content    string            `json:"content"`
	Headers    map[string]string `json:"headers"`
	StatusCode int32             `json:"statusCode"`
}

type HysteriaConfig struct {
	Version        int32      `json:"version"`
	Auth           string     `json:"auth"`
	UdpIdleTimeout int64      `json:"udpIdleTimeout"`
	Masquerade     Masquerade `json:"masquerade"`
}

func (c *HysteriaConfig) Build() (proto.Message, error) {
	if c.Version != 2 {
		return nil, errors.New("version != 2")
	}

	if c.UdpIdleTimeout != 0 && (c.UdpIdleTimeout < 2 || c.UdpIdleTimeout > 600) {
		return nil, errors.New("UdpIdleTimeout must be between 2 and 600")
	}

	config := &hysteria.Config{}
	config.Auth = c.Auth
	config.UdpIdleTimeout = c.UdpIdleTimeout
	config.MasqType = c.Masquerade.Type
	config.MasqFile = c.Masquerade.Dir
	config.MasqUrl = c.Masquerade.Url
	config.MasqUrlRewriteHost = c.Masquerade.RewriteHost
	config.MasqUrlInsecure = c.Masquerade.Insecure
	config.MasqString = c.Masquerade.Content
	config.MasqStringHeaders = c.Masquerade.Headers
	config.MasqStringStatusCode = c.Masquerade.StatusCode

	if config.UdpIdleTimeout == 0 {
		config.UdpIdleTimeout = 60
	}

	return config, nil
}

func readFileOrString(f string, s []string) ([]byte, error) {
	if len(f) > 0 {
		return filesystem.ReadCert(f)
	}
	if len(s) > 0 {
		return []byte(strings.Join(s, "\n")), nil
	}
	return nil, errors.New("both file and bytes are empty.")
}
