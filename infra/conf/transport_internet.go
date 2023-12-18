package conf

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/domainsocket"
	httpheader "github.com/xtls/xray-core/transport/internet/headers/http"
	"github.com/xtls/xray-core/transport/internet/http"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/quic"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

var (
	kcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none":         func() interface{} { return new(NoOpAuthenticator) },
		"srtp":         func() interface{} { return new(SRTPAuthenticator) },
		"utp":          func() interface{} { return new(UTPAuthenticator) },
		"wechat-video": func() interface{} { return new(WechatVideoAuthenticator) },
		"dtls":         func() interface{} { return new(DTLSAuthenticator) },
		"wireguard":    func() interface{} { return new(WireguardAuthenticator) },
		"dns":          func() interface{} { return new(DNSAuthenticator) },
	}, "type", "")

	tcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none": func() interface{} { return new(NoOpConnectionAuthenticator) },
		"http": func() interface{} { return new(Authenticator) },
	}, "type", "")
)

type KCPConfig struct {
	Mtu             *uint32         `json:"mtu,omitempty"`
	Tti             *uint32         `json:"tti,omitempty"`
	UpCap           *uint32         `json:"uplinkCapacity,omitempty"`
	DownCap         *uint32         `json:"downlinkCapacity,omitempty"`
	Congestion      *bool           `json:"congestion,omitempty"`
	ReadBufferSize  *uint32         `json:"readBufferSize,omitempty"`
	WriteBufferSize *uint32         `json:"writeBufferSize,omitempty"`
	HeaderConfig    json.RawMessage `json:"header,omitempty"`
	Seed            *string         `json:"seed,omitempty"`
}

// Build implements Buildable.
func (c *KCPConfig) Build() (proto.Message, error) {
	config := new(kcp.Config)

	if c.Mtu != nil {
		mtu := *c.Mtu
		if mtu < 576 || mtu > 1460 {
			return nil, newError("invalid mKCP MTU size: ", mtu).AtError()
		}
		config.Mtu = &kcp.MTU{Value: mtu}
	}
	if c.Tti != nil {
		tti := *c.Tti
		if tti < 10 || tti > 100 {
			return nil, newError("invalid mKCP TTI: ", tti).AtError()
		}
		config.Tti = &kcp.TTI{Value: tti}
	}
	if c.UpCap != nil {
		config.UplinkCapacity = &kcp.UplinkCapacity{Value: *c.UpCap}
	}
	if c.DownCap != nil {
		config.DownlinkCapacity = &kcp.DownlinkCapacity{Value: *c.DownCap}
	}
	if c.Congestion != nil {
		config.Congestion = *c.Congestion
	}
	if c.ReadBufferSize != nil {
		size := *c.ReadBufferSize
		if size > 0 {
			config.ReadBuffer = &kcp.ReadBuffer{Size: size * 1024 * 1024}
		} else {
			config.ReadBuffer = &kcp.ReadBuffer{Size: 512 * 1024}
		}
	}
	if c.WriteBufferSize != nil {
		size := *c.WriteBufferSize
		if size > 0 {
			config.WriteBuffer = &kcp.WriteBuffer{Size: size * 1024 * 1024}
		} else {
			config.WriteBuffer = &kcp.WriteBuffer{Size: 512 * 1024}
		}
	}
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, newError("invalid mKCP header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, newError("invalid mKCP header config").Base(err).AtError()
		}
		config.HeaderConfig = serial.ToTypedMessage(ts)
	}

	if c.Seed != nil {
		config.Seed = &kcp.EncryptionSeed{Seed: *c.Seed}
	}

	return config, nil
}

type TCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header,omitempty"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol,omitempty"`
}

// Build implements Buildable.
func (c *TCPConfig) Build() (proto.Message, error) {
	config := new(tcp.Config)
	if len(c.HeaderConfig) > 0 {
		headerConfig, _, err := tcpHeaderLoader.Load(c.HeaderConfig)
		if err != nil {
			return nil, newError("invalid TCP header config").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, newError("invalid TCP header config").Base(err).AtError()
		}
		config.HeaderSettings = serial.ToTypedMessage(ts)
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type WebSocketConfig struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol,omitempty"`
}

// Build implements Buildable.
func (c *WebSocketConfig) Build() (proto.Message, error) {
	path := c.Path
	header := make([]*websocket.Header, 0, 32)
	for key, value := range c.Headers {
		header = append(header, &websocket.Header{
			Key:   key,
			Value: value,
		})
	}
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
	config := &websocket.Config{
		Path:   path,
		Header: header,
		Ed:     ed,
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

type HTTPConfig struct {
	Host               *StringList            `json:"host,omitempty"`
	Path               string                 `json:"path,omitempty"`
	ReadIdleTimeout    int32                  `json:"read_idle_timeout,omitempty"`
	HealthCheckTimeout int32                  `json:"health_check_timeout,omitempty"`
	Method             string                 `json:"method,omitempty"`
	Headers            map[string]*StringList `json:"headers,omitempty"`
}

// Build implements Buildable.
func (c *HTTPConfig) Build() (proto.Message, error) {
	if c.ReadIdleTimeout <= 0 {
		c.ReadIdleTimeout = 0
	}
	if c.HealthCheckTimeout <= 0 {
		c.HealthCheckTimeout = 0
	}
	config := &http.Config{
		Path:               c.Path,
		IdleTimeout:        c.ReadIdleTimeout,
		HealthCheckTimeout: c.HealthCheckTimeout,
	}
	if c.Host != nil {
		config.Host = []string(*c.Host)
	}
	if c.Method != "" {
		config.Method = c.Method
	}
	if len(c.Headers) > 0 {
		config.Header = make([]*httpheader.Header, 0, len(c.Headers))
		headerNames := sortMapKeys(c.Headers)
		for _, key := range headerNames {
			value := c.Headers[key]
			if value == nil {
				return nil, newError("empty HTTP header value: " + key).AtError()
			}
			config.Header = append(config.Header, &httpheader.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}
	return config, nil
}

type QUICConfig struct {
	Header   json.RawMessage `json:"header,omitempty"`
	Security string          `json:"security,omitempty"`
	Key      string          `json:"key,omitempty"`
}

// Build implements Buildable.
func (c *QUICConfig) Build() (proto.Message, error) {
	config := &quic.Config{
		Key: c.Key,
	}

	if len(c.Header) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.Header)
		if err != nil {
			return nil, newError("invalid QUIC header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, newError("invalid QUIC header config").Base(err).AtError()
		}
		config.Header = serial.ToTypedMessage(ts)
	}

	var st protocol.SecurityType
	switch strings.ToLower(c.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	default:
		st = protocol.SecurityType_NONE
	}

	config.Security = &protocol.SecurityConfig{
		Type: st,
	}

	return config, nil
}

type DomainSocketConfig struct {
	Path     string `json:"path,omitempty"`
	Abstract bool   `json:"abstract,omitempty"`
	Padding  bool   `json:"padding,omitempty"`
}

// Build implements Buildable.
func (c *DomainSocketConfig) Build() (proto.Message, error) {
	return &domainsocket.Config{
		Path:     c.Path,
		Abstract: c.Abstract,
		Padding:  c.Padding,
	}, nil
}

func readFileOrString(f string, s []string) ([]byte, error) {
	if len(f) > 0 {
		return filesystem.ReadFile(f)
	}
	if len(s) > 0 {
		return []byte(strings.Join(s, "\n")), nil
	}
	return nil, newError("both file and bytes are empty.")
}

type TLSCertConfig struct {
	CertFile       string   `json:"certificateFile,omitempty"`
	CertStr        []string `json:"certificate,omitempty"`
	KeyFile        string   `json:"keyFile,omitempty"`
	KeyStr         []string `json:"key,omitempty"`
	Usage          string   `json:"usage,omitempty"`
	OcspStapling   uint64   `json:"ocspStapling,omitempty"`
	OneTimeLoading bool     `json:"oneTimeLoading,omitempty"`
}

// Build implements Buildable.
func (c *TLSCertConfig) Build() (*tls.Certificate, error) {
	certificate := new(tls.Certificate)

	cert, err := readFileOrString(c.CertFile, c.CertStr)
	if err != nil {
		return nil, newError("failed to parse certificate").Base(err)
	}
	certificate.Certificate = cert
	certificate.CertificatePath = c.CertFile

	if len(c.KeyFile) > 0 || len(c.KeyStr) > 0 {
		key, err := readFileOrString(c.KeyFile, c.KeyStr)
		if err != nil {
			return nil, newError("failed to parse key").Base(err)
		}
		certificate.Key = key
		certificate.KeyPath = c.KeyFile
	}

	switch strings.ToLower(c.Usage) {
	case "encipherment":
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	case "verify":
		certificate.Usage = tls.Certificate_AUTHORITY_VERIFY
	case "issue":
		certificate.Usage = tls.Certificate_AUTHORITY_ISSUE
	default:
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	}
	if certificate.KeyPath == "" && certificate.CertificatePath == "" {
		certificate.OneTimeLoading = true
	} else {
		certificate.OneTimeLoading = c.OneTimeLoading
	}
	certificate.OcspStapling = c.OcspStapling

	return certificate, nil
}

type TLSConfig struct {
	Insecure                             bool             `json:"allowInsecure,omitempty"`
	Certs                                []*TLSCertConfig `json:"certificates,omitempty"`
	ServerName                           string           `json:"serverName,omitempty"`
	ALPN                                 *StringList      `json:"alpn,omitempty"`
	EnableSessionResumption              bool             `json:"enableSessionResumption,omitempty"`
	DisableSystemRoot                    bool             `json:"disableSystemRoot,omitempty"`
	MinVersion                           string           `json:"minVersion,omitempty"`
	MaxVersion                           string           `json:"maxVersion,omitempty"`
	CipherSuites                         string           `json:"cipherSuites,omitempty"`
	PreferServerCipherSuites             bool             `json:"preferServerCipherSuites,omitempty"`
	Fingerprint                          string           `json:"fingerprint,omitempty"`
	RejectUnknownSNI                     bool             `json:"rejectUnknownSni,omitempty"`
	PinnedPeerCertificateChainSha256     *[]string        `json:"pinnedPeerCertificateChainSha256,omitempty"`
	PinnedPeerCertificatePublicKeySha256 *[]string        `json:"pinnedPeerCertificatePublicKeySha256,omitempty"`
	MasterKeyLog                         string           `json:"masterKeyLog,omitempty"`
}

// Build implements Buildable.
func (c *TLSConfig) Build() (proto.Message, error) {
	config := new(tls.Config)
	config.Certificate = make([]*tls.Certificate, len(c.Certs))
	for idx, certConf := range c.Certs {
		cert, err := certConf.Build()
		if err != nil {
			return nil, err
		}
		config.Certificate[idx] = cert
	}
	serverName := c.ServerName
	config.AllowInsecure = c.Insecure
	if len(c.ServerName) > 0 {
		config.ServerName = serverName
	}
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.PreferServerCipherSuites = c.PreferServerCipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, newError(`unknown fingerprint: `, config.Fingerprint)
	}
	config.RejectUnknownSni = c.RejectUnknownSNI

	if c.PinnedPeerCertificateChainSha256 != nil {
		config.PinnedPeerCertificateChainSha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificateChainSha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificateChainSha256 = append(config.PinnedPeerCertificateChainSha256, hashValue)
		}
	}

	if c.PinnedPeerCertificatePublicKeySha256 != nil {
		config.PinnedPeerCertificatePublicKeySha256 = [][]byte{}
		for _, v := range *c.PinnedPeerCertificatePublicKeySha256 {
			hashValue, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, err
			}
			config.PinnedPeerCertificatePublicKeySha256 = append(config.PinnedPeerCertificatePublicKeySha256, hashValue)
		}
	}

	config.MasterKeyLog = c.MasterKeyLog

	return config, nil
}

type REALITYConfig struct {
	Show         bool            `json:"show,omitempty"`
	Dest         json.RawMessage `json:"dest,omitempty"`
	Type         string          `json:"type,omitempty"`
	Xver         uint64          `json:"xver,omitempty"`
	ServerNames  []string        `json:"serverNames,omitempty"`
	PrivateKey   string          `json:"privateKey,omitempty"`
	MinClientVer string          `json:"minClientVer,omitempty"`
	MaxClientVer string          `json:"maxClientVer,omitempty"`
	MaxTimeDiff  uint64          `json:"maxTimeDiff,omitempty"`
	ShortIds     []string        `json:"shortIds,omitempty"`

	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortId     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

func (c *REALITYConfig) Build() (proto.Message, error) {
	config := new(reality.Config)
	config.Show = c.Show
	var err error
	if c.Dest != nil {
		var i uint16
		var s string
		if err = json.Unmarshal(c.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(c.Dest, &s)
		}
		if c.Type == "" && s != "" {
			switch s[0] {
			case '@', '/':
				c.Type = "unix"
				if s[0] == '@' && len(s) > 1 && s[1] == '@' && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
					copy(fullAddr, s[1:])
					s = string(fullAddr)
				}
			default:
				if _, err = strconv.Atoi(s); err == nil {
					s = "127.0.0.1:" + s
				}
				if _, _, err = net.SplitHostPort(s); err == nil {
					c.Type = "tcp"
				}
			}
		}
		if c.Type == "" {
			return nil, newError(`please fill in a valid value for "dest"`)
		}
		if c.Xver > 2 {
			return nil, newError(`invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
		if len(c.ServerNames) == 0 {
			return nil, newError(`empty "serverNames"`)
		}
		if c.PrivateKey == "" {
			return nil, newError(`empty "privateKey"`)
		}
		if config.PrivateKey, err = base64.RawURLEncoding.DecodeString(c.PrivateKey); err != nil || len(config.PrivateKey) != 32 {
			return nil, newError(`invalid "privateKey": `, c.PrivateKey)
		}
		if c.MinClientVer != "" {
			config.MinClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(c.MinClientVer, ".") {
				if i == 3 {
					return nil, newError(`invalid "minClientVer": `, c.MinClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, newError(`"minClientVer[`, i, `]" should be lesser than 256`)
				} else {
					config.MinClientVer[i] = byte(u)
				}
			}
		}
		if c.MaxClientVer != "" {
			config.MaxClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(c.MaxClientVer, ".") {
				if i == 3 {
					return nil, newError(`invalid "maxClientVer": `, c.MaxClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, newError(`"maxClientVer[`, i, `]" should be lesser than 256`)
				} else {
					config.MaxClientVer[i] = byte(u)
				}
			}
		}
		if len(c.ShortIds) == 0 {
			return nil, newError(`empty "shortIds"`)
		}
		config.ShortIds = make([][]byte, len(c.ShortIds))
		for i, s := range c.ShortIds {
			config.ShortIds[i] = make([]byte, 8)
			if _, err = hex.Decode(config.ShortIds[i], []byte(s)); err != nil {
				return nil, newError(`invalid "shortIds[`, i, `]": `, s)
			}
		}
		config.Dest = s
		config.Type = c.Type
		config.Xver = c.Xver
		config.ServerNames = c.ServerNames
		config.MaxTimeDiff = c.MaxTimeDiff
	} else {
		if c.Fingerprint == "" {
			return nil, newError(`empty "fingerprint"`)
		}
		if config.Fingerprint = strings.ToLower(c.Fingerprint); tls.GetFingerprint(config.Fingerprint) == nil {
			return nil, newError(`unknown "fingerprint": `, config.Fingerprint)
		}
		if config.Fingerprint == "hellogolang" {
			return nil, newError(`invalid "fingerprint": `, config.Fingerprint)
		}
		if len(c.ServerNames) != 0 {
			return nil, newError(`non-empty "serverNames", please use "serverName" instead`)
		}
		if c.PublicKey == "" {
			return nil, newError(`empty "publicKey"`)
		}
		if config.PublicKey, err = base64.RawURLEncoding.DecodeString(c.PublicKey); err != nil || len(config.PublicKey) != 32 {
			return nil, newError(`invalid "publicKey": `, c.PublicKey)
		}
		if len(c.ShortIds) != 0 {
			return nil, newError(`non-empty "shortIds", please use "shortId" instead`)
		}
		config.ShortId = make([]byte, 8)
		if _, err = hex.Decode(config.ShortId, []byte(c.ShortId)); err != nil {
			return nil, newError(`invalid "shortId": `, c.ShortId)
		}
		if c.SpiderX == "" {
			c.SpiderX = "/"
		}
		if c.SpiderX[0] != '/' {
			return nil, newError(`invalid "spiderX": `, c.SpiderX)
		}
		config.SpiderY = make([]int64, 10)
		u, _ := url.Parse(c.SpiderX)
		q := u.Query()
		parse := func(param string, index int) {
			if q.Get(param) != "" {
				s := strings.Split(q.Get(param), "-")
				if len(s) == 1 {
					config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
					config.SpiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
				} else {
					config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
					config.SpiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
				}
			}
			q.Del(param)
		}
		parse("p", 0) // padding
		parse("c", 2) // concurrency
		parse("t", 4) // times
		parse("i", 6) // interval
		parse("r", 8) // return
		u.RawQuery = q.Encode()
		config.SpiderX = u.String()
		config.ServerName = c.ServerName
	}
	return config, nil
}

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "tcp":
		return "tcp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "ws", "websocket":
		return "websocket", nil
	case "h2", "http":
		return "http", nil
	case "ds", "domainsocket":
		return "domainsocket", nil
	case "quic":
		return "quic", nil
	case "grpc", "gun":
		return "grpc", nil
	default:
		return "", newError("Config: unknown transport protocol: ", p)
	}
}

type SocketConfig struct {
	Mark                 int32       `json:"mark,omitempty"`
	TFO                  interface{} `json:"tcpFastOpen,omitempty"`
	TProxy               string      `json:"tproxy,omitempty"`
	AcceptProxyProtocol  bool        `json:"acceptProxyProtocol,omitempty"`
	DomainStrategy       string      `json:"domainStrategy,omitempty"`
	DialerProxy          string      `json:"dialerProxy,omitempty"`
	TCPKeepAliveInterval int32       `json:"tcpKeepAliveInterval,omitempty"`
	TCPKeepAliveIdle     int32       `json:"tcpKeepAliveIdle,omitempty"`
	TCPCongestion        string      `json:"tcpCongestion,omitempty"`
	TCPWindowClamp       int32       `json:"tcpWindowClamp,omitempty"`
	TCPMaxSeg            int32       `json:"tcpMaxSeg,omitempty"`
	TcpNoDelay           bool        `json:"tcpNoDelay,omitempty"`
	TCPUserTimeout       int32       `json:"tcpUserTimeout,omitempty"`
	V6only               bool        `json:"v6only,omitempty"`
	Interface            string      `json:"interface,omitempty"`
	TcpMptcp             bool        `json:"tcpMptcp,omitempty"`
}

// Build implements Buildable.
func (c *SocketConfig) Build() (*internet.SocketConfig, error) {
	tfo := int32(0) // don't invoke setsockopt() for TFO
	if c.TFO != nil {
		switch v := c.TFO.(type) {
		case bool:
			if v {
				tfo = 256
			} else {
				tfo = -1 // TFO need to be disabled
			}
		case float64:
			tfo = int32(math.Min(v, math.MaxInt32))
		default:
			return nil, newError("tcpFastOpen: only boolean and integer value is acceptable")
		}
	}
	var tproxy internet.SocketConfig_TProxyMode
	switch strings.ToLower(c.TProxy) {
	case "tproxy":
		tproxy = internet.SocketConfig_TProxy
	case "redirect":
		tproxy = internet.SocketConfig_Redirect
	default:
		tproxy = internet.SocketConfig_Off
	}

	dStrategy := internet.DomainStrategy_AS_IS
	switch strings.ToLower(c.DomainStrategy) {
	case "asis", "":
		dStrategy = internet.DomainStrategy_AS_IS
	case "useip":
		dStrategy = internet.DomainStrategy_USE_IP
	case "useipv4":
		dStrategy = internet.DomainStrategy_USE_IP4
	case "useipv6":
		dStrategy = internet.DomainStrategy_USE_IP6
	case "useipv4v6":
		dStrategy = internet.DomainStrategy_USE_IP46
	case "useipv6v4":
		dStrategy = internet.DomainStrategy_USE_IP64
	case "forceip":
		dStrategy = internet.DomainStrategy_FORCE_IP
	case "forceipv4":
		dStrategy = internet.DomainStrategy_FORCE_IP4
	case "forceipv6":
		dStrategy = internet.DomainStrategy_FORCE_IP6
	case "forceipv4v6":
		dStrategy = internet.DomainStrategy_FORCE_IP46
	case "forceipv6v4":
		dStrategy = internet.DomainStrategy_FORCE_IP64
	default:
		return nil, newError("unsupported domain strategy: ", c.DomainStrategy)
	}

	return &internet.SocketConfig{
		Mark:                 c.Mark,
		Tfo:                  tfo,
		Tproxy:               tproxy,
		DomainStrategy:       dStrategy,
		AcceptProxyProtocol:  c.AcceptProxyProtocol,
		DialerProxy:          c.DialerProxy,
		TcpKeepAliveInterval: c.TCPKeepAliveInterval,
		TcpKeepAliveIdle:     c.TCPKeepAliveIdle,
		TcpCongestion:        c.TCPCongestion,
		TcpWindowClamp:       c.TCPWindowClamp,
		TcpMaxSeg:            c.TCPMaxSeg,
		TcpNoDelay:           c.TcpNoDelay,
		TcpUserTimeout:       c.TCPUserTimeout,
		V6Only:               c.V6only,
		Interface:            c.Interface,
		TcpMptcp:             c.TcpMptcp,
	}, nil
}

type StreamConfig struct {
	Network         *TransportProtocol  `json:"network,omitempty"`
	Security        string              `json:"security,omitempty"`
	TLSSettings     *TLSConfig          `json:"tlsSettings,omitempty"`
	REALITYSettings *REALITYConfig      `json:"realitySettings,omitempty"`
	TCPSettings     *TCPConfig          `json:"tcpSettings,omitempty"`
	KCPSettings     *KCPConfig          `json:"kcpSettings,omitempty"`
	WSSettings      *WebSocketConfig    `json:"wsSettings,omitempty"`
	HTTPSettings    *HTTPConfig         `json:"httpSettings,omitempty"`
	DSSettings      *DomainSocketConfig `json:"dsSettings,omitempty"`
	QUICSettings    *QUICConfig         `json:"quicSettings,omitempty"`
	SocketSettings  *SocketConfig       `json:"sockopt,omitempty"`
	GRPCConfig      *GRPCConfig         `json:"grpcSettings,omitempty"`
	GUNConfig       *GRPCConfig         `json:"gunSettings,omitempty"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		ProtocolName: "tcp",
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, newError("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "http" && config.ProtocolName != "grpc" && config.ProtocolName != "domainsocket" {
			return nil, newError("REALITY only supports TCP, H2, gRPC and DomainSocket for now.")
		}
		if c.REALITYSettings == nil {
			return nil, newError(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, newError("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, newError(`Please use VLESS flow "xtls-rprx-vision" with TLS or REALITY.`)
	default:
		return nil, newError(`Unknown security "` + c.Security + `".`)
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build TCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, newError("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPSettings != nil {
		ts, err := c.HTTPSettings.Build()
		if err != nil {
			return nil, newError("Failed to build HTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "http",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.DSSettings != nil {
		ds, err := c.DSSettings.Build()
		if err != nil {
			return nil, newError("Failed to build DomainSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "domainsocket",
			Settings:     serial.ToTypedMessage(ds),
		})
	}
	if c.QUICSettings != nil {
		qs, err := c.QUICSettings.Build()
		if err != nil {
			return nil, newError("Failed to build QUIC config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(qs),
		})
	}
	if c.GRPCConfig == nil {
		c.GRPCConfig = c.GUNConfig
	}
	if c.GRPCConfig != nil {
		gs, err := c.GRPCConfig.Build()
		if err != nil {
			return nil, newError("Failed to build gRPC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, newError("Failed to build sockopt").Base(err)
		}
		config.SocketSettings = ss
	}
	return config, nil
}

type ProxyConfig struct {
	Tag string `json:"tag,omitempty"`

	// TransportLayerProxy: For compatibility.
	TransportLayerProxy bool `json:"transportLayer,omitempty"`
}

// Build implements Buildable.
func (v *ProxyConfig) Build() (*internet.ProxyConfig, error) {
	if v.Tag == "" {
		return nil, newError("Proxy tag is not set.")
	}
	return &internet.ProxyConfig{
		Tag:                 v.Tag,
		TransportLayerProxy: v.TransportLayerProxy,
	}, nil
}
