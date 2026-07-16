package conf

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

var defaultMinClientVer = [...]byte{26, 3, 27}

type LimitFallback struct {
	AfterBytes       uint64
	BytesPerSec      uint64
	BurstBytesPerSec uint64
}

type REALITYConfig struct {
	MasterKeyLog string          `json:"masterKeyLog"`
	Show         bool            `json:"show"`
	Target       json.RawMessage `json:"target"`
	Dest         json.RawMessage `json:"dest"`
	Type         string          `json:"type"`
	Xver         uint64          `json:"xver"`
	ServerNames  []string        `json:"serverNames"`
	PrivateKey   string          `json:"privateKey"`
	MinClientVer string          `json:"minClientVer"`
	MaxClientVer string          `json:"maxClientVer"`
	MaxTimeDiff  uint64          `json:"maxTimeDiff"`
	ShortIds     []string        `json:"shortIds"`
	Mldsa65Seed  string          `json:"mldsa65Seed"`

	LimitFallbackUpload   LimitFallback `json:"limitFallbackUpload"`
	LimitFallbackDownload LimitFallback `json:"limitFallbackDownload"`

	Fingerprint   string `json:"fingerprint"`
	ServerName    string `json:"serverName"`
	Password      string `json:"password"`
	PublicKey     string `json:"publicKey"`
	ShortId       string `json:"shortId"`
	Mldsa65Verify string `json:"mldsa65Verify"`
	SpiderX       string `json:"spiderX"`
}

func (c *REALITYConfig) Build() (proto.Message, error) {
	config := new(reality.Config)
	config.MasterKeyLog = c.MasterKeyLog
	config.Show = c.Show
	var err error
	if c.Target != nil {
		c.Dest = c.Target
	}
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
					s = "localhost:" + s
				}
				if _, _, err = net.SplitHostPort(s); err == nil {
					c.Type = "tcp"
				}
			}
		}
		if c.Type == "" {
			return nil, errors.New(`please fill in a valid value for "target"`)
		}
		if c.Xver > 2 {
			return nil, errors.New(`invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
		if len(c.ServerNames) == 0 {
			return nil, errors.New(`empty "serverNames"`)
		}
		if c.PrivateKey == "" {
			return nil, errors.New(`empty "privateKey"`)
		}
		if config.PrivateKey, err = base64.RawURLEncoding.DecodeString(c.PrivateKey); err != nil || len(config.PrivateKey) != 32 {
			return nil, errors.New(`invalid "privateKey": `, c.PrivateKey)
		}

		var clientVer [len(defaultMinClientVer)]byte
		if c.MinClientVer != "" {
			var u uint64
			for i, s := range strings.Split(c.MinClientVer, ".") {
				if i == len(clientVer) {
					return nil, errors.New(`invalid "minClientVer": `, c.MinClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, errors.New(`"minClientVer[`, i, `]" should be less than 256`)
				} else {
					clientVer[i] = byte(u)
				}
			}
		} else {
			clientVer = defaultMinClientVer
		}

		config.MinClientVer = clientVer[:]

		if clientVer == defaultMinClientVer {
			errors.LogWarning(context.Background(), `REALITY: The default "minClientVer" only allows Xray-core v26.3.27+ clients to connect`)
		} else {
			errors.LogWarning(context.Background(), `REALITY: A non-default "minClientVer" may create a distinctive fingerprint and increase detection risk: `, c.MinClientVer)
		}
		if c.MaxClientVer != "" {
			config.MaxClientVer = make([]byte, 3)
			var u uint64
			for i, s := range strings.Split(c.MaxClientVer, ".") {
				if i == 3 {
					return nil, errors.New(`invalid "maxClientVer": `, c.MaxClientVer)
				}
				if u, err = strconv.ParseUint(s, 10, 8); err != nil {
					return nil, errors.New(`"maxClientVer[`, i, `]" should be less than 256`)
				} else {
					config.MaxClientVer[i] = byte(u)
				}
			}
		}
		if len(c.ShortIds) == 0 {
			return nil, errors.New(`empty "shortIds"`)
		}
		config.ShortIds = make([][]byte, len(c.ShortIds))
		for i, s := range c.ShortIds {
			if len(s) > 16 {
				return nil, errors.New(`too long "shortIds[`, i, `]": `, s)
			}
			config.ShortIds[i] = make([]byte, 8)
			if _, err = hex.Decode(config.ShortIds[i], []byte(s)); err != nil {
				return nil, errors.New(`invalid "shortIds[`, i, `]": `, s)
			}
		}
		config.Dest = s
		config.Type = c.Type
		config.Xver = c.Xver
		config.ServerNames = c.ServerNames
		config.MaxTimeDiff = c.MaxTimeDiff

		if c.Mldsa65Seed != "" {
			if c.Mldsa65Seed == c.PrivateKey {
				return nil, errors.New(`"mldsa65Seed" and "privateKey" can not be the same value: `, c.Mldsa65Seed)
			}
			if config.Mldsa65Seed, err = base64.RawURLEncoding.DecodeString(c.Mldsa65Seed); err != nil || len(config.Mldsa65Seed) != 32 {
				return nil, errors.New(`invalid "mldsa65Seed": `, c.Mldsa65Seed)
			}
		}

		for _, sn := range config.ServerNames {
			if strings.Contains(sn, "apple") || strings.Contains(sn, "icloud") {
				errors.LogWarning(context.Background(), `REALITY: Choosing apple, icloud, etc. as the target may get your IP blocked by the GFW`)
			}
		}

		config.LimitFallbackUpload = new(reality.LimitFallback)
		config.LimitFallbackUpload.AfterBytes = c.LimitFallbackUpload.AfterBytes
		config.LimitFallbackUpload.BytesPerSec = c.LimitFallbackUpload.BytesPerSec
		config.LimitFallbackUpload.BurstBytesPerSec = c.LimitFallbackUpload.BurstBytesPerSec
		config.LimitFallbackDownload = new(reality.LimitFallback)
		config.LimitFallbackDownload.AfterBytes = c.LimitFallbackDownload.AfterBytes
		config.LimitFallbackDownload.BytesPerSec = c.LimitFallbackDownload.BytesPerSec
		config.LimitFallbackDownload.BurstBytesPerSec = c.LimitFallbackDownload.BurstBytesPerSec
	} else {
		config.Fingerprint = strings.ToLower(c.Fingerprint)
		if config.Fingerprint == "unsafe" || config.Fingerprint == "hellogolang" {
			return nil, errors.New(`invalid "fingerprint": `, config.Fingerprint)
		}
		if tls.GetFingerprint(config.Fingerprint) == nil {
			return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
		}
		if len(c.ServerNames) != 0 {
			return nil, errors.New(`non-empty "serverNames", please use "serverName" instead`)
		}
		if c.Password != "" {
			c.PublicKey = c.Password
		}
		if c.PublicKey == "" {
			return nil, errors.New(`empty "password"`)
		}
		if config.PublicKey, err = base64.RawURLEncoding.DecodeString(c.PublicKey); err != nil || len(config.PublicKey) != 32 {
			return nil, errors.New(`invalid "password": `, c.PublicKey)
		}
		if len(c.ShortIds) != 0 {
			return nil, errors.New(`non-empty "shortIds", please use "shortId" instead`)
		}
		if len(c.ShortId) > 16 {
			return nil, errors.New(`too long "shortId": `, c.ShortId)
		}
		config.ShortId = make([]byte, 8)
		if _, err = hex.Decode(config.ShortId, []byte(c.ShortId)); err != nil {
			return nil, errors.New(`invalid "shortId": `, c.ShortId)
		}
		if c.Mldsa65Verify != "" {
			if config.Mldsa65Verify, err = base64.RawURLEncoding.DecodeString(c.Mldsa65Verify); err != nil || len(config.Mldsa65Verify) != 1952 {
				return nil, errors.New(`invalid "mldsa65Verify": `, c.Mldsa65Verify)
			}
		}
		if c.SpiderX == "" {
			c.SpiderX = "/"
		}
		if c.SpiderX[0] != '/' {
			return nil, errors.New(`invalid "spiderX": `, c.SpiderX)
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

type TLSCertConfig struct {
	CertFile       string   `json:"certificateFile"`
	CertStr        []string `json:"certificate"`
	KeyFile        string   `json:"keyFile"`
	KeyStr         []string `json:"key"`
	Usage          string   `json:"usage"`
	OcspStapling   uint64   `json:"ocspStapling"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
	BuildChain     bool     `json:"buildChain"`
}

// Build implements Buildable.
func (c *TLSCertConfig) Build() (*tls.Certificate, error) {
	certificate := new(tls.Certificate)

	cert, err := readFileOrString(c.CertFile, c.CertStr)
	if err != nil {
		return nil, errors.New("failed to parse certificate").Base(err)
	}
	certificate.Certificate = cert
	certificate.CertificatePath = c.CertFile

	if len(c.KeyFile) > 0 || len(c.KeyStr) > 0 {
		key, err := readFileOrString(c.KeyFile, c.KeyStr)
		if err != nil {
			return nil, errors.New("failed to parse key").Base(err)
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
	certificate.BuildChain = c.BuildChain

	return certificate, nil
}

type TLSConfig struct {
	AllowInsecure           bool             `json:"allowInsecure"`
	Certs                   []*TLSCertConfig `json:"certificates"`
	ServerName              string           `json:"serverName"`
	ALPN                    *StringList      `json:"alpn"`
	EnableSessionResumption bool             `json:"enableSessionResumption"`
	DisableSystemRoot       bool             `json:"disableSystemRoot"`
	MinVersion              string           `json:"minVersion"`
	MaxVersion              string           `json:"maxVersion"`
	CipherSuites            string           `json:"cipherSuites"`
	Fingerprint             string           `json:"fingerprint"`
	RejectUnknownSNI        bool             `json:"rejectUnknownSni"`
	CurvePreferences        *StringList      `json:"curvePreferences"`
	MasterKeyLog            string           `json:"masterKeyLog"`
	PinnedPeerCertSha256    string           `json:"pinnedPeerCertSha256"`
	VerifyPeerCertByName    string           `json:"verifyPeerCertByName"`
	ECHServerKeys           string           `json:"echServerKeys"`
	ECHConfigList           string           `json:"echConfigList"`
	ECHSocketSettings       *SocketConfig    `json:"echSockopt"`
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
	if len(c.ServerName) > 0 {
		config.ServerName = serverName
	}
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	if len(config.NextProtocol) > 1 {
		for _, p := range config.NextProtocol {
			if tls.IsFromMitm(p) {
				return nil, errors.New(`only one element is allowed in "alpn" when using "fromMitm" in it`)
			}
		}
	}
	if c.CurvePreferences != nil && len(*c.CurvePreferences) > 0 {
		config.CurvePreferences = []string(*c.CurvePreferences)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "unsafe" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, errors.New(`unknown "fingerprint": `, config.Fingerprint)
	}
	config.RejectUnknownSni = c.RejectUnknownSNI
	config.MasterKeyLog = c.MasterKeyLog

	if c.AllowInsecure {
		return nil, errors.PrintRemovedFeatureError(`"allowInsecure"`, `"pinnedPeerCertSha256"(pcs) and "verifyPeerCertByName"(vcn)`)
	}
	if c.PinnedPeerCertSha256 != "" {
		for v := range strings.SplitSeq(c.PinnedPeerCertSha256, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			// remove colons for OpenSSL format
			hashValue, err := hex.DecodeString(strings.ReplaceAll(v, ":", ""))
			if err != nil {
				return nil, err
			}
			if len(hashValue) != 32 {
				return nil, errors.New("incorrect pinnedPeerCertSha256 length: ", v)
			}
			config.PinnedPeerCertSha256 = append(config.PinnedPeerCertSha256, hashValue)
		}
	}
	if c.VerifyPeerCertByName != "" {
		for v := range strings.SplitSeq(c.VerifyPeerCertByName, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			config.VerifyPeerCertByName = append(config.VerifyPeerCertByName, v)
		}
	}

	if c.ECHServerKeys != "" {
		EchPrivateKey, err := base64.StdEncoding.DecodeString(c.ECHServerKeys)
		if err != nil {
			return nil, errors.New("invalid ECH Config", c.ECHServerKeys)
		}
		config.EchServerKeys = EchPrivateKey
	}
	config.EchConfigList = c.ECHConfigList
	if c.ECHSocketSettings != nil {
		ss, err := c.ECHSocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build ech sockopt.").Base(err)
		}
		config.EchSocketSettings = ss
	}

	return config, nil
}
