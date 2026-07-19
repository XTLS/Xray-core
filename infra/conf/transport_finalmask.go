package conf

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	googleuuid "github.com/google/uuid"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
	"github.com/xtls/xray-core/transport/internet/finalmask/realm"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"github.com/xtls/xray-core/transport/internet/finalmask/xicmp"
	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func PraseByteSlice(data json.RawMessage, typ string) ([]byte, error) {
	switch strings.ToLower(typ) {
	case "", "array":
		if len(data) == 0 {
			return data, nil
		}
		var packet []byte
		if err := json.Unmarshal(data, &packet); err != nil {
			return nil, err
		}
		return packet, nil
	case "str":
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return nil, err
		}
		return []byte(str), nil
	case "hex":
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return nil, err
		}
		return hex.DecodeString(str)
	case "base64":
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(str)
	default:
		return nil, errors.New("unknown type")
	}
}

var (
	customVarNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	tcpmaskLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"header-custom": func() interface{} { return new(HeaderCustomTCP) },
		"fragment":      func() interface{} { return new(FragmentMask) },
		"sudoku":        func() interface{} { return new(Sudoku) },
		"xmc":           func() interface{} { return new(XMC) },
	}, "type", "settings")

	udpmaskLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"header-custom": func() interface{} { return new(HeaderCustomUDP) },
		"mkcp-legacy":   func() interface{} { return new(MkcpLegacy) },
		"noise":         func() interface{} { return new(NoiseMask) },
		"salamander":    func() interface{} { return new(Salamander) },
		"sudoku":        func() interface{} { return new(Sudoku) },
		"xdns":          func() interface{} { return new(Xdns) },
		"xicmp":         func() interface{} { return new(Xicmp) },
		"realm":         func() interface{} { return new(Realm) },
	}, "type", "settings")
)

type TCPItem struct {
	Delay     Int32Range       `json:"delay"`
	Rand      int32            `json:"rand"`
	RandRange *Int32Range      `json:"randRange"`
	Capture   string           `json:"capture"`
	Type      string           `json:"type"`
	Reuse     string           `json:"reuse"`
	Transform *CustomTransform `json:"transform"`
	Packet    json.RawMessage  `json:"packet"`
}

type HeaderCustomTCP struct {
	Clients [][]TCPItem `json:"clients"`
	Servers [][]TCPItem `json:"servers"`
	Errors  [][]TCPItem `json:"errors"`
}

func (c *HeaderCustomTCP) Build() (proto.Message, error) {
	for _, value := range c.Clients {
		for _, item := range value {
			if err := validateCustomItemSpec(item.Capture, item.Packet, item.Rand, item.Reuse, item.Transform); err != nil {
				return nil, err
			}
		}
	}
	for _, value := range c.Servers {
		for _, item := range value {
			if err := validateCustomItemSpec(item.Capture, item.Packet, item.Rand, item.Reuse, item.Transform); err != nil {
				return nil, err
			}
		}
	}
	for _, value := range c.Errors {
		for _, item := range value {
			if err := validateCustomItemSpec(item.Capture, item.Packet, item.Rand, item.Reuse, item.Transform); err != nil {
				return nil, err
			}
		}
	}

	errInvalidRange := errors.New("invalid randRange")

	clients := make([]*custom.TCPSequence, len(c.Clients))
	for i, value := range c.Clients {
		clients[i] = &custom.TCPSequence{}
		for _, item := range value {
			if item.RandRange == nil {
				item.RandRange = &Int32Range{From: 0, To: 255}
			}
			if item.RandRange.From < 0 || item.RandRange.To > 255 {
				return nil, errInvalidRange
			}
			var err error
			if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
				return nil, err
			}
			transform, err := buildCustomTransform(item.Transform)
			if err != nil {
				return nil, err
			}
			clients[i].Sequence = append(clients[i].Sequence, &custom.TCPItem{
				DelayMin: int64(item.Delay.From),
				DelayMax: int64(item.Delay.To),
				Rand:     item.Rand,
				RandMin:  item.RandRange.From,
				RandMax:  item.RandRange.To,
				Packet:   item.Packet,
				Save:     item.Capture,
				Var:      item.Reuse,
				Expr:     transform,
			})
		}
	}

	servers := make([]*custom.TCPSequence, len(c.Servers))
	for i, value := range c.Servers {
		servers[i] = &custom.TCPSequence{}
		for _, item := range value {
			if item.RandRange == nil {
				item.RandRange = &Int32Range{From: 0, To: 255}
			}
			if item.RandRange.From < 0 || item.RandRange.To > 255 {
				return nil, errInvalidRange
			}
			var err error
			if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
				return nil, err
			}
			transform, err := buildCustomTransform(item.Transform)
			if err != nil {
				return nil, err
			}
			servers[i].Sequence = append(servers[i].Sequence, &custom.TCPItem{
				DelayMin: int64(item.Delay.From),
				DelayMax: int64(item.Delay.To),
				Rand:     item.Rand,
				RandMin:  item.RandRange.From,
				RandMax:  item.RandRange.To,
				Packet:   item.Packet,
				Save:     item.Capture,
				Var:      item.Reuse,
				Expr:     transform,
			})
		}
	}

	errors := make([]*custom.TCPSequence, len(c.Errors))
	for i, value := range c.Errors {
		errors[i] = &custom.TCPSequence{}
		for _, item := range value {
			if item.RandRange == nil {
				item.RandRange = &Int32Range{From: 0, To: 255}
			}
			if item.RandRange.From < 0 || item.RandRange.To > 255 {
				return nil, errInvalidRange
			}
			var err error
			if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
				return nil, err
			}
			transform, err := buildCustomTransform(item.Transform)
			if err != nil {
				return nil, err
			}
			errors[i].Sequence = append(errors[i].Sequence, &custom.TCPItem{
				DelayMin: int64(item.Delay.From),
				DelayMax: int64(item.Delay.To),
				Rand:     item.Rand,
				RandMin:  item.RandRange.From,
				RandMax:  item.RandRange.To,
				Packet:   item.Packet,
				Save:     item.Capture,
				Var:      item.Reuse,
				Expr:     transform,
			})
		}
	}

	return &custom.TCPConfig{
		Clients: clients,
		Servers: servers,
		Errors:  errors,
	}, nil
}

type FragmentMask struct {
	Packets  string       `json:"packets"`
	Length   Int32Range   `json:"length"`
	Delay    Int32Range   `json:"delay"`
	Lengths  []Int32Range `json:"lengths"`
	Delays   []Int32Range `json:"delays"`
	MaxSplit Int32Range   `json:"maxSplit"`
}

func (c *FragmentMask) Build() (proto.Message, error) {
	config := &fragment.Config{}

	switch strings.ToLower(c.Packets) {
	case "tlshello":
		config.PacketsFrom = 0
		config.PacketsTo = 1
	case "":
		config.PacketsFrom = 0
		config.PacketsTo = 0
	default:
		from, to, err := ParseRangeString(c.Packets)
		if err != nil {
			return nil, errors.New("Invalid PacketsFrom").Base(err)
		}
		config.PacketsFrom = int64(from)
		config.PacketsTo = int64(to)
		if config.PacketsFrom == 0 {
			return nil, errors.New("PacketsFrom can't be 0")
		}
	}

	if len(c.Lengths) > 0 {
		for _, r := range c.Lengths {
			config.LengthsMin = append(config.LengthsMin, int64(r.From))
			config.LengthsMax = append(config.LengthsMax, int64(r.To))
		}
	} else {
		config.LengthsMin = append(config.LengthsMin, int64(c.Length.From))
		config.LengthsMax = append(config.LengthsMax, int64(c.Length.To))
	}

	if config.LengthsMin[len(config.LengthsMin)-1] == 0 {
		return nil, errors.New("last lengths entry min can't be 0")
	}

	if len(c.Delays) > 0 {
		for _, r := range c.Delays {
			config.DelaysMin = append(config.DelaysMin, int64(r.From))
			config.DelaysMax = append(config.DelaysMax, int64(r.To))
		}
	} else {
		config.DelaysMin = append(config.DelaysMin, int64(c.Delay.From))
		config.DelaysMax = append(config.DelaysMax, int64(c.Delay.To))
	}

	config.MaxSplitMin = int64(c.MaxSplit.From)
	config.MaxSplitMax = int64(c.MaxSplit.To)

	return config, nil
}

type NoiseItem struct {
	Rand      Int32Range      `json:"rand"`
	RandRange *Int32Range     `json:"randRange"`
	Type      string          `json:"type"`
	Packet    json.RawMessage `json:"packet"`
	Delay     Int32Range      `json:"delay"`
}

type NoiseMask struct {
	Reset Int32Range  `json:"reset"`
	Noise []NoiseItem `json:"noise"`
}

func (c *NoiseMask) Build() (proto.Message, error) {
	for _, item := range c.Noise {
		if len(item.Packet) > 0 && item.Rand.To > 0 {
			return nil, errors.New("len(item.Packet) > 0 && item.Rand.To > 0")
		}
	}

	noiseSlice := make([]*noise.Item, 0, len(c.Noise))
	for _, item := range c.Noise {
		if item.RandRange == nil {
			item.RandRange = &Int32Range{From: 0, To: 255}
		}
		if item.RandRange.From < 0 || item.RandRange.To > 255 {
			return nil, errors.New("invalid randRange")
		}
		var err error
		if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
			return nil, err
		}
		noiseSlice = append(noiseSlice, &noise.Item{
			RandMin:      int64(item.Rand.From),
			RandMax:      int64(item.Rand.To),
			RandRangeMin: item.RandRange.From,
			RandRangeMax: item.RandRange.To,
			Packet:       item.Packet,
			DelayMin:     int64(item.Delay.From),
			DelayMax:     int64(item.Delay.To),
		})
	}

	return &noise.Config{
		ResetMin: int64(c.Reset.From),
		ResetMax: int64(c.Reset.To),
		Items:    noiseSlice,
	}, nil
}

type UDPItem struct {
	Rand      int32            `json:"rand"`
	RandRange *Int32Range      `json:"randRange"`
	Capture   string           `json:"capture"`
	Type      string           `json:"type"`
	Reuse     string           `json:"reuse"`
	Transform *CustomTransform `json:"transform"`
	Packet    json.RawMessage  `json:"packet"`
}

type CustomTransform struct {
	Op   string               `json:"op"`
	Args []CustomTransformArg `json:"args"`
}

type CustomTransformArg struct {
	Type      string           `json:"type"`
	Bytes     json.RawMessage  `json:"bytes"`
	U64       *uint64          `json:"u64"`
	Reuse     string           `json:"reuse"`
	Metadata  string           `json:"metadata"`
	Transform *CustomTransform `json:"transform"`
}

func validateCustomVarName(name string) error {
	if name == "" {
		return nil
	}
	if !customVarNamePattern.MatchString(name) {
		return errors.New("invalid variable name")
	}
	return nil
}

func validateCustomItemSpec(capture string, packet json.RawMessage, rand int32, reuse string, transform *CustomTransform) error {
	if err := validateCustomVarName(capture); err != nil {
		return err
	}
	if err := validateCustomVarName(reuse); err != nil {
		return err
	}

	kindCount := 0
	if len(packet) > 0 {
		kindCount++
	}
	if rand > 0 {
		kindCount++
	}
	if reuse != "" {
		kindCount++
	}
	if transform != nil {
		kindCount++
	}
	if kindCount > 1 {
		return errors.New("exactly one item kind must be set")
	}
	if kindCount == 0 && capture != "" {
		return errors.New("exactly one item kind must be set")
	}

	return nil
}

func buildCustomTransform(transform *CustomTransform) (*custom.Expr, error) {
	if transform == nil {
		return nil, nil
	}
	if transform.Op == "" {
		return nil, errors.New("transform op is required")
	}
	if len(transform.Args) == 0 {
		return nil, errors.New("transform args are required")
	}

	args := make([]*custom.ExprArg, 0, len(transform.Args))
	for _, arg := range transform.Args {
		parsedArg, err := buildCustomTransformArg(arg)
		if err != nil {
			return nil, err
		}
		args = append(args, parsedArg)
	}

	return &custom.Expr{
		Op:   transform.Op,
		Args: args,
	}, nil
}

func buildCustomTransformArg(arg CustomTransformArg) (*custom.ExprArg, error) {
	kindCount := 0
	if len(arg.Bytes) > 0 {
		kindCount++
	}
	if arg.U64 != nil {
		kindCount++
	}
	if arg.Reuse != "" {
		kindCount++
	}
	if arg.Metadata != "" {
		kindCount++
	}
	if arg.Transform != nil {
		kindCount++
	}
	if kindCount != 1 {
		return nil, errors.New("transform arg must set exactly one value")
	}

	if len(arg.Bytes) > 0 {
		value, err := PraseByteSlice(arg.Bytes, arg.Type)
		if err != nil {
			return nil, err
		}
		return &custom.ExprArg{
			Value: &custom.ExprArg_Bytes{
				Bytes: value,
			},
		}, nil
	}
	if arg.U64 != nil {
		return &custom.ExprArg{
			Value: &custom.ExprArg_U64{
				U64: *arg.U64,
			},
		}, nil
	}
	if arg.Reuse != "" {
		if err := validateCustomVarName(arg.Reuse); err != nil {
			return nil, err
		}
		return &custom.ExprArg{
			Value: &custom.ExprArg_Var{
				Var: arg.Reuse,
			},
		}, nil
	}
	if arg.Metadata != "" {
		return &custom.ExprArg{
			Value: &custom.ExprArg_Metadata{
				Metadata: arg.Metadata,
			},
		}, nil
	}

	parsedExpr, err := buildCustomTransform(arg.Transform)
	if err != nil {
		return nil, err
	}
	return &custom.ExprArg{
		Value: &custom.ExprArg_Expr{
			Expr: parsedExpr,
		},
	}, nil
}

type HeaderCustomUDP struct {
	Mode   string    `json:"mode"`
	Client []UDPItem `json:"client"`
	Server []UDPItem `json:"server"`
}

func (c *HeaderCustomUDP) Build() (proto.Message, error) {
	switch c.Mode {
	case "", "prefix", "standalone":
	default:
		return nil, errors.New("unknown udp mode")
	}

	for _, item := range c.Client {
		if err := validateCustomItemSpec(item.Capture, item.Packet, item.Rand, item.Reuse, item.Transform); err != nil {
			return nil, err
		}
	}
	for _, item := range c.Server {
		if err := validateCustomItemSpec(item.Capture, item.Packet, item.Rand, item.Reuse, item.Transform); err != nil {
			return nil, err
		}
	}

	client := make([]*custom.UDPItem, 0, len(c.Client))
	for _, item := range c.Client {
		if item.RandRange == nil {
			item.RandRange = &Int32Range{From: 0, To: 255}
		}
		if item.RandRange.From < 0 || item.RandRange.To > 255 {
			return nil, errors.New("invalid randRange")
		}
		var err error
		if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
			return nil, err
		}
		transform, err := buildCustomTransform(item.Transform)
		if err != nil {
			return nil, err
		}
		client = append(client, &custom.UDPItem{
			Rand:    item.Rand,
			RandMin: item.RandRange.From,
			RandMax: item.RandRange.To,
			Packet:  item.Packet,
			Save:    item.Capture,
			Var:     item.Reuse,
			Expr:    transform,
		})
	}

	server := make([]*custom.UDPItem, 0, len(c.Server))
	for _, item := range c.Server {
		if item.RandRange == nil {
			item.RandRange = &Int32Range{From: 0, To: 255}
		}
		if item.RandRange.From < 0 || item.RandRange.To > 255 {
			return nil, errors.New("invalid randRange")
		}
		var err error
		if item.Packet, err = PraseByteSlice(item.Packet, item.Type); err != nil {
			return nil, err
		}
		transform, err := buildCustomTransform(item.Transform)
		if err != nil {
			return nil, err
		}
		server = append(server, &custom.UDPItem{
			Rand:    item.Rand,
			RandMin: item.RandRange.From,
			RandMax: item.RandRange.To,
			Packet:  item.Packet,
			Save:    item.Capture,
			Var:     item.Reuse,
			Expr:    transform,
		})
	}

	if c.Mode == "standalone" {
		return &custom.UDPStandaloneConfig{
			Client: client,
			Server: server,
		}, nil
	} else {
		return &custom.UDPConfig{
			Client: client,
			Server: server,
		}, nil
	}
}

type MkcpLegacy struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

func (c *MkcpLegacy) Build() (proto.Message, error) {
	if len(c.Header) == 0 {
		if len(c.Value) == 0 {
			return &original.Config{}, nil
		} else {
			return &aes128gcm.Config{Password: c.Value}, nil
		}
	}
	switch strings.ToLower(c.Header) {
	case "dns":
		domain := c.Value
		if len(domain) == 0 {
			domain = "www.baidu.com"
		}
		return &header.Config{ID: 0, Domain: domain}, nil
	case "dtls":
		return &header.Config{ID: 1}, nil
	case "srtp":
		return &header.Config{ID: 2}, nil
	case "utp":
		return &header.Config{ID: 3}, nil
	case "wechat":
		return &header.Config{ID: 4}, nil
	case "wireguard":
		return &header.Config{ID: 5}, nil
	default:
		return nil, errors.New("invalid header ", c.Header)
	}
}

type Salamander struct {
	Password   string     `json:"password"`
	PacketSize Int32Range `json:"packetSize"`
}

func (c *Salamander) Build() (proto.Message, error) {
	if c.PacketSize.To > 0 {
		if c.PacketSize.From <= 0 || c.PacketSize.To > 2048 {
			return nil, errors.New("gecko: invalid min/max packet size")
		}
		return &salamander.GeckoConfig{
			Password:      c.Password,
			MinPacketSize: c.PacketSize.From,
			MaxPacketSize: c.PacketSize.To,
		}, nil
	}
	return &salamander.Config{
		Password: c.Password,
	}, nil
}

type Sudoku struct {
	Password string `json:"password"`
	ASCII    string `json:"ascii"`

	CustomTable       string   `json:"customTable"`
	LegacyCustomTable string   `json:"custom_table"`
	CustomTables      []string `json:"customTables"`
	LegacyCustomSets  []string `json:"custom_tables"`

	PaddingMin       uint32 `json:"paddingMin"`
	LegacyPaddingMin uint32 `json:"padding_min"`
	PaddingMax       uint32 `json:"paddingMax"`
	LegacyPaddingMax uint32 `json:"padding_max"`
}

func (c *Sudoku) Build() (proto.Message, error) {
	customTable := c.CustomTable
	if customTable == "" {
		customTable = c.LegacyCustomTable
	}
	customTables := c.CustomTables
	if len(customTables) == 0 {
		customTables = c.LegacyCustomSets
	}

	paddingMin := c.PaddingMin
	if paddingMin == 0 {
		paddingMin = c.LegacyPaddingMin
	}
	paddingMax := c.PaddingMax
	if paddingMax == 0 {
		paddingMax = c.LegacyPaddingMax
	}

	return &sudoku.Config{
		Password:     c.Password,
		Ascii:        c.ASCII,
		CustomTable:  customTable,
		CustomTables: customTables,
		PaddingMin:   paddingMin,
		PaddingMax:   paddingMax,
	}, nil
}

type Xdns struct {
	Domain json.RawMessage `json:"domain"`

	Domains   []string `json:"domains"`
	Resolvers []string `json:"resolvers"`
}

func (c *Xdns) Build() (proto.Message, error) {
	if c.Domain != nil {
		return nil, errors.PrintRemovedFeatureError("domain", "domains(server) & resolvers(client)")
	}

	if len(c.Domains) == 0 && len(c.Resolvers) == 0 {
		return nil, errors.New("empty domains & empty resolvers")
	}

	for _, r := range c.Resolvers {
		if !strings.Contains(r, "+udp://") {
			return nil, errors.New("invalid resolver ", r)
		}
	}

	return &xdns.Config{
		Domains:   c.Domains,
		Resolvers: c.Resolvers,
	}, nil
}

type XMC struct {
	Hostname string       `json:"hostname"`
	Profiles []XMCProfile `json:"profiles"`
	Password string       `json:"password"`
}

type XMCProfile struct {
	// Resolve the UUID by username, then request the session profile with
	// unsigned=false. Client and server must use the same signed profile.
	Username          string `json:"username"`
	UUID              string `json:"uuid"`
	TexturesValue     string `json:"texturesValue"`
	TexturesSignature string `json:"texturesSignature"`
}

var xmcUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

func (c *XMCProfile) Build() (*xmc.Profile, error) {
	if !xmcUsernamePattern.MatchString(c.Username) {
		return nil, fmt.Errorf("invalid minecraft profile username: %q", c.Username)
	}

	profileUUID, err := googleuuid.Parse(c.UUID)
	if err != nil {
		return nil, fmt.Errorf("invalid minecraft profile UUID: %w", err)
	}
	if c.TexturesValue == "" || c.TexturesSignature == "" {
		return nil, fmt.Errorf("incomplete minecraft profile textures")
	}

	return &xmc.Profile{
		Username:          c.Username,
		Uuid:              append([]byte(nil), profileUUID[:]...),
		TexturesValue:     c.TexturesValue,
		TexturesSignature: c.TexturesSignature,
	}, nil
}

func (c *XMC) Build() (proto.Message, error) {
	if len(c.Profiles) == 0 {
		return nil, fmt.Errorf("minecraft profiles are required")
	}

	if c.Password == "" {
		return nil, fmt.Errorf("empty password")
	}

	rsaPrivateKey, err := xmc.DeriveRSAKey(c.Password)
	if err != nil {
		return nil, fmt.Errorf("derive minecraft rsa key: %w", err)
	}

	rsaPublicKey, err := x509.MarshalPKIXPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal minecraft rsa public key: %w", err)
	}

	profiles := make([]*xmc.Profile, 0, len(c.Profiles))
	for i := range c.Profiles {
		profile, err := c.Profiles[i].Build()
		if err != nil {
			return nil, fmt.Errorf("build minecraft profile %d: %w", i, err)
		}
		profiles = append(profiles, profile)
	}

	return &xmc.Config{
		Password:      c.Password,
		Hostname:      c.Hostname,
		RsaPrivateKey: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
		RsaPublicKey:  rsaPublicKey,
		Profiles:      profiles,
	}, nil
}

type Xicmp struct {
	DGRAM bool     `json:"dgram"`
	IPs   []string `json:"ips"`
}

func (c *Xicmp) Build() (proto.Message, error) {
	for _, ip := range c.IPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, err
		}
	}

	config := &xicmp.Config{
		DGRAM: c.DGRAM,
		IPs:   c.IPs,
	}

	return config, nil
}

type Realm struct {
	Url         string     `json:"url"`
	StunServers []string   `json:"stunServers"`
	TlsConfig   *TLSConfig `json:"tlsConfig"`
}

func (c *Realm) Build() (proto.Message, error) {
	var scheme, host, port, token, id string
	var stunServers []string
	var tlsConfig *tls.Config

	u, err := url.Parse(c.Url)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "realm":
		scheme = "https"
	case "realm+http":
		scheme = "http"
	default:
		return nil, errors.New("invalid scheme", u.Scheme)
	}

	host = u.Hostname()
	if host == "" {
		return nil, errors.New("invalid host", host)
	}

	port = u.Port()
	if port == "" {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}

	token, err = url.PathUnescape(u.User.String())
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("invalid token", token)
	}

	id, err = url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/"))
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errors.New("invalid id", id)
	}

	if len(c.StunServers) == 0 {
		return nil, errors.New("empty stunServers")
	}

	for _, s := range c.StunServers {
		_, _, err = net.SplitHostPort(s)
		if err != nil {
			return nil, err
		}
	}

	stunServers = c.StunServers

	if c.TlsConfig != nil {
		tc, err := c.TlsConfig.Build()
		if err != nil {
			return nil, err
		}
		tlsConfig = tc.(*tls.Config)
	}

	return &realm.Config{
		Scheme:      scheme,
		Host:        host,
		Port:        port,
		Token:       token,
		ID:          id,
		StunServers: stunServers,
		TlsConfig:   tlsConfig,
	}, nil
}

type Mask struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

func (c *Mask) Build(tcp bool) (proto.Message, error) {
	loader := udpmaskLoader
	if tcp {
		loader = tcpmaskLoader
	}

	settings := []byte("{}")
	if c.Settings != nil {
		settings = ([]byte)(*c.Settings)
	}
	rawConfig, err := loader.LoadWithID(settings, c.Type)
	if err != nil {
		return nil, err
	}
	ts, err := rawConfig.(Buildable).Build()
	if err != nil {
		return nil, err
	}
	return ts, nil
}

type QuicParamsConfig struct {
	Congestion                  string    `json:"congestion"`
	Debug                       bool      `json:"debug"`
	BbrProfile                  string    `json:"bbrProfile"`
	BrutalUp                    Bandwidth `json:"brutalUp"`
	BrutalDown                  Bandwidth `json:"brutalDown"`
	UdpHop                      UdpHop    `json:"udpHop"`
	InitStreamReceiveWindow     uint64    `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64    `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64    `json:"initConnectionReceiveWindow"`
	MaxConnectionReceiveWindow  uint64    `json:"maxConnectionReceiveWindow"`
	MaxIdleTimeout              int64     `json:"maxIdleTimeout"`
	KeepAlivePeriod             int64     `json:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool      `json:"disablePathMTUDiscovery"`
	MaxIncomingStreams          int64     `json:"maxIncomingStreams"`
}

type FinalMask struct {
	Tcp        []Mask            `json:"tcp"`
	Udp        []Mask            `json:"udp"`
	QuicParams *QuicParamsConfig `json:"quicParams"`
}
