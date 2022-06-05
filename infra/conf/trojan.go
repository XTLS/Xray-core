package conf

import (
	"encoding/json"
	"runtime"
	"strconv"
	"syscall"

	"github.com/golang/protobuf/proto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trojan"
)

// TrojanServerTarget is configuration of a single trojan server
type TrojanServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Level    byte     `json:"level"`
	Flow     string   `json:"flow"`
}

// TrojanClientConfig is configuration of trojan servers
type TrojanClientConfig struct {
	Servers []*TrojanServerTarget `json:"servers"`
}

// Build implements Buildable
func (c *TrojanClientConfig) Build() (proto.Message, error) {
	config := new(trojan.ClientConfig)

	if len(c.Servers) == 0 {
		return nil, newError("0 Trojan server configured.")
	}

	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Servers))
	for idx, rec := range c.Servers {
		if rec.Address == nil {
			return nil, newError("Trojan server address is not set.")
		}
		if rec.Port == 0 {
			return nil, newError("Invalid Trojan port.")
		}
		if rec.Password == "" {
			return nil, newError("Trojan password is not specified.")
		}
		account := &trojan.Account{
			Password: rec.Password,
			Flow:     rec.Flow,
		}

		switch account.Flow {
		case "", "xtls-rprx-origin", "xtls-rprx-origin-udp443", "xtls-rprx-direct", "xtls-rprx-direct-udp443":
		case "xtls-rprx-splice", "xtls-rprx-splice-udp443":
			if runtime.GOOS != "linux" && runtime.GOOS != "android" {
				return nil, newError(`Trojan servers: "` + account.Flow + `" only support linux in this version`)
			}
		default:
			return nil, newError(`Trojan servers: "flow" doesn't support "` + account.Flow + `" in this version`)
		}

		trojan := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User: []*protocol.User{
				{
					Level:   uint32(rec.Level),
					Email:   rec.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = trojan
	}

	config.Server = serverSpecs

	return config, nil
}

// TrojanInboundFallback is fallback configuration
type TrojanInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

// TrojanUserConfig is user configuration
type TrojanUserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
	Flow     string `json:"flow"`
}

// TrojanServerConfig is Inbound configuration
type TrojanServerConfig struct {
	Clients   []*TrojanUserConfig      `json:"clients"`
	Fallback  *TrojanInboundFallback   `json:"fallback"`
	Fallbacks []*TrojanInboundFallback `json:"fallbacks"`
}

// Build implements Buildable
func (c *TrojanServerConfig) Build() (proto.Message, error) {
	config := new(trojan.ServerConfig)
	config.Users = make([]*protocol.User, len(c.Clients))
	for idx, rawUser := range c.Clients {
		user := new(protocol.User)
		account := &trojan.Account{
			Password: rawUser.Password,
			Flow:     rawUser.Flow,
		}

		switch account.Flow {
		case "", "xtls-rprx-origin", "xtls-rprx-direct":
		case "xtls-rprx-splice":
			return nil, newError(`Trojan clients: inbound doesn't support "xtls-rprx-splice" in this version, please use "xtls-rprx-direct" instead`)
		default:
			return nil, newError(`Trojan clients: "flow" doesn't support "` + account.Flow + `" in this version`)
		}

		user.Email = rawUser.Email
		user.Level = uint32(rawUser.Level)
		user.Account = serial.ToTypedMessage(account)
		config.Users[idx] = user
	}

	if c.Fallback != nil {
		return nil, newError(`Trojan settings: please use "fallbacks":[{}] instead of "fallback":{}`)
	}
	for _, fb := range c.Fallbacks {
		var i uint16
		var s string
		if err := json.Unmarshal(fb.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(fb.Dest, &s)
		}
		config.Fallbacks = append(config.Fallbacks, &trojan.Fallback{
			Name: fb.Name,
			Alpn: fb.Alpn,
			Path: fb.Path,
			Type: fb.Type,
			Dest: s,
			Xver: fb.Xver,
		})
	}
	for _, fb := range config.Fallbacks {
		/*
			if fb.Alpn == "h2" && fb.Path != "" {
				return nil, newError(`Trojan fallbacks: "alpn":"h2" doesn't support "path"`)
			}
		*/
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, newError(`Trojan fallbacks: "path" must be empty or start with "/"`)
		}
		if fb.Type == "" && fb.Dest != "" {
			if fb.Dest == "serve-ws-none" {
				fb.Type = "serve"
			} else {
				switch fb.Dest[0] {
				case '@', '/':
					fb.Type = "unix"
					if fb.Dest[0] == '@' && len(fb.Dest) > 1 && fb.Dest[1] == '@' && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
						fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
						copy(fullAddr, fb.Dest[1:])
						fb.Dest = string(fullAddr)
					}
				default:
					if _, err := strconv.Atoi(fb.Dest); err == nil {
						fb.Dest = "127.0.0.1:" + fb.Dest
					}
					if _, _, err := net.SplitHostPort(fb.Dest); err == nil {
						fb.Type = "tcp"
					}
				}
			}
		}
		if fb.Type == "" {
			return nil, newError(`Trojan fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, newError(`Trojan fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}

	return config, nil
}
