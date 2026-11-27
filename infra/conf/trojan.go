package conf

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/proxy/trojan"
	"google.golang.org/protobuf/proto"
)

// TrojanClientConfig is configuration of trojan servers
type TrojanClientConfig struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
}

// Build implements Buildable
func (c *TrojanClientConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("Trojan (with no Flow, etc.)", "VLESS with Flow & Seed")

	config := &trojan.ClientConfig{}

	if c.Address == nil {
		return nil, errors.New("Trojan server address is not set.")
	}
	if c.Port == 0 {
		return nil, errors.New("Invalid Trojan port.")
	}
	if c.Password == "" {
		return nil, errors.New("Trojan password is not specified.")
	}

	config.Server = &protocol.ServerEndpoint{
		Address: c.Address.Build(),
		Port:    uint32(c.Port),
		User: &protocol.User{
			Level: uint32(c.Level),
			Email: c.Email,
			Account: serial.ToTypedMessage(&trojan.Account{
				Password: c.Password,
			}),
		},
	}

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
}

// TrojanServerConfig is Inbound configuration
type TrojanServerConfig struct {
	Users     []*TrojanUserConfig      `json:"users"`
	Clients   []*TrojanUserConfig      `json:"clients"`
	Fallbacks []*TrojanInboundFallback `json:"fallbacks"`
}

// Build implements Buildable
func (c *TrojanServerConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("Trojan (with no Flow, etc.)", "VLESS with Flow & Seed")

	if c.Clients != nil {
		c.Users = c.Clients
	}

	config := &trojan.ServerConfig{
		Users: make([]*protocol.User, len(c.Users)),
	}

	processClient := func(idx int) error {
		rawUser := c.Users[idx]

		config.Users[idx] = &protocol.User{
			Level: uint32(rawUser.Level),
			Email: rawUser.Email,
			Account: serial.ToTypedMessage(&trojan.Account{
				Password: rawUser.Password,
			}),
		}
		return nil
	}
	if err := task.ParallelForN(len(c.Users), processClient); err != nil {
		return nil, err
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
				return nil, errors.New(`Trojan fallbacks: "alpn":"h2" doesn't support "path"`)
			}
		*/
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, errors.New(`Trojan fallbacks: "path" must be empty or start with "/"`)
		}
		if fb.Type == "" && fb.Dest != "" {
			if fb.Dest == "serve-ws-none" {
				fb.Type = "serve"
			} else if filepath.IsAbs(fb.Dest) || fb.Dest[0] == '@' {
				fb.Type = "unix"
				if strings.HasPrefix(fb.Dest, "@@") && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path)) // may need padding to work with haproxy
					copy(fullAddr, fb.Dest[1:])
					fb.Dest = string(fullAddr)
				}
			} else {
				if _, err := strconv.Atoi(fb.Dest); err == nil {
					fb.Dest = "localhost:" + fb.Dest
				}
				if _, _, err := net.SplitHostPort(fb.Dest); err == nil {
					fb.Type = "tcp"
				}
			}
		}
		if fb.Type == "" {
			return nil, errors.New(`Trojan fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, errors.New(`Trojan fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}

	return config, nil
}
