package conf

import (
	"encoding/base64"
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
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"google.golang.org/protobuf/proto"
)

type VLessInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

type VLessInboundConfig struct {
	Clients    []json.RawMessage       `json:"clients"`
	Decryption string                  `json:"decryption"`
	Fallbacks  []*VLessInboundFallback `json:"fallbacks"`
	Flow       string                  `json:"flow"`
}

// Build implements Buildable
func (c *VLessInboundConfig) Build() (proto.Message, error) {
	config := new(inbound.Config)
	config.Clients = make([]*protocol.User, len(c.Clients))
	switch c.Flow {
	case vless.None:
		c.Flow = ""
	case "", vless.XRV:
	default:
		return nil, errors.New(`VLESS "settings.flow" doesn't support "` + c.Flow + `" in this version`)
	}
	for idx, rawUser := range c.Clients {
		user := new(protocol.User)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New(`VLESS clients: invalid user`).Base(err)
		}
		account := new(vless.Account)
		if err := json.Unmarshal(rawUser, account); err != nil {
			return nil, errors.New(`VLESS clients: invalid user`).Base(err)
		}

		u, err := uuid.ParseString(account.Id)
		if err != nil {
			return nil, err
		}
		account.Id = u.String()

		switch account.Flow {
		case "":
			account.Flow = c.Flow
		case vless.None:
			account.Flow = ""
		case vless.XRV:
		default:
			return nil, errors.New(`VLESS clients: "flow" doesn't support "` + account.Flow + `" in this version`)
		}

		if account.Encryption != "" {
			return nil, errors.New(`VLESS clients: "encryption" should not in inbound settings`)
		}

		user.Account = serial.ToTypedMessage(account)
		config.Clients[idx] = user
	}

	config.Decryption = c.Decryption
	if !func() bool {
		s := strings.Split(config.Decryption, ".")
		if len(s) < 4 || s[0] != "mlkem768x25519plus" {
			return false
		}
		switch s[1] {
		case "native":
		case "xorpub":
			config.XorMode = 1
		case "random":
			config.XorMode = 2
		default:
			return false
		}
		if s[2] != "1rtt" {
			t := strings.TrimSuffix(s[2], "s")
			if t == s[2] {
				return false
			}
			i, err := strconv.Atoi(t)
			if err != nil {
				return false
			}
			config.Seconds = uint32(i)
		}
		for i := 3; i < len(s); i++ {
			if b, _ := base64.RawURLEncoding.DecodeString(s[i]); len(b) != 32 && len(b) != 64 {
				return false
			}
		}
		config.Decryption = config.Decryption[27+len(s[2]):]
		return true
	}() && config.Decryption != "none" {
		if config.Decryption == "" {
			return nil, errors.New(`VLESS settings: please add/set "decryption":"none" to every settings`)
		}
		return nil, errors.New(`VLESS settings: unsupported "decryption": ` + config.Decryption)
	}

	for _, fb := range c.Fallbacks {
		var i uint16
		var s string
		if err := json.Unmarshal(fb.Dest, &i); err == nil {
			s = strconv.Itoa(int(i))
		} else {
			_ = json.Unmarshal(fb.Dest, &s)
		}
		config.Fallbacks = append(config.Fallbacks, &inbound.Fallback{
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
				return nil, errors.New(`VLESS fallbacks: "alpn":"h2" doesn't support "path"`)
			}
		*/
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, errors.New(`VLESS fallbacks: "path" must be empty or start with "/"`)
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
			return nil, errors.New(`VLESS fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, errors.New(`VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}

	return config, nil
}

type VLessOutboundVnext struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutboundConfig struct {
	Vnext []*VLessOutboundVnext `json:"vnext"`
}

// Build implements Buildable
func (c *VLessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)

	if len(c.Vnext) != 1 {
		return nil, errors.New(`VLESS settings: "vnext" should have one and only one member`)
	}
	config.Vnext = make([]*protocol.ServerEndpoint, len(c.Vnext))
	for idx, rec := range c.Vnext {
		if rec.Address == nil {
			return nil, errors.New(`VLESS vnext: "address" is not set`)
		}
		if len(rec.Users) != 1 {
			return nil, errors.New(`VLESS vnext: "users" should have one and only one member`)
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User:    make([]*protocol.User, len(rec.Users)),
		}
		for idx, rawUser := range rec.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, errors.New(`VLESS users: invalid user`).Base(err)
			}
			account := new(vless.Account)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, errors.New(`VLESS users: invalid user`).Base(err)
			}

			u, err := uuid.ParseString(account.Id)
			if err != nil {
				return nil, err
			}
			account.Id = u.String()

			switch account.Flow {
			case "", vless.XRV, vless.XRV + "-udp443":
			default:
				return nil, errors.New(`VLESS users: "flow" doesn't support "` + account.Flow + `" in this version`)
			}

			if !func() bool {
				s := strings.Split(account.Encryption, ".")
				if len(s) < 4 || s[0] != "mlkem768x25519plus" {
					return false
				}
				switch s[1] {
				case "native":
				case "xorpub":
					account.XorMode = 1
				case "random":
					account.XorMode = 2
				default:
					return false
				}
				switch s[2] {
				case "1rtt":
				case "0rtt":
					account.Seconds = 1
				default:
					return false
				}
				for i := 3; i < len(s); i++ {
					if b, _ := base64.RawURLEncoding.DecodeString(s[i]); len(b) != 32 && len(b) != 1184 {
						return false
					}
				}
				account.Encryption = account.Encryption[27+len(s[2]):]
				return true
			}() && account.Encryption != "none" {
				if account.Encryption == "" {
					return nil, errors.New(`VLESS users: please add/set "encryption":"none" for every user`)
				}
				return nil, errors.New(`VLESS users: unsupported "encryption": ` + account.Encryption)
			}

			user.Account = serial.ToTypedMessage(account)
			spec.User[idx] = user
		}
		config.Vnext[idx] = spec
	}

	return config, nil
}
