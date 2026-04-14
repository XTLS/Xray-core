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
	"github.com/xtls/xray-core/proxy/xtess"
	"github.com/xtls/xray-core/proxy/xtess/inbound"
	"github.com/xtls/xray-core/proxy/xtess/outbound"
	"google.golang.org/protobuf/proto"
)

const xtessEncryptionPrefix = "mlkem768x25519plus"

type XTessInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

type XTessInboundConfig struct {
	Clients    []json.RawMessage       `json:"clients"`
	Decryption string                  `json:"decryption"`
	Fallbacks  []*XTessInboundFallback `json:"fallbacks"`
	Flow       string                  `json:"flow"`
}

func (c *XTessInboundConfig) Build() (proto.Message, error) {
	config := new(inbound.Config)
	config.Clients = make([]*protocol.User, len(c.Clients))
	switch c.Flow {
	case xtess.None:
		c.Flow = ""
	case "", xtess.XRV:
	default:
		return nil, errors.New(`XTESS "settings.flow" doesn't support "` + c.Flow + `" in this version`)
	}
	for idx, rawUser := range c.Clients {
		user := new(protocol.User)
		if err := json.Unmarshal(rawUser, user); err != nil {
			return nil, errors.New(`XTESS clients: invalid user`).Base(err)
		}
		account := new(xtess.Account)
		if err := json.Unmarshal(rawUser, account); err != nil {
			return nil, errors.New(`XTESS clients: invalid user`).Base(err)
		}

		u, err := uuid.ParseString(account.Id)
		if err != nil {
			return nil, err
		}
		account.Id = u.String()

		switch account.Flow {
		case "":
			account.Flow = c.Flow
		case xtess.None:
			account.Flow = ""
		case xtess.XRV:
		default:
			return nil, errors.New(`XTESS clients: "flow" doesn't support "` + account.Flow + `" in this version`)
		}

		if account.Encryption != "" {
			return nil, errors.New(`XTESS clients: "encryption" should not be in inbound settings`)
		}

		if account.Reverse != nil && account.Reverse.Tag == "" {
			return nil, errors.New(`XTESS clients: "tag" can't be empty for "reverse"`)
		}

		user.Account = serial.ToTypedMessage(account)
		config.Clients[idx] = user
	}

	config.Decryption = c.Decryption
	if !func() bool {
		s := strings.Split(config.Decryption, ".")
		if len(s) < 4 || s[0] != xtessEncryptionPrefix {
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
		t := strings.SplitN(strings.TrimSuffix(s[2], "s"), "-", 2)
		i, err := strconv.Atoi(t[0])
		if err != nil {
			return false
		}
		config.SecondsFrom = int64(i)
		if len(t) == 2 {
			i, err := strconv.Atoi(t[1])
			if err != nil {
				return false
			}
			config.SecondsTo = int64(i)
		}
		padding := 0
		for _, r := range s[3:] {
			if len(r) < 20 {
				padding += len(r) + 1
				continue
			}
			if b, _ := base64.RawURLEncoding.DecodeString(r); len(b) != 32 && len(b) != 64 {
				return false
			}
		}
		config.Decryption = config.Decryption[27+len(s[2]):]
		if padding > 0 {
			config.Padding = config.Decryption[:padding-1]
			config.Decryption = config.Decryption[padding:]
		}
		return true
	}() && config.Decryption != "none" {
		if config.Decryption == "" {
			return nil, errors.New(`XTESS settings: please add/set "decryption":"none" to every settings`)
		}
		return nil, errors.New(`XTESS settings: unsupported "decryption": ` + config.Decryption)
	}

	if config.Decryption != "none" && c.Fallbacks != nil {
		return nil, errors.New(`XTESS settings: "fallbacks" can not be used together with "decryption"`)
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
		if fb.Path != "" && fb.Path[0] != '/' {
			return nil, errors.New(`XTESS fallbacks: "path" must be empty or start with "/"`)
		}
		if fb.Type == "" && fb.Dest != "" {
			if fb.Dest == "serve-ws-none" {
				fb.Type = "serve"
			} else if filepath.IsAbs(fb.Dest) || fb.Dest[0] == '@' {
				fb.Type = "unix"
				if strings.HasPrefix(fb.Dest, "@@") && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
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
			return nil, errors.New(`XTESS fallbacks: please fill in a valid value for every "dest"`)
		}
		if fb.Xver > 2 {
			return nil, errors.New(`XTESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2`)
		}
	}

	return config, nil
}

type XTessOutboundVnext struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type XTessOutboundConfig struct {
	Address    *Address              `json:"address"`
	Port       uint16                `json:"port"`
	Level      uint32                `json:"level"`
	Email      string                `json:"email"`
	Id         string                `json:"id"`
	Flow       string                `json:"flow"`
	Seed       string                `json:"seed"`
	Encryption string                `json:"encryption"`
	Reverse    *xtess.Reverse        `json:"reverse"`
	Vnext      []*XTessOutboundVnext `json:"vnext"`
}

func (c *XTessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)
	if c.Address != nil {
		c.Vnext = []*XTessOutboundVnext{
			{
				Address: c.Address,
				Port:    c.Port,
				Users:   []json.RawMessage{{}},
			},
		}
	}
	if len(c.Vnext) != 1 {
		return nil, errors.New(`XTESS settings: "vnext" should have one and only one member`)
	}
	config.Vnext = make([]*protocol.ServerEndpoint, len(c.Vnext))
	for idx, rec := range c.Vnext {
		if rec.Address == nil {
			return nil, errors.New(`XTESS vnext: "address" is not set`)
		}
		if len(rec.Users) != 1 {
			return nil, errors.New(`XTESS vnext: "users" should have one and only one member`)
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if c.Address != nil {
				user.Level = c.Level
				user.Email = c.Email
			} else {
				if err := json.Unmarshal(rawUser, user); err != nil {
					return nil, errors.New(`XTESS users: invalid user`).Base(err)
				}
			}
			account := new(xtess.Account)
			if c.Address != nil {
				account.Id = c.Id
				account.Flow = c.Flow
				account.Encryption = c.Encryption
				account.Reverse = c.Reverse
			} else {
				if err := json.Unmarshal(rawUser, account); err != nil {
					return nil, errors.New(`XTESS users: invalid user`).Base(err)
				}
			}

			u, err := uuid.ParseString(account.Id)
			if err != nil {
				return nil, err
			}
			account.Id = u.String()

			switch account.Flow {
			case "", xtess.XRV, xtess.XRV + "-udp443":
			default:
				return nil, errors.New(`XTESS users: "flow" doesn't support "` + account.Flow + `" in this version`)
			}

			if !func() bool {
				s := strings.Split(account.Encryption, ".")
				if len(s) < 4 || s[0] != xtessEncryptionPrefix {
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
				padding := 0
				for _, r := range s[3:] {
					if len(r) < 20 {
						padding += len(r) + 1
						continue
					}
					if b, _ := base64.RawURLEncoding.DecodeString(r); len(b) != 32 && len(b) != 1184 {
						return false
					}
				}
				account.Encryption = account.Encryption[27+len(s[2]):]
				if padding > 0 {
					account.Padding = account.Encryption[:padding-1]
					account.Encryption = account.Encryption[padding:]
				}
				return true
			}() && account.Encryption != "none" {
				if account.Encryption == "" {
					return nil, errors.New(`XTESS users: please add/set "encryption":"none" for every user`)
				}
				return nil, errors.New(`XTESS users: unsupported "encryption": ` + account.Encryption)
			}

			if account.Reverse != nil && account.Reverse.Tag == "" {
				return nil, errors.New(`XTESS clients: "tag" can't be empty for "reverse"`)
			}

			user.Account = serial.ToTypedMessage(account)
			spec.User = user
		}
		config.Vnext[idx] = spec
	}

	return config, nil
}
