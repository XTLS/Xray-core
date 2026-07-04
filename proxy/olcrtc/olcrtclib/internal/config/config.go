// Package config loads olcrtc runtime configuration from YAML files.
//
// The YAML schema mirrors [session.Config]. Fields left unset in the file
// remain at their zero value. Use [Apply] to map a parsed [File] onto an
// existing [session.Config]; non-zero fields in the session config take
// precedence over the YAML values.
//
//nolint:tagliatelle // YAML keys are the documented config file schema.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/xtls/xray-core/proxy/olcrtc/olcrtclib/internal/app/session"
	"gopkg.in/yaml.v3"
)

var (
	// ErrConfigNotFound is returned when a config file path is set but the file does not exist.
	ErrConfigNotFound = errors.New("config file not found")
	// ErrConfigInvalidUTF8 is returned when a config file is not valid UTF-8.
	ErrConfigInvalidUTF8 = errors.New("config file is not valid UTF-8")
	// ErrCryptoKeyConflict is returned when both inline and file-backed keys are configured.
	ErrCryptoKeyConflict = errors.New("crypto.key and crypto.key_file cannot both be set")
	// ErrCryptoKeyFileEmpty is returned when crypto.key_file points to an empty file.
	ErrCryptoKeyFileEmpty = errors.New("crypto key file is empty")
)

// File is the on-disk YAML schema.
type File struct {
	Mode      string    `yaml:"mode"`
	Auth      Auth      `yaml:"auth"`
	Room      Room      `yaml:"room"`
	Crypto    Crypto    `yaml:"crypto"`
	Net       Net       `yaml:"net"`
	SOCKS     SOCKS     `yaml:"socks"`
	Engine    Engine    `yaml:"engine"`
	Video     Video     `yaml:"video"`
	VP8       VP8       `yaml:"vp8"`
	SEI       SEI       `yaml:"sei"`
	Liveness  Liveness  `yaml:"liveness"`
	Lifecycle Lifecycle `yaml:"lifecycle"`
	Traffic   Traffic   `yaml:"traffic"`
	Gen       Gen       `yaml:"gen"`
	Profiles  []Profile `yaml:"profiles"`
	Failover  Failover  `yaml:"failover"`
	Data      string    `yaml:"data"`
	Debug     bool      `yaml:"debug"`
}

// Profile is a failover entry that overrides top-level runtime fields.
type Profile struct {
	Name      string    `yaml:"name"`
	Auth      Auth      `yaml:"auth"`
	Room      Room      `yaml:"room"`
	Crypto    Crypto    `yaml:"crypto"`
	Net       Net       `yaml:"net"`
	SOCKS     SOCKS     `yaml:"socks"`
	Engine    Engine    `yaml:"engine"`
	Video     Video     `yaml:"video"`
	VP8       VP8       `yaml:"vp8"`
	SEI       SEI       `yaml:"sei"`
	Liveness  Liveness  `yaml:"liveness"`
	Lifecycle Lifecycle `yaml:"lifecycle"`
	Traffic   Traffic   `yaml:"traffic"`
}

// Failover controls ordered profile failover.
type Failover struct {
	RetryDelay string `yaml:"retry_delay"`
	MaxCycles  int    `yaml:"max_cycles"`
}

// Auth selects the auth provider.
type Auth struct {
	Provider string `yaml:"provider"` // telemost, wbstream, none
	Token    string `yaml:"token"`    // optional pre-issued account token (wbstream)
}

// Room identifies the conference room.
type Room struct {
	ID      string `yaml:"id"`
	Channel string `yaml:"channel"`
}

// Crypto holds the shared secret used to authenticate and encrypt the tunnel.
type Crypto struct {
	Key     string `yaml:"key"`      // 64-char hex (32 bytes)
	KeyFile string `yaml:"key_file"` // path to a file containing crypto.key
}

// Net groups network and transport selection.
type Net struct {
	Transport string `yaml:"transport"` // datachannel, videochannel, seichannel, vp8channel
	DNS       string `yaml:"dns"`
}

// SOCKS bundles SOCKS5 listener and outbound-proxy settings.
type SOCKS struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	User      string `yaml:"user"`
	Pass      string `yaml:"pass"`
	ProxyAddr string `yaml:"proxy_addr"`
	ProxyPort int    `yaml:"proxy_port"`
	ProxyUser string `yaml:"proxy_user"`
	ProxyPass string `yaml:"proxy_pass"`
}

// Engine selects a direct SFU connection when Auth.Provider is "none".
type Engine struct {
	Name  string `yaml:"name"` // livekit, goolom, jitsi
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

// Video tunes the videochannel transport.
type Video struct {
	Width      int    `yaml:"width"`
	Height     int    `yaml:"height"`
	FPS        int    `yaml:"fps"`
	Bitrate    string `yaml:"bitrate"`
	HW         string `yaml:"hw"`
	QRSize     int    `yaml:"qr_size"`
	QRRecovery string `yaml:"qr_recovery"`
	Codec      string `yaml:"codec"`
	TileModule int    `yaml:"tile_module"`
	TileRS     int    `yaml:"tile_rs"`
}

// VP8 tunes the vp8channel transport.
type VP8 struct {
	FPS       int `yaml:"fps"`
	BatchSize int `yaml:"batch_size"`
}

// SEI tunes the seichannel transport.
type SEI struct {
	FPS          int `yaml:"fps"`
	BatchSize    int `yaml:"batch_size"`
	FragmentSize int `yaml:"fragment_size"`
	AckTimeoutMS int `yaml:"ack_timeout_ms"`
}

// Liveness tunes the post-handshake control stream ping/pong checks.
type Liveness struct {
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	Failures int    `yaml:"failures"`
}

// Lifecycle controls planned session rebuilds.
type Lifecycle struct {
	MaxSessionDuration string `yaml:"max_session_duration"`
}

// Traffic controls optional reliability-oriented send shaping.
type Traffic struct {
	MaxPayloadSize int    `yaml:"max_payload_size"`
	MinDelay       string `yaml:"min_delay"`
	MaxDelay       string `yaml:"max_delay"`
}

// Gen controls room-generation mode.
type Gen struct {
	Amount int `yaml:"amount"`
}

// Load parses a YAML file from disk.
func Load(path string) (File, error) {
	// #nosec G304 -- config path is an explicit CLI/user input.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return File{}, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return File{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if !utf8.Valid(data) {
		return File{}, fmt.Errorf("parse config %s: %w", path, ErrConfigInvalidUTF8)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := loadExternalSecrets(path, &f); err != nil {
		return File{}, err
	}
	return f, nil
}

func loadExternalSecrets(configPath string, f *File) error {
	if f.Crypto.KeyFile == "" {
		return loadProfileSecrets(configPath, f.Profiles)
	}
	if f.Crypto.Key != "" {
		return ErrCryptoKeyConflict
	}

	key, err := readKeyFile(configPath, f.Crypto.KeyFile)
	if err != nil {
		return err
	}
	f.Crypto.Key = key
	return loadProfileSecrets(configPath, f.Profiles)
}

func loadProfileSecrets(configPath string, profiles []Profile) error {
	for i := range profiles {
		if profiles[i].Crypto.KeyFile == "" {
			continue
		}
		if profiles[i].Crypto.Key != "" {
			return fmt.Errorf("profiles[%d]: %w", i, ErrCryptoKeyConflict)
		}
		key, err := readKeyFile(configPath, profiles[i].Crypto.KeyFile)
		if err != nil {
			return fmt.Errorf("profiles[%d]: %w", i, err)
		}
		profiles[i].Crypto.Key = key
	}
	return nil
}

func readKeyFile(configPath, keyFile string) (string, error) {
	keyPath := keyFile
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(filepath.Dir(configPath), keyPath)
	}

	// #nosec G304 -- key_file is an explicit path in the user's config file.
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read crypto key file %s: %w", keyPath, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", ErrCryptoKeyFileEmpty
	}
	return key, nil
}

// Apply merges f onto dst. CLI-set fields (non-zero values in dst) win;
// YAML values fill in the rest.
func Apply(dst session.Config, f File) session.Config {
	dst.Mode = pickString(dst.Mode, f.Mode)
	dst.Transport = pickString(dst.Transport, f.Net.Transport)
	dst.Auth = pickString(dst.Auth, f.Auth.Provider)
	dst.AuthToken = pickString(dst.AuthToken, f.Auth.Token)
	dst.Engine = pickString(dst.Engine, f.Engine.Name)
	dst.URL = pickString(dst.URL, f.Engine.URL)
	dst.Token = pickString(dst.Token, f.Engine.Token)
	dst.RoomID = pickString(dst.RoomID, f.Room.ID)
	dst.ChannelID = pickString(dst.ChannelID, f.Room.Channel)
	dst.KeyHex = pickString(dst.KeyHex, f.Crypto.Key)
	dst.SOCKSHost = pickString(dst.SOCKSHost, f.SOCKS.Host)
	dst.SOCKSPort = pickInt(dst.SOCKSPort, f.SOCKS.Port)
	dst.SOCKSUser = pickString(dst.SOCKSUser, f.SOCKS.User)
	dst.SOCKSPass = pickString(dst.SOCKSPass, f.SOCKS.Pass)
	dst.DNSServer = pickString(dst.DNSServer, f.Net.DNS)
	dst.SOCKSProxyAddr = pickString(dst.SOCKSProxyAddr, f.SOCKS.ProxyAddr)
	dst.SOCKSProxyPort = pickInt(dst.SOCKSProxyPort, f.SOCKS.ProxyPort)
	dst.SOCKSProxyUser = pickString(dst.SOCKSProxyUser, f.SOCKS.ProxyUser)
	dst.SOCKSProxyPass = pickString(dst.SOCKSProxyPass, f.SOCKS.ProxyPass)
	dst.Video.Width = pickInt(dst.Video.Width, f.Video.Width)
	dst.Video.Height = pickInt(dst.Video.Height, f.Video.Height)
	dst.Video.FPS = pickInt(dst.Video.FPS, f.Video.FPS)
	dst.Video.Bitrate = pickString(dst.Video.Bitrate, f.Video.Bitrate)
	dst.Video.HW = pickString(dst.Video.HW, f.Video.HW)
	dst.Video.QRSize = pickInt(dst.Video.QRSize, f.Video.QRSize)
	dst.Video.QRRecovery = pickString(dst.Video.QRRecovery, f.Video.QRRecovery)
	dst.Video.Codec = pickString(dst.Video.Codec, f.Video.Codec)
	dst.Video.TileModule = pickInt(dst.Video.TileModule, f.Video.TileModule)
	dst.Video.TileRS = pickInt(dst.Video.TileRS, f.Video.TileRS)
	dst.VP8.FPS = pickInt(dst.VP8.FPS, f.VP8.FPS)
	dst.VP8.BatchSize = pickInt(dst.VP8.BatchSize, f.VP8.BatchSize)
	dst.SEI.FPS = pickInt(dst.SEI.FPS, f.SEI.FPS)
	dst.SEI.BatchSize = pickInt(dst.SEI.BatchSize, f.SEI.BatchSize)
	dst.SEI.FragmentSize = pickInt(dst.SEI.FragmentSize, f.SEI.FragmentSize)
	dst.SEI.AckTimeoutMS = pickInt(dst.SEI.AckTimeoutMS, f.SEI.AckTimeoutMS)
	dst.LivenessInterval = pickString(dst.LivenessInterval, f.Liveness.Interval)
	dst.LivenessTimeout = pickString(dst.LivenessTimeout, f.Liveness.Timeout)
	dst.LivenessFailures = pickInt(dst.LivenessFailures, f.Liveness.Failures)
	dst.MaxSessionDuration = pickString(dst.MaxSessionDuration, f.Lifecycle.MaxSessionDuration)
	dst.TrafficMaxPayloadSize = pickInt(dst.TrafficMaxPayloadSize, f.Traffic.MaxPayloadSize)
	dst.TrafficMinDelay = pickString(dst.TrafficMinDelay, f.Traffic.MinDelay)
	dst.TrafficMaxDelay = pickString(dst.TrafficMaxDelay, f.Traffic.MaxDelay)
	dst.Amount = pickInt(dst.Amount, f.Gen.Amount)
	return dst
}

// ApplyProfile overlays a failover profile onto an already-applied base config.
func ApplyProfile(base session.Config, p Profile) session.Config {
	dst := base
	dst.Transport = overlayString(dst.Transport, p.Net.Transport)
	dst.Auth = overlayString(dst.Auth, p.Auth.Provider)
	dst.AuthToken = overlayString(dst.AuthToken, p.Auth.Token)
	dst.Engine = overlayString(dst.Engine, p.Engine.Name)
	dst.URL = overlayString(dst.URL, p.Engine.URL)
	dst.Token = overlayString(dst.Token, p.Engine.Token)
	dst.RoomID = overlayString(dst.RoomID, p.Room.ID)
	dst.ChannelID = overlayString(dst.ChannelID, p.Room.Channel)
	dst.KeyHex = overlayString(dst.KeyHex, p.Crypto.Key)
	dst.SOCKSHost = overlayString(dst.SOCKSHost, p.SOCKS.Host)
	dst.SOCKSPort = overlayInt(dst.SOCKSPort, p.SOCKS.Port)
	dst.SOCKSUser = overlayString(dst.SOCKSUser, p.SOCKS.User)
	dst.SOCKSPass = overlayString(dst.SOCKSPass, p.SOCKS.Pass)
	dst.DNSServer = overlayString(dst.DNSServer, p.Net.DNS)
	dst.SOCKSProxyAddr = overlayString(dst.SOCKSProxyAddr, p.SOCKS.ProxyAddr)
	dst.SOCKSProxyPort = overlayInt(dst.SOCKSProxyPort, p.SOCKS.ProxyPort)
	dst.SOCKSProxyUser = overlayString(dst.SOCKSProxyUser, p.SOCKS.ProxyUser)
	dst.SOCKSProxyPass = overlayString(dst.SOCKSProxyPass, p.SOCKS.ProxyPass)
	dst.Video.Width = overlayInt(dst.Video.Width, p.Video.Width)
	dst.Video.Height = overlayInt(dst.Video.Height, p.Video.Height)
	dst.Video.FPS = overlayInt(dst.Video.FPS, p.Video.FPS)
	dst.Video.Bitrate = overlayString(dst.Video.Bitrate, p.Video.Bitrate)
	dst.Video.HW = overlayString(dst.Video.HW, p.Video.HW)
	dst.Video.QRSize = overlayInt(dst.Video.QRSize, p.Video.QRSize)
	dst.Video.QRRecovery = overlayString(dst.Video.QRRecovery, p.Video.QRRecovery)
	dst.Video.Codec = overlayString(dst.Video.Codec, p.Video.Codec)
	dst.Video.TileModule = overlayInt(dst.Video.TileModule, p.Video.TileModule)
	dst.Video.TileRS = overlayInt(dst.Video.TileRS, p.Video.TileRS)
	dst.VP8.FPS = overlayInt(dst.VP8.FPS, p.VP8.FPS)
	dst.VP8.BatchSize = overlayInt(dst.VP8.BatchSize, p.VP8.BatchSize)
	dst.SEI.FPS = overlayInt(dst.SEI.FPS, p.SEI.FPS)
	dst.SEI.BatchSize = overlayInt(dst.SEI.BatchSize, p.SEI.BatchSize)
	dst.SEI.FragmentSize = overlayInt(dst.SEI.FragmentSize, p.SEI.FragmentSize)
	dst.SEI.AckTimeoutMS = overlayInt(dst.SEI.AckTimeoutMS, p.SEI.AckTimeoutMS)
	dst.LivenessInterval = overlayString(dst.LivenessInterval, p.Liveness.Interval)
	dst.LivenessTimeout = overlayString(dst.LivenessTimeout, p.Liveness.Timeout)
	dst.LivenessFailures = overlayInt(dst.LivenessFailures, p.Liveness.Failures)
	dst.MaxSessionDuration = overlayString(dst.MaxSessionDuration, p.Lifecycle.MaxSessionDuration)
	dst.TrafficMaxPayloadSize = overlayInt(dst.TrafficMaxPayloadSize, p.Traffic.MaxPayloadSize)
	dst.TrafficMinDelay = overlayString(dst.TrafficMinDelay, p.Traffic.MinDelay)
	dst.TrafficMaxDelay = overlayString(dst.TrafficMaxDelay, p.Traffic.MaxDelay)
	return dst
}

func pickString(cli, yamlVal string) string {
	if cli != "" {
		return cli
	}
	return yamlVal
}

func pickInt(cli, yamlVal int) int {
	if cli != 0 {
		return cli
	}
	return yamlVal
}

func overlayString(base, override string) string {
	if override != "" {
		return override
	}
	return base
}

func overlayInt(base, override int) int {
	if override != 0 {
		return override
	}
	return base
}
