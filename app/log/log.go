package log

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

// Instance is a log.Handler that handles logs.
type Instance struct {
	sync.RWMutex
	config       *Config
	accessLogger log.Handler
	errorLogger  log.Handler
	active       bool
	dns          bool
}

// New creates a new log.Instance based on the given config.
func New(ctx context.Context, config *Config) (*Instance, error) {
	g := &Instance{
		config: config,
		active: false,
		dns:    config.EnableDnsLog,
	}
	log.RegisterHandler(g)

	// start logger now,
	// then other modules will be able to log during initialization
	if err := g.startInternal(); err != nil {
		return nil, err
	}

	errors.LogDebug(ctx, "Logger started")
	return g, nil
}

func (g *Instance) initAccessLogger() error {
	handler, err := createHandler(g.config.AccessLogType, HandlerCreatorOptions{
		Path: g.config.AccessLogPath,
	})
	if err != nil {
		return err
	}
	g.accessLogger = handler
	return nil
}

func (g *Instance) initErrorLogger() error {
	handler, err := createHandler(g.config.ErrorLogType, HandlerCreatorOptions{
		Path: g.config.ErrorLogPath,
	})
	if err != nil {
		return err
	}
	g.errorLogger = handler
	return nil
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return (*Instance)(nil)
}

func (g *Instance) startInternal() error {
	g.Lock()
	defer g.Unlock()

	if g.active {
		return nil
	}

	g.active = true

	if err := g.initAccessLogger(); err != nil {
		return errors.New("failed to initialize access logger").Base(err).AtWarning()
	}
	if err := g.initErrorLogger(); err != nil {
		return errors.New("failed to initialize error logger").Base(err).AtWarning()
	}

	return nil
}

// Start implements common.Runnable.Start().
func (g *Instance) Start() error {
	return g.startInternal()
}

// Handle implements log.Handler.
func (g *Instance) Handle(msg log.Message) {
	g.RLock()
	defer g.RUnlock()

	if !g.active {
		return
	}

	var Msg log.Message
	if g.config.MaskAddress != "" {
		Msg = &MaskedMsgWrapper{Message: msg, config: g.config}
	} else {
		Msg = msg
	}

	switch msg := msg.(type) {
	case *log.AccessMessage:
		if g.accessLogger != nil {
			g.accessLogger.Handle(Msg)
		}
	case *log.DNSLog:
		if g.dns && g.accessLogger != nil {
			g.accessLogger.Handle(Msg)
		}
	case *log.GeneralMessage:
		if g.errorLogger != nil && msg.Severity <= g.config.ErrorLogLevel {
			g.errorLogger.Handle(Msg)
		}
	default:
		// Swallow
	}
}

// Close implements common.Closable.Close().
func (g *Instance) Close() error {
	errors.LogDebug(context.Background(), "Logger closing")

	g.Lock()
	defer g.Unlock()

	if !g.active {
		return nil
	}

	g.active = false

	common.Close(g.accessLogger)
	g.accessLogger = nil

	common.Close(g.errorLogger)
	g.errorLogger = nil

	return nil
}

// MaskedMsgWrapper is to wrap the string() method to mask IP addresses in the log.
type MaskedMsgWrapper struct {
	log.Message
	config *Config
}

func (m *MaskedMsgWrapper) String() string {
	str := m.Message.String()

	ipv4Regex := regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	ipv6Regex := regexp.MustCompile(`((?:[\da-fA-F]{0,4}:[\da-fA-F]{0,4}){2,7})(?:[\/\\%](\d{1,3}))?`)

	// Process ipv4
	maskedMsg := ipv4Regex.ReplaceAllStringFunc(str, func(ip string) string {
		parts := strings.Split(ip, ".")
		switch m.config.MaskAddress {
		case "half":
			return fmt.Sprintf("%s.%s.*.*", parts[0], parts[1])
		case "quarter":
			return fmt.Sprintf("%s.*.*.*", parts[0])
		case "full":
			return "[Masked IPv4]"
		default:
			return ip
		}
	})

	// process ipv6
	maskedMsg = ipv6Regex.ReplaceAllStringFunc(maskedMsg, func(ip string) string {
		parts := strings.Split(ip, ":")
		switch m.config.MaskAddress {
		case "half":
			if len(parts) >= 2 {
				return fmt.Sprintf("%s:%s::/32", parts[0], parts[1])
			}
		case "quarter":
			if len(parts) >= 1 {
				return fmt.Sprintf("%s::/16", parts[0])
			}
		case "full":
			return "Masked IPv6" // Do not use [Masked IPv6] like ipv4, or you will get "[[Masked IPv6]]" (v6 address already has [])
		default:
			return ip
		}
		return ip
	})

	return maskedMsg
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
