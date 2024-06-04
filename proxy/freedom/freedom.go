package freedom

//go:generate go run github.com/GFW-knocker/Xray-core/common/errors/errorgen

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"regexp"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/dice"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/platform"
	"github.com/GFW-knocker/Xray-core/common/retry"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/common/signal"
	"github.com/GFW-knocker/Xray-core/common/task"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/features/dns"
	"github.com/GFW-knocker/Xray-core/features/policy"
	"github.com/GFW-knocker/Xray-core/features/stats"
	"github.com/GFW-knocker/Xray-core/proxy"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/pires/go-proxyproto"
)

var useSplice bool

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager, d dns.Client) error {
			return h.Init(config.(*Config), pm, d)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useSplice = true
	}
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	dns           dns.Client
	config        *Config
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager, d dns.Client) error {
	h.config = config
	h.policyManager = pm
	h.dns = d

	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	if h.config.Timeout > 0 && h.config.UserLevel == 0 {
		p.Timeouts.ConnectionIdle = time.Duration(h.config.Timeout) * time.Second
	}
	return p
}

func (h *Handler) resolveIP(ctx context.Context, domain string, localAddr net.Address) net.Address {
	ips, err := h.dns.LookupIP(domain, dns.IPOption{
		IPv4Enable: (localAddr == nil || localAddr.Family().IsIPv4()) && h.config.preferIP4(),
		IPv6Enable: (localAddr == nil || localAddr.Family().IsIPv6()) && h.config.preferIP6(),
	})
	{ // Resolve fallback
		if (len(ips) == 0 || err != nil) && h.config.hasFallback() && localAddr == nil {
			ips, err = h.dns.LookupIP(domain, dns.IPOption{
				IPv4Enable: h.config.fallbackIP4(),
				IPv6Enable: h.config.fallbackIP6(),
			})
		}
	}
	if err != nil {
		newError("failed to get IP address for domain ", domain).Base(err).WriteToLog(session.ExportIDToError(ctx))
	}
	if len(ips) == 0 {
		return nil
	}
	return net.IPAddress(ips[dice.Roll(len(ips))])
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return newError("target not specified.")
	}
	ob.Name = "freedom"
	ob.CanSpliceCopy = 1
	inbound := session.InboundFromContext(ctx)

	destination := ob.Target
	UDPOverride := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			UDPOverride.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			UDPOverride.Port = destination.Port
		}
	}

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dialDest := destination
		if h.config.hasStrategy() && dialDest.Address.Family().IsDomain() {
			ip := h.resolveIP(ctx, dialDest.Address.Domain(), dialer.Address())
			if ip != nil {
				dialDest = net.Destination{
					Network: dialDest.Network,
					Address: ip,
					Port:    dialDest.Port,
				}
				newError("dialing to ", dialDest).WriteToLog(session.ExportIDToError(ctx))
			} else if h.config.forceIP() {
				return dns.ErrEmptyResponse
			}
		}

		rawConn, err := dialer.Dial(ctx, dialDest)
		if err != nil {
			return err
		}

		if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
			version := byte(h.config.ProxyProtocol)
			srcAddr := inbound.Source.RawNetAddr()
			dstAddr := rawConn.RemoteAddr()
			header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
			if _, err = header.WriteTo(rawConn); err != nil {
				rawConn.Close()
				return err
			}
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return newError("failed to open connection to ", destination).Base(err)
	}
	defer conn.Close()
	newError("connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr()).WriteToLog(session.ExportIDToError(ctx))

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			if h.config.Fragment != nil {
				newError("FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
					h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax).AtDebug().WriteToLog(session.ExportIDToError(ctx))
				writer = buf.NewWriter(&FragmentWriter{
					fragment: h.config.Fragment,
					writer:   conn,
				})
			} else {
				writer = buf.NewWriter(conn)
			}
		} else {
			writer = NewPacketWriter(conn, h, ctx, UDPOverride)
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to process request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if destination.Network == net.Network_TCP {
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil && useSplice {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		reader := NewPacketReader(conn, UDPOverride)
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func NewPacketReader(conn net.Conn, UDPOverride net.Destination) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok && UDPOverride.Address == nil && UDPOverride.Port == 0 {
		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	stats.Counter
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	b.UDP = &net.Destination{
		Address: net.IPAddress(d.(*net.UDPAddr).IP),
		Port:    net.Port(d.(*net.UDPAddr).Port),
		Network: net.Network_UDP,
	}
	if r.Counter != nil {
		r.Counter.Add(int64(n))
	}
	return buf.MultiBuffer{b}, nil
}

func NewPacketWriter(conn net.Conn, h *Handler, ctx context.Context, UDPOverride net.Destination) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		return &PacketWriter{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			Context:           ctx,
			UDPOverride:       UDPOverride,
		}
	}
	return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	stats.Counter
	*Handler
	context.Context
	UDPOverride net.Destination
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var n int
		var err error
		if b.UDP != nil {
			if w.UDPOverride.Address != nil {
				b.UDP.Address = w.UDPOverride.Address
			}
			if w.UDPOverride.Port != 0 {
				b.UDP.Port = w.UDPOverride.Port
			}
			if w.Handler.config.hasStrategy() && b.UDP.Address.Family().IsDomain() {
				ip := w.Handler.resolveIP(w.Context, b.UDP.Address.Domain(), nil)
				if ip != nil {
					b.UDP.Address = ip
				}
			}
			destAddr, _ := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
			if destAddr == nil {
				b.Release()
				continue
			}
			n, err = w.PacketConnWrapper.WriteTo(b.Bytes(), destAddr)
		} else {
			n, err = w.PacketConnWrapper.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if w.Counter != nil {
			w.Counter.Add(int64(n))
		}
	}
	return nil
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.FakeHost {
		if f.count == 1 {
			h1_header := f.fragment.Host1Header
			h1_domain := f.fragment.Host1Domain
			h2_header := f.fragment.Host2Header
			h2_domain := f.fragment.Host2Domain

			// find the old host case-insensitive
			re := regexp.MustCompile("(?i)(\r\nHost:.*\r\n)")
			firstMatch := re.FindSubmatch(b)
			var new_b []byte
			if len(firstMatch) > 1 {
				old_h := firstMatch[1]
				new_h := []byte("\r\n" + h1_header + h1_domain + string(old_h) + h2_header + h2_domain + "\r\n")
				new_b = bytes.Replace(b, old_h, new_h, 1)
			} else {
				new_b = b
			}
			return f.writer.Write(new_b)

		} else {
			return f.writer.Write(b)
		}
	}

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buf := make([]byte, 1024)
		queue := make([]byte, 2048)
		n_queue := int(randBetween(int64(1), int64(4)))
		L_queue := 0
		c_queue := 0
		for from := 0; ; {
			to := from + int(randBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			if to > len(data) {
				to = len(data)
			}
			copy(buf[:3], b)
			copy(buf[5:], data[from:to])
			l := to - from
			from = to
			buf[3] = byte(l >> 8)
			buf[4] = byte(l)

			if c_queue < n_queue {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}
				c_queue = c_queue + 1
			} else {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}

				if L_queue > 0 {
					_, err := f.writer.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
					if err != nil {
						return 0, err
					}
				}

				L_queue = 0
				c_queue = 0

			}

			if from == len(data) {
				if L_queue > 0 {
					_, err := f.writer.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
					L_queue = 0
					c_queue = 0

					if err != nil {
						return 0, err
					}
				}

				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}

	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}
	for from := 0; ; {
		to := from + int(randBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		if to > len(b) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if err != nil {
			return from, err
		}
		if from >= len(b) {
			return from, nil
		}
	}
}

// copy from github.com/GFW-knocker/Xray-core/transport/internet/reality
func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
