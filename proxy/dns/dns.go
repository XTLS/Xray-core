package dns

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	dns_proto "github.com/xtls/xray-core/common/protocol/dns"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/net/dns/dnsmessage"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(dnsClient dns.Client, policyManager policy.Manager) error {
			return h.Init(config.(*Config), dnsClient, policyManager)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
}

type ownLinkVerifier interface {
	IsOwnLink(ctx context.Context) bool
}

type Handler struct {
	client          dns.Client
	ownLinkVerifier ownLinkVerifier
	server          net.Destination
	timeout         time.Duration
	nonIPQuery      string
}

func (h *Handler) Init(config *Config, dnsClient dns.Client, policyManager policy.Manager) error {
	h.client = dnsClient
	h.timeout = policyManager.ForLevel(config.UserLevel).Timeouts.ConnectionIdle

	if v, ok := dnsClient.(ownLinkVerifier); ok {
		h.ownLinkVerifier = v
	}

	if config.Server != nil {
		h.server = config.Server.AsDestination()
	}
	h.nonIPQuery = config.Non_IPQuery
	return nil
}

func (h *Handler) isOwnLink(ctx context.Context) bool {
	return h.ownLinkVerifier != nil && h.ownLinkVerifier.IsOwnLink(ctx)
}

func parseIPQuery(b []byte) (r bool, domain string, id uint16, qType dnsmessage.Type) {
	var parser dnsmessage.Parser
	header, err := parser.Start(b)
	if err != nil {
		newError("parser start").Base(err).WriteToLog()
		return
	}

	id = header.ID
	q, err := parser.Question()
	if err != nil {
		newError("question").Base(err).WriteToLog()
		return
	}
	qType = q.Type
	if qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA {
		return
	}

	domain = q.Name.String()
	r = true
	return
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, d internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("invalid outbound")
	}
	outbound.Name = "dns"

	srcNetwork := outbound.Target.Network

	dest := outbound.Target
	if h.server.Network != net.Network_Unknown {
		dest.Network = h.server.Network
	}
	if h.server.Address != nil {
		dest.Address = h.server.Address
	}
	if h.server.Port != 0 {
		dest.Port = h.server.Port
	}

	newError("handling DNS traffic to ", dest).WriteToLog(session.ExportIDToError(ctx))

	conn := &outboundConn{
		dialer: func() (stat.Connection, error) {
			return d.Dial(ctx, dest)
		},
		connReady: make(chan struct{}, 1),
	}

	var reader dns_proto.MessageReader
	var writer dns_proto.MessageWriter
	if srcNetwork == net.Network_TCP {
		reader = dns_proto.NewTCPReader(link.Reader)
		writer = &dns_proto.TCPWriter{
			Writer: link.Writer,
		}
	} else {
		reader = &dns_proto.UDPReader{
			Reader: link.Reader,
		}
		writer = &dns_proto.UDPWriter{
			Writer: link.Writer,
		}
	}

	var connReader dns_proto.MessageReader
	var connWriter dns_proto.MessageWriter
	if dest.Network == net.Network_TCP {
		connReader = dns_proto.NewTCPReader(buf.NewReader(conn))
		connWriter = &dns_proto.TCPWriter{
			Writer: buf.NewWriter(conn),
		}
	} else {
		connReader = &dns_proto.UDPReader{
			Reader: buf.NewPacketReader(conn),
		}
		connWriter = &dns_proto.UDPWriter{
			Writer: buf.NewWriter(conn),
		}
	}

	if session.TimeoutOnlyFromContext(ctx) {
		ctx, _ = context.WithCancel(context.Background())
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, h.timeout)

	request := func() error {
		defer conn.Close()

		for {
			b, err := reader.ReadMessage()
			if err == io.EOF {
				return nil
			}

			if err != nil {
				return err
			}

			timer.Update()

			if !h.isOwnLink(ctx) {
				isIPQuery, domain, id, qType := parseIPQuery(b.Bytes())
				if isIPQuery {
					go h.handleIPQuery(id, qType, domain, writer)
				}
				if isIPQuery || h.nonIPQuery == "drop" {
					b.Release()
					continue
				}
			}

			if err := connWriter.WriteMessage(b); err != nil {
				return err
			}
		}
	}

	response := func() error {
		for {
			b, err := connReader.ReadMessage()
			if err == io.EOF {
				return nil
			}

			if err != nil {
				return err
			}

			timer.Update()

			if err := writer.WriteMessage(b); err != nil {
				return err
			}
		}
	}

	if err := task.Run(ctx, request, response); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func (h *Handler) handleIPQuery(id uint16, qType dnsmessage.Type, domain string, writer dns_proto.MessageWriter) {
	var ips []net.IP
	var err error

	var ttl uint32 = 600

	switch qType {
	case dnsmessage.TypeA:
		ips, err = h.client.LookupIP(domain, dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: true,
		})
	case dnsmessage.TypeAAAA:
		ips, err = h.client.LookupIP(domain, dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: true,
		})
	}

	rcode := dns.RCodeFromError(err)
	if rcode == 0 && len(ips) == 0 && !errors.AllEqual(dns.ErrEmptyResponse, errors.Cause(err)) {
		newError("ip query").Base(err).WriteToLog()
		return
	}

	switch qType {
	case dnsmessage.TypeA:
		for i, ip := range ips {
			ips[i] = ip.To4()
		}
	case dnsmessage.TypeAAAA:
		for i, ip := range ips {
			ips[i] = ip.To16()
		}
	}

	b := buf.New()
	rawBytes := b.Extend(buf.Size)
	builder := dnsmessage.NewBuilder(rawBytes[:0], dnsmessage.Header{
		ID:                 id,
		RCode:              dnsmessage.RCode(rcode),
		RecursionAvailable: true,
		RecursionDesired:   true,
		Response:           true,
		Authoritative:      true,
	})
	builder.EnableCompression()
	common.Must(builder.StartQuestions())
	common.Must(builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Class: dnsmessage.ClassINET,
		Type:  qType,
	}))
	common.Must(builder.StartAnswers())

	rHeader := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(domain), Class: dnsmessage.ClassINET, TTL: ttl}
	for _, ip := range ips {
		if len(ip) == net.IPv4len {
			var r dnsmessage.AResource
			copy(r.A[:], ip)
			common.Must(builder.AResource(rHeader, r))
		} else {
			var r dnsmessage.AAAAResource
			copy(r.AAAA[:], ip)
			common.Must(builder.AAAAResource(rHeader, r))
		}
	}
	msgBytes, err := builder.Finish()
	if err != nil {
		newError("pack message").Base(err).WriteToLog()
		b.Release()
		return
	}
	b.Resize(0, int32(len(msgBytes)))

	if err := writer.WriteMessage(b); err != nil {
		newError("write IP answer").Base(err).WriteToLog()
	}
}

type outboundConn struct {
	access sync.Mutex
	dialer func() (stat.Connection, error)

	conn      net.Conn
	connReady chan struct{}
}

func (c *outboundConn) dial() error {
	conn, err := c.dialer()
	if err != nil {
		return err
	}
	c.conn = conn
	c.connReady <- struct{}{}
	return nil
}

func (c *outboundConn) Write(b []byte) (int, error) {
	c.access.Lock()

	if c.conn == nil {
		if err := c.dial(); err != nil {
			c.access.Unlock()
			newError("failed to dial outbound connection").Base(err).AtWarning().WriteToLog()
			return len(b), nil
		}
	}

	c.access.Unlock()

	return c.conn.Write(b)
}

func (c *outboundConn) Read(b []byte) (int, error) {
	var conn net.Conn
	c.access.Lock()
	conn = c.conn
	c.access.Unlock()

	if conn == nil {
		_, open := <-c.connReady
		if !open {
			return 0, io.EOF
		}
		conn = c.conn
	}

	return conn.Read(b)
}

func (c *outboundConn) Close() error {
	c.access.Lock()
	close(c.connReady)
	if c.conn != nil {
		c.conn.Close()
	}
	c.access.Unlock()
	return nil
}
