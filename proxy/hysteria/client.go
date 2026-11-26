package hysteria

import (
	"context"
	go_errors "errors"
	"io"
	"math/rand"
	"slices"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*hysteria.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}
	if config.Server == nil {
		return nil, errors.New(`no target server found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}

	return &Client{
		server:        server,
		policyManager: p,
	}, nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "hysteria"
	ob.CanSpliceCopy = 3
	target := ob.Target

	conn, err := dialer.Dial(hysteria.ContextWithDatagram(ctx, target.Network == net.Network_UDP), c.server.Destination)
	if err != nil {
		return errors.New("failed to find an available destination").Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", target.Network, ":", c.server.Destination.NetAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	if newCtx != nil {
		ctx = newCtx
	}

	if target.Network == net.Network_TCP {
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
			err := WriteTCPRequest(bufferedWriter, target.NetAddr())
			if err != nil {
				return errors.New("failed to write request").Base(err)
			}
			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}
			return buf.Copy(link.Reader, bufferedWriter, buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			ok, msg, err := ReadTCPResponse(conn)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New(msg)
			}
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	if target.Network == net.Network_UDP {
		iConn := stat.TryUnwrapStatsConn(conn)
		_, ok := iConn.(*hysteria.InterConn)
		if !ok {
			return errors.New("udp requires hysteria udp transport")
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			writer := &UDPWriter{
				writer: conn,
				addr:   target.NetAddr(),
			}

			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP request").Base(err)
			}

			return nil
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			reader := &UDPReader{
				reader: conn,
				df:     &Defragger{},
			}

			if err := buf.Copy(reader, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP response").Base(err)
			}

			return nil
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// UDPWriter is not safe for concurrent writes.
type UDPWriter struct {
	writer io.Writer
	addr   string
	buf    [buf.Size]byte

	// Last b.UDP and its NetAddr, which allocates on every call.
	lastUDP     net.Destination
	lastUDPAddr string
}

func (w *UDPWriter) SendMessage(msg *UDPMessage) error {
	msgN := msg.Serialize(w.buf[:])
	if msgN < 0 {
		return nil
	}
	_, err := w.writer.Write(w.buf[:msgN])
	return err
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		addr := w.addr
		if b.UDP != nil {
			if *b.UDP != w.lastUDP {
				w.lastUDP = *b.UDP
				w.lastUDPAddr = b.UDP.NetAddr()
			}
			addr = w.lastUDPAddr
		}

		msg := &UDPMessage{
			FragCount: 1,
			Addr:      addr,
			Data:      b.Bytes(),
		}

		err := w.SendMessage(msg)
		if errTooLarge, ok := go_errors.AsType[*quic.DatagramTooLargeError](err); ok {
			msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
			fMsgs := FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
			for _, fMsg := range fMsgs {
				err := w.SendMessage(&fMsg)
				if err != nil {
					buf.ReleaseMulti(mb[i:])
					return err
				}
			}
		} else if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}

		b.Release()
	}

	return nil
}

// UDPReader is not safe for concurrent reads.
type UDPReader struct {
	reader   io.Reader
	df       *Defragger
	firstBuf *buf.Buffer

	// Last message address and its parsed destination.
	lastAddr string
	lastDest net.Destination

	packet [1500]byte
	msg    UDPMessage
}

func (r *UDPReader) ReadFrom(p []byte) (n int, addr *net.Destination, err error) {
	for {
		n, err := r.reader.Read(r.packet[:])
		if err != nil {
			return 0, nil, err
		}

		if err := parseUDPMessage(r.packet[:n], r.lastAddr, &r.msg); err != nil {
			continue
		}

		msg := &r.msg
		if msg.FragCount > 1 {
			// The defragger keeps fragments between calls, so they must not alias packet.
			frag := *msg
			frag.Data = slices.Clone(msg.Data)
			msg = &frag
		}

		dfMsg := r.df.Feed(msg)
		if dfMsg == nil {
			continue
		}

		if dfMsg.Addr != r.lastAddr {
			dest, err := net.ParseDestination("udp:" + dfMsg.Addr)
			if err != nil {
				continue
			}
			r.lastAddr = dfMsg.Addr
			r.lastDest = dest
		}

		if len(p) < len(dfMsg.Data) {
			continue
		}

		// Callers can rewrite the packet destination in place.
		dest := r.lastDest
		return copy(p, dfMsg.Data), &dest, nil
	}
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.firstBuf != nil {
		mb := buf.MultiBuffer{r.firstBuf}
		r.firstBuf = nil
		return mb, nil
	}
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := r.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	b.UDP = addr
	return buf.MultiBuffer{b}, nil
}
