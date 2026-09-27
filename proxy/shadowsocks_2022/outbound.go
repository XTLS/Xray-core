package shadowsocks_2022

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

type Outbound struct {
	server        net.Destination
	method        *CipherMethod
	pskList       [][]byte
	finalPSK      []byte
	udpCodec      *UDPPacketCodec
	policyManager policy.Manager
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	method, err := GetCipherMethod(config.Method)
	if err != nil {
		return nil, errors.New("unsupported method: ", config.Method).Base(err)
	}

	pskList, err := ParsePSKList(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, errors.New("invalid key: ", config.Key).Base(err)
	}

	finalPSK := pskList[len(pskList)-1]
	udpCodec, err := NewUDPPacketCodec(method, finalPSK)
	if err != nil {
		return nil, errors.New("failed to create udp packet codec").Base(err)
	}

	v := core.MustFromContext(ctx)
	return &Outbound{
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
		method:        method,
		pskList:       pskList,
		finalPSK:      finalPSK,
		udpCodec:      udpCodec,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "shadowsocks-2022"
	ob.CanSpliceCopy = 3
	destination := ob.Target
	network := destination.Network

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", o.server.NetAddr())

	serverDestination := o.server
	serverDestination.Network = network

	var conn net.Conn
	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, serverDestination)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	}); err != nil {
		return errors.New("failed to find an available destination").Base(err)
	}
	defer conn.Close()

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := o.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	if newCtx != nil {
		ctx = newCtx
	}

	if network == net.Network_TCP {
		var clientSalt [32]byte
		clientSaltSlice := clientSalt[:o.method.KeySaltLength]
		if _, err := io.ReadFull(rand.Reader, clientSaltSlice); err != nil {
			return errors.New("failed to generate client salt").Base(err)
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
			bodyWriter, err := WriteTCPRequest(bufferedWriter, o.method, o.pskList, destination, clientSaltSlice, nil)
			if err != nil {
				return errors.New("failed to write request").Base(err)
			}

			if err = buf.CopyOnceTimeout(link.Reader, bodyWriter, time.Millisecond*100); err != nil && err != buf.ErrNotTimeoutReader && err != buf.ErrReadTimeout {
				return errors.New("failed to write A request payload").Base(err)
			}

			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}

			return buf.Copy(link.Reader, bodyWriter, buf.UpdateActivity(timer))
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			responseReader, err := ReadTCPResponse(conn, o.method, o.finalPSK, clientSaltSlice)
			if err != nil {
				return err
			}

			return buf.Copy(responseReader, link.Writer, buf.UpdateActivity(timer))
		}

		responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
			return errors.New("connection ends").Base(err)
		}

		return nil
	}

	if network == net.Network_UDP {
		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			writer := &UDPWriter{
				Writer:      conn,
				Destination: destination,
				Codec:       o.udpCodec,
			}

			if err := buf.Copy(link.Reader, writer, buf.UpdateActivity(timer)); err != nil {
				return errors.New("failed to transport all UDP request").Base(err)
			}
			return nil
		}

		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			reader := &UDPReader{
				Reader: conn,
				Codec:  o.udpCodec,
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

	return errors.New("unsupported network: ", network)
}
