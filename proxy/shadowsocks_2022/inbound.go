package shadowsocks_2022

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type Inbound struct {
	networks      []net.Network
	method        *CipherMethod
	psk           []byte
	user          *protocol.MemoryUser
	saltFilter    *antireplay.ReplayFilter[[32]byte]
	udpCodec      *UDPServerCodec
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}

	method, err := GetCipherMethod(config.Method)
	if err != nil {
		return nil, errors.New("unsupported method: ", config.Method).Base(err)
	}

	psk, err := ParseKey(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, err
	}

	udpCodec, err := NewUDPServerCodec(method, psk, 500*time.Second)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	return &Inbound{
		networks:   networks,
		method:     method,
		psk:        psk,
		saltFilter: antireplay.NewMapFilter[[32]byte](60),
		user: &protocol.MemoryUser{
			Email: config.Email,
			Level: uint32(config.Level),
		},
		udpCodec:      udpCodec,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func (i *Inbound) Network() []net.Network {
	return i.networks
}

func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022"
	inbound.CanSpliceCopy = 3

	if network == net.Network_TCP {
		return i.processTCP(ctx, connection, dispatcher)
	}
	return i.processUDP(ctx, connection, dispatcher)
}

func (i *Inbound) processTCP(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	defer conn.Close()

	sessionPolicy := i.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	var salt [32]byte
	saltSlice := salt[:i.method.KeySaltLength]
	if _, err := io.ReadFull(conn, saltSlice); err != nil {
		return err
	}

	if !i.saltFilter.Check(salt) {
		return ErrSaltNotUnique
	}

	sessionKey := DeriveSessionSubKey(i.psk, saltSlice, i.method.KeySaltLength)
	aead, err := i.method.NewAEAD(sessionKey)
	if err != nil {
		return err
	}

	reader := NewStreamReader(conn, aead)

	reqHeader, err := ReadClientRequestHeader(conn, reader)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	dest := reqHeader.Destination

	writer, err := WriteTCPResponse(conn, i.method, i.psk, saltSlice, nil)
	if err != nil {
		return err
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = new(session.Inbound)
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.User = i.user

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  i.user.Email,
	})

	errors.LogInfo(ctx, "tunneling request to ", dest)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	if len(reqHeader.EarlyData) > 0 {
		earlyBuf := buf.New()
		earlyBuf.Write(reqHeader.EarlyData)
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{earlyBuf}); err != nil {
			return err
		}
	}

	sessionPolicy = i.policyManager.ForLevel(uint32(i.user.Level))
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	return task.Run(ctx, requestDone, responseDoneAndCloseWriter)
}

func (i *Inbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	udpConns := utils.NewTypedSyncMap[uint64, *udpConnEntry]()
	defer func() {
		udpConns.Range(func(key uint64, entry *udpConnEntry) bool {
			entry.timer.SetTimeout(0)
			return true
		})
	}()

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = new(session.Inbound)
		ctx = session.ContextWithInbound(ctx, inbound)
	}
	inbound.User = i.user

	reader := buf.NewReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}

		for _, b := range mb {
			decoded, err := i.udpCodec.DecodePacket(b.Bytes())
			if err != nil {
				b.Release()
				continue
			}

			entry, ok := udpConns.Load(decoded.SessionID)
			if !ok {
				sessCtx, cancel := context.WithCancel(ctx)
				sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
					From:   conn.RemoteAddr(),
					To:     decoded.Destination,
					Status: log.AccessAccepted,
					Email:  i.user.Email,
				})

				link, err := dispatcher.Dispatch(sessCtx, decoded.Destination)
				if err != nil {
					cancel()
					b.Release()
					continue
				}

				newEntry := &udpConnEntry{
					link:   link,
					cancel: cancel,
				}
				sessionPolicy := i.policyManager.ForLevel(uint32(i.user.Level))
				newEntry.timer = signal.CancelAfterInactivity(sessCtx, func() {
					udpConns.Delete(decoded.SessionID)
					common.Interrupt(link.Reader)
					common.Interrupt(link.Writer)
					cancel()
				}, sessionPolicy.Timeouts.ConnectionIdle)

				actual, loaded := udpConns.LoadOrStore(decoded.SessionID, newEntry)
				if loaded {
					// Another goroutine/packet beat us to storing, terminate our redundant link
					newEntry.timer.SetTimeout(0)
					entry = actual
				} else {
					entry = newEntry
					go func(sessID uint64, dest net.Destination, cEntry *udpConnEntry) {
						defer func() {
							cEntry.timer.SetTimeout(0)
						}()
						for {
							resMb, err := cEntry.link.Reader.ReadMultiBuffer()
							if err != nil {
								return
							}
							cEntry.timer.Update()
							for _, rb := range resMb {
								encPacket, err := i.udpCodec.EncodePacket(sessID, dest, rb.Bytes())
								rb.Release()
								if err != nil {
									continue
								}
								_, _ = conn.Write(encPacket)
							}
						}
					}(decoded.SessionID, decoded.Destination, entry)
				}
			}

			entry.timer.Update()
			payloadBuf := buf.New()
			payloadBuf.Write(decoded.Payload)
			b.Release()
			_ = entry.link.Writer.WriteMultiBuffer(buf.MultiBuffer{payloadBuf})
		}
	}
}
