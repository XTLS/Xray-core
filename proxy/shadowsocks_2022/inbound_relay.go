package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"strconv"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*RelayServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewRelayServer(ctx, config.(*RelayServerConfig))
	}))
}

type relayDest struct {
	destination net.Destination
	email       string
	level       uint32
	key         []byte
	blockCipher cipher.Block
}

type RelayInbound struct {
	networks        []net.Network
	method          *CipherMethod
	relayPSK        []byte
	relayBlock      cipher.Block
	destinations    map[[AESBlockSize]byte]*relayDest
	rawDestinations []*RelayDestination
	policyManager   policy.Manager
}

func NewRelayServer(ctx context.Context, config *RelayServerConfig) (*RelayInbound, error) {
	networks := config.Network
	if len(networks) == 0 {
		networks = []net.Network{
			net.Network_TCP,
			net.Network_UDP,
		}
	}

	method, err := GetCipherMethod(config.Method)
	if err != nil {
		return nil, err
	}
	if method.IsChaCha {
		return nil, errors.New("shadowsocks 2022 relay: only aes methods are supported")
	}

	relayPSK, err := ParseKey(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, err
	}

	relayBlock, err := method.NewBlock(relayPSK)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	i := &RelayInbound{
		networks:        networks,
		method:          method,
		relayPSK:        relayPSK,
		relayBlock:      relayBlock,
		destinations:    make(map[[AESBlockSize]byte]*relayDest),
		rawDestinations: config.Destinations,
		policyManager:   v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	for idx, d := range config.Destinations {
		if d.Email == "" {
			u := uuid.New()
			d.Email = "unnamed-destination-" + strconv.Itoa(idx) + "-" + u.String()
		}
		destKey, err := ParseKey(d.Key, method.KeySaltLength)
		if err != nil {
			return nil, err
		}

		destBlock, err := method.NewBlock(destKey)
		if err != nil {
			return nil, err
		}

		hash := DeriveUserPSKHash(destKey)

		i.destinations[hash] = &relayDest{
			destination: net.TCPDestination(d.Address.AsAddress(), net.Port(d.Port)),
			email:       d.Email,
			level:       uint32(d.Level),
			key:         destKey,
			blockCipher: destBlock,
		}
	}

	return i, nil
}

func (i *RelayInbound) Network() []net.Network {
	return i.networks
}

func (i *RelayInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-relay"
	inbound.CanSpliceCopy = 3

	if network == net.Network_TCP {
		return i.processTCP(ctx, connection, dispatcher)
	}
	return i.processUDP(ctx, connection, dispatcher)
}

func (i *RelayInbound) processTCP(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	defer conn.Close()

	sessionPolicy := i.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// Read Salt + Outer EIH
	needed := i.method.KeySaltLength + AESBlockSize
	var headerBuf [48]byte
	headerSlice := headerBuf[:needed]
	if _, err := io.ReadFull(conn, headerSlice); err != nil {
		return err
	}

	salt := headerSlice[:i.method.KeySaltLength]
	eih := headerSlice[i.method.KeySaltLength:]

	identitySubkey := DeriveIdentitySubKey(i.relayPSK, salt, i.method.KeySaltLength)
	block, err := i.method.NewBlock(identitySubkey)
	if err != nil {
		return err
	}

	var decryptedHash [AESBlockSize]byte
	block.Decrypt(decryptedHash[:], eih)

	targetDest, ok := i.destinations[decryptedHash]
	if !ok {
		return ErrInvalidRequest
	}
	_ = conn.SetReadDeadline(time.Time{})

	inbound := session.InboundFromContext(ctx)
	inbound.User = &protocol.MemoryUser{
		Email: targetDest.email,
		Level: targetDest.level,
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     targetDest.destination,
		Status: log.AccessAccepted,
		Email:  targetDest.email,
	})

	errors.LogInfo(ctx, "relaying connection to ", targetDest.destination)

	link, err := dispatcher.Dispatch(ctx, targetDest.destination)
	if err != nil {
		return err
	}

	// Unwrap outer EIH: send client salt to next hop, stripping this hop's EIH
	saltBuf := buf.New()
	saltBuf.Write(salt)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{saltBuf}); err != nil {
		return err
	}

	sessionPolicy = i.policyManager.ForLevel(targetDest.level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}

	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	return task.Run(ctx, requestDone, responseDoneAndCloseWriter)
}

func (i *RelayInbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	udpConns := utils.NewTypedSyncMap[uint64, *udpConnEntry]()
	defer func() {
		udpConns.Range(func(key uint64, entry *udpConnEntry) bool {
			entry.timer.SetTimeout(0)
			return true
		})
	}()

	reader := buf.NewReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}

		for _, b := range mb {
			data := b.Bytes()
			if len(data) < 2*AESBlockSize {
				b.Release()
				continue
			}

			var packetHeader [AESBlockSize]byte
			i.relayBlock.Decrypt(packetHeader[:], data[:AESBlockSize])

			var eiHeader [AESBlockSize]byte
			i.relayBlock.Decrypt(eiHeader[:], data[AESBlockSize:2*AESBlockSize])
			for idx := 0; idx < AESBlockSize; idx++ {
				eiHeader[idx] ^= packetHeader[idx]
			}

			targetDest, ok := i.destinations[eiHeader]
			if !ok {
				b.Release()
				continue
			}

			// Extract sessionID from raw packetHeader for session-level link caching before re-encrypting
			sessionID := binary.BigEndian.Uint64(packetHeader[:8])

			// Re-encrypt packetHeader with next hop block cipher
			targetDest.blockCipher.Encrypt(packetHeader[:], packetHeader[:])

			// Strip outer EIH: replace second block with re-encrypted packetHeader and advance
			copy(data[AESBlockSize:2*AESBlockSize], packetHeader[:])
			b.Advance(int32(AESBlockSize))

			dest := targetDest.destination
			dest.Network = net.Network_UDP

			entry, ok := udpConns.Load(sessionID)
			if !ok {
				sessCtx, cancel := context.WithCancel(ctx)
				inbound := session.InboundFromContext(sessCtx)
				inbound.User = &protocol.MemoryUser{
					Email: targetDest.email,
					Level: targetDest.level,
				}

				sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
					From:   conn.RemoteAddr(),
					To:     dest,
					Status: log.AccessAccepted,
					Email:  targetDest.email,
				})

				link, err := dispatcher.Dispatch(sessCtx, dest)
				if err != nil {
					cancel()
					b.Release()
					continue
				}

				newEntry := &udpConnEntry{
					link:   link,
					cancel: cancel,
				}
				sessionPolicy := i.policyManager.ForLevel(targetDest.level)
				newEntry.timer = signal.CancelAfterInactivity(sessCtx, func() {
					udpConns.Delete(sessionID)
					common.Interrupt(link.Reader)
					common.Interrupt(link.Writer)
					cancel()
				}, sessionPolicy.Timeouts.ConnectionIdle)

				actual, loaded := udpConns.LoadOrStore(sessionID, newEntry)
				if loaded {
					newEntry.timer.SetTimeout(0)
					entry = actual
				} else {
					entry = newEntry
					go func(cEntry *udpConnEntry) {
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
								_, _ = conn.Write(rb.Bytes())
								rb.Release()
							}
						}
					}(entry)
				}
			}

			entry.timer.Update()
			_ = entry.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b})
		}
	}
}
