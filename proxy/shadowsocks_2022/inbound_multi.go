package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*MultiUserServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewMultiServer(ctx, config.(*MultiUserServerConfig))
	}))
}

type MultiUserInbound struct {
	sync.Mutex
	networks        []net.Network
	method          *CipherMethod
	masterPSK       []byte
	usersByHash     *utils.TypedSyncMap[[AESBlockSize]byte, *protocol.MemoryUser]
	usersByEmail    *utils.TypedSyncMap[string, *protocol.MemoryUser]
	userCount       atomic.Int64
	saltFilter      *antireplay.ReplayFilter[[32]byte]
	udpSessions     *UDPSessionManager
	udpMasterCipher cipher.Block
	policyManager   policy.Manager
}

func NewMultiServer(ctx context.Context, config *MultiUserServerConfig) (*MultiUserInbound, error) {
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
		return nil, errors.New("shadowsocks 2022 multi-user: only aes methods are supported")
	}

	masterPSK, err := ParseKey(config.Key, method.KeySaltLength)
	if err != nil {
		return nil, err
	}

	masterBlock, err := method.NewBlock(masterPSK)
	if err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	i := &MultiUserInbound{
		networks:        networks,
		method:          method,
		masterPSK:       masterPSK,
		usersByHash:     utils.NewTypedSyncMap[[AESBlockSize]byte, *protocol.MemoryUser](),
		usersByEmail:    utils.NewTypedSyncMap[string, *protocol.MemoryUser](),
		saltFilter:      antireplay.NewMapFilter[[32]byte](60),
		udpSessions:     NewUDPSessionManager(500 * time.Second),
		udpMasterCipher: masterBlock,
		policyManager:   v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	for idx, user := range config.Users {
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(idx) + "-" + u.String()
		}
		memUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to parse shadowsocks user").Base(err)
		}
		if err := i.AddUser(ctx, memUser); err != nil {
			return nil, err
		}
	}

	return i, nil
}

// AddUser implements proxy.UserManager.AddUser()
func (i *MultiUserInbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	i.Lock()
	defer i.Unlock()

	var emailKey string
	if u.Email != "" {
		emailKey = strings.ToLower(u.Email)
		if _, exists := i.usersByEmail.Load(emailKey); exists {
			return errors.New("user ", u.Email, " already exists")
		}
	}

	memAcc, ok := u.Account.(*MemoryAccount)
	if !ok {
		return errors.New("missing or invalid user account")
	}

	if len(memAcc.Key) != i.method.KeySaltLength {
		return ErrBadKey
	}

	pskHash := DeriveUserPSKHash(memAcc.Key)
	i.usersByHash.Store(pskHash, u)
	if emailKey != "" {
		i.usersByEmail.Store(emailKey, u)
	}
	i.userCount.Add(1)

	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser()
func (i *MultiUserInbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("email must not be empty")
	}

	i.Lock()
	defer i.Unlock()

	emailKey := strings.ToLower(email)
	u, loaded := i.usersByEmail.LoadAndDelete(emailKey)
	if !loaded {
		return errors.New("user ", email, " not found")
	}

	pskHash := DeriveUserPSKHash(u.Account.(*MemoryAccount).Key)
	i.usersByHash.Delete(pskHash)
	i.userCount.Add(-1)

	return nil
}

// GetUser implements proxy.UserManager.GetUser()
func (i *MultiUserInbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}
	u, _ := i.usersByEmail.Load(strings.ToLower(email))
	return u
}

// GetUsers implements proxy.UserManager.GetUsers()
func (i *MultiUserInbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	var users []*protocol.MemoryUser
	i.usersByEmail.Range(func(_ string, user *protocol.MemoryUser) bool {
		users = append(users, user)
		return true
	})
	return users
}

// GetUsersCount implements proxy.UserManager.GetUsersCount()
func (i *MultiUserInbound) GetUsersCount(context.Context) int64 {
	return i.userCount.Load()
}

func (i *MultiUserInbound) Network() []net.Network {
	return i.networks
}

func (i *MultiUserInbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "shadowsocks-2022-multi"
	inbound.CanSpliceCopy = 3

	if network == net.Network_TCP {
		return i.processTCP(ctx, connection, dispatcher)
	}
	return i.processUDP(ctx, connection, dispatcher)
}

func (i *MultiUserInbound) processTCP(ctx context.Context, conn net.Conn, dispatcher routing.Dispatcher) error {
	defer conn.Close()

	sessionPolicy := i.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	// 1. Read Request Salt (16 or 32 bytes)
	var salt [32]byte
	saltSlice := salt[:i.method.KeySaltLength]
	if _, err := io.ReadFull(conn, saltSlice); err != nil {
		return err
	}

	if !i.saltFilter.Check(salt) {
		return ErrSaltNotUnique
	}

	// 2. Read Extended Identity Header (16 bytes)
	var eih [AESBlockSize]byte
	if _, err := io.ReadFull(conn, eih[:]); err != nil {
		return err
	}

	// Decrypt EIH with IdentitySubKey derived from masterPSK and salt
	identitySubkey := DeriveIdentitySubKey(i.masterPSK, saltSlice, i.method.KeySaltLength)
	block, err := i.method.NewBlock(identitySubkey)
	if err != nil {
		return err
	}

	var decryptedHash [AESBlockSize]byte
	block.Decrypt(decryptedHash[:], eih[:])

	// Lookup user
	user, ok := i.usersByHash.Load(decryptedHash)
	if !ok || user == nil {
		return ErrInvalidRequest
	}
	userPSK := user.Account.(*MemoryAccount).Key

	// 3. Derive Session Subkey using matched user's PSK
	sessionKey := DeriveSessionSubKey(userPSK, saltSlice, i.method.KeySaltLength)
	aead, err := i.method.NewAEAD(sessionKey)
	if err != nil {
		return err
	}

	reader := NewStreamReader(conn, aead)

	// 4 & 5. Read Client Request Header
	reqHeader, err := ReadClientRequestHeader(conn, reader)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	dest := reqHeader.Destination

	// 6. Send Server Response Handshake
	writer, err := WriteTCPResponse(conn, i.method, userPSK, saltSlice, nil)
	if err != nil {
		return err
	}

	// 7. Dispatch Connection to Xray routing with matched User
	inbound := session.InboundFromContext(ctx)
	inbound.User = user

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})

	errors.LogInfo(ctx, "tunneling request to ", dest, " for user ", user.Email)

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

	sessionPolicy = i.policyManager.ForLevel(user.Level)
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

func (i *MultiUserInbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
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
			// In multi-user UDP:
			// Packet header is 16 bytes: Encrypted(SessionID + PacketID)
			// Followed by 16 bytes EIH
			packetBytes := b.Bytes()
			if len(packetBytes) < 32+1+8+2 {
				b.Release()
				continue
			}

			var rawHeader [16]byte
			i.udpMasterCipher.Decrypt(rawHeader[:], packetBytes[:16])

			sessionID := binary.BigEndian.Uint64(rawHeader[:8])
			packetID := binary.BigEndian.Uint64(rawHeader[8:16])

			// Replay protection & session lookup
			sessionItem, _ := i.udpSessions.GetOrCreate(sessionID)

			sessionItem.Lock()
			if !sessionItem.Window.Check(packetID) {
				sessionItem.Unlock()
				b.Release()
				continue
			}

			var userPSK []byte
			var currentUser *protocol.MemoryUser
			if sessionItem.User != nil {
				currentUser = sessionItem.User
				userPSK = sessionItem.UserPSK
				sessionItem.Unlock()
			} else {
				sessionItem.Unlock()
				// Decrypt EIH
				identitySubkey := DeriveIdentitySubKey(i.masterPSK, rawHeader[:8], i.method.KeySaltLength)
				idBlock, err := i.method.NewBlock(identitySubkey)
				if err != nil {
					b.Release()
					continue
				}

				var decryptedHash [16]byte
				idBlock.Decrypt(decryptedHash[:], packetBytes[16:32])

				user, ok := i.usersByHash.Load(decryptedHash)
				if !ok || user == nil {
					b.Release()
					continue
				}
				currentUser = user
				userPSK = user.Account.(*MemoryAccount).Key

				sessionItem.Lock()
				sessionItem.User = user
				sessionItem.UserPSK = userPSK
				sessionItem.Unlock()
			}

			// Decrypt Body (with AEAD caching per session)
			bodyAead := sessionItem.GetRemoteCipher()
			if bodyAead == nil {
				bodyKey := DeriveSessionSubKey(userPSK, rawHeader[:8], i.method.KeySaltLength)
				var err error
				bodyAead, err = i.method.NewAEAD(bodyKey)
				if err != nil {
					b.Release()
					continue
				}
				sessionItem.SetRemoteCipher(bodyAead)
			}

			bodyNonce := rawHeader[4:16]
			bodyCipher := packetBytes[32:]
			bodyPlain, err := bodyAead.Open(nil, bodyNonce, bodyCipher, nil)
			b.Release()
			if err != nil || len(bodyPlain) < 1+8+2 {
				continue
			}

			sessionItem.Lock()
			sessionItem.Window.Add(packetID)
			sessionItem.Unlock()

			if bodyPlain[0] != HeaderTypeClient {
				continue
			}
			epoch := binary.BigEndian.Uint64(bodyPlain[1:9])
			diff := time.Now().Unix() - int64(epoch)
			if diff < -30 || diff > 30 {
				continue
			}

			paddingLen := int(binary.BigEndian.Uint16(bodyPlain[9:11]))
			offset := 11 + paddingLen
			if len(bodyPlain) < offset {
				continue
			}

			dest, addrLen, err := parseAddressPort(bodyPlain[offset:])
			if err != nil {
				continue
			}

			payload := bodyPlain[offset+addrLen:]
			payloadCopy := make([]byte, len(payload))
			copy(payloadCopy, payload)

			entry, ok := udpConns.Load(sessionID)
			if !ok {
				sessCtx, cancel := context.WithCancel(ctx)
				inbound := session.InboundFromContext(sessCtx)
				inbound.User = currentUser

				sessCtx = log.ContextWithAccessMessage(sessCtx, &log.AccessMessage{
					From:   conn.RemoteAddr(),
					To:     dest,
					Status: log.AccessAccepted,
					Email:  currentUser.Email,
				})

				link, err := dispatcher.Dispatch(sessCtx, dest)
				if err != nil {
					cancel()
					continue
				}

				newEntry := &udpConnEntry{
					link:   link,
					cancel: cancel,
				}
				sessionPolicy := i.policyManager.ForLevel(currentUser.Level)
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
					go func(sessID uint64, uPSK []byte, d net.Destination, cEntry *udpConnEntry) {
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
								encPacket, err := i.encodeServerUDPPacket(sessID, uPSK, d, rb.Bytes())
								rb.Release()
								if err != nil {
									continue
								}
								_, _ = conn.Write(encPacket)
							}
						}
					}(sessionID, userPSK, dest, entry)
				}
			}

			entry.timer.Update()
			pBuf := buf.New()
			pBuf.Write(payloadCopy)
			_ = entry.link.Writer.WriteMultiBuffer(buf.MultiBuffer{pBuf})
		}
	}
}

func (i *MultiUserInbound) encodeServerUDPPacket(clientSessionID uint64, userPSK []byte, dest net.Destination, payload []byte) ([]byte, error) {
	sessionItem, _ := i.udpSessions.GetOrCreate(clientSessionID)
	if err := sessionItem.EnsureServerState(i.method, i.udpMasterCipher, nil, userPSK); err != nil {
		return nil, err
	}
	return sessionItem.EncodeServerPacket(i.method, clientSessionID, dest, payload)
}
