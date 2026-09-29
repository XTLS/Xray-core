package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
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
		return errors.New("unable to set read deadline").Base(err)
	}

	// 1. Single read call for Salt + EIH + Fixed-length header chunk per SIP022 §3.1.4
	headerLen := i.method.KeySaltLength + AESBlockSize + RequestHeaderFixedChunkLength + AEADTagSize
	headerBuf := make([]byte, headerLen)
	n, err := conn.Read(headerBuf)
	if err != nil || n < headerLen {
		ResetTCPConn(conn)
		return errors.New("failed to read complete handshake header")
	}

	var salt [32]byte
	copy(salt[:i.method.KeySaltLength], headerBuf[:i.method.KeySaltLength])
	saltSlice := salt[:i.method.KeySaltLength]
	eih := headerBuf[i.method.KeySaltLength : i.method.KeySaltLength+AESBlockSize]
	fixedChunk := headerBuf[i.method.KeySaltLength+AESBlockSize:]

	decryptedHash, err := DecryptEIH(i.method, i.masterPSK, saltSlice, eih)
	if err != nil {
		ResetTCPConn(conn)
		return err
	}

	// Lookup user
	user, ok := i.usersByHash.Load(decryptedHash)
	if !ok {
		ResetTCPConn(conn)
		return ErrInvalidRequest
	}
	userPSK := user.Account.(*MemoryAccount).Key

	reader, reqHeader, err := InitServerStream(conn, i.method, userPSK, saltSlice, salt, fixedChunk, i.saltFilter)
	if err != nil {
		ResetTCPConn(conn)
		return err
	}

	dest := reqHeader.Destination

	writer := NewServerStreamWriter(conn, i.method, userPSK, saltSlice)

	// Dispatch Connection to Xray routing with matched User
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
		mb := buf.MergeBytes(nil, reqHeader.EarlyData)
		if err := link.Writer.WriteMultiBuffer(mb); err != nil {
			return err
		}
	}

	return TransportTCP(ctx, i.policyManager.ForLevel(user.Level), reader, writer, link)
}

func (i *MultiUserInbound) processUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	reader := buf.NewPacketReader(conn)
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

			sessionItem := i.udpSessions.GetOrCreate(sessionID)

			if !sessionItem.CheckPacketID(packetID) {
				b.Release()
				continue
			}

			var userPSK []byte
			var currentUser *protocol.MemoryUser
			sessionItem.Lock()
			currentUser = sessionItem.User
			userPSK = sessionItem.UserPSK
			sessionItem.Unlock()

			if currentUser == nil {
				// Decrypt EIH
				decryptedHash := DecryptUDPEIH(i.udpMasterCipher, rawHeader[:], packetBytes[16:32])

				user, ok := i.usersByHash.Load(decryptedHash)
				if !ok {
					b.Release()
					continue
				}
				currentUser = user
				userPSK = user.Account.(*MemoryAccount).Key
			}

			decoded, err := sessionItem.DecryptAESPayload(i.method, userPSK, sessionID, packetID, rawHeader[:], packetBytes[32:])
			b.Release()
			if err != nil {
				continue
			}

			sessionItem.Lock()
			if sessionItem.User == nil {
				sessionItem.User = currentUser
				sessionItem.UserPSK = userPSK
			}
			sessionItem.Unlock()

			link, err := sessionItem.EnsureLink(ctx, conn, decoded.Destination, dispatcher, i.policyManager, func(replyDest net.Destination, payload []byte) ([]byte, error) {
				return i.encodeServerUDPPacket(sessionID, userPSK, replyDest, payload)
			})
			if err != nil {
				continue
			}

			pBuf := buf.New()
			pBuf.Write(decoded.Payload)
			pBuf.UDP = &decoded.Destination
			_ = link.Writer.WriteMultiBuffer(buf.MultiBuffer{pBuf})
		}
	}
}

func (i *MultiUserInbound) encodeServerUDPPacket(clientSessionID uint64, userPSK []byte, dest net.Destination, payload []byte) ([]byte, error) {
	return i.udpSessions.EncodeServerPacket(i.method, userPSK, clientSessionID, dest, payload)
}
