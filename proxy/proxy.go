// Package proxy contains all proxies used by Xray.
//
// To implement an inbound or outbound proxy, one needs to do the following:
// 1. Implement the interface(s) below.
// 2. Register a config creator through common.RegisterConfig.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"runtime"
	"strconv"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var (
	Tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	TlsClientHandShakeStart = []byte{0x16, 0x03}
	TlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	TlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

	Tls13CipherSuiteDic = map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256",
	}
)

const (
	TlsHandshakeTypeClientHello byte = 0x01
	TlsHandshakeTypeServerHello byte = 0x02

	CommandPaddingContinue byte = 0x00
	CommandPaddingEnd      byte = 0x01
	CommandPaddingDirect   byte = 0x02
)

// An Inbound processes inbound connections.
type Inbound interface {
	// Network returns a list of networks that this inbound supports. Connections with not-supported networks will not be passed into Process().
	Network() []net.Network

	// Process processes a connection of given network. If necessary, the Inbound can dispatch the connection to an Outbound.
	Process(context.Context, net.Network, stat.Connection, routing.Dispatcher) error
}

// An Outbound process outbound connections.
type Outbound interface {
	// Process processes the given connection. The given dialer may be used to dial a system outbound connection.
	Process(context.Context, *transport.Link, internet.Dialer) error
}

// UserManager is the interface for Inbounds and Outbounds that can manage their users.
type UserManager interface {
	// AddUser adds a new user.
	AddUser(context.Context, *protocol.MemoryUser) error

	// RemoveUser removes a user by email.
	RemoveUser(context.Context, string) error
}

type GetInbound interface {
	GetInbound() Inbound
}

type GetOutbound interface {
	GetOutbound() Outbound
}

// TrafficState is used to track uplink and downlink of one connection
// It is used by XTLS to determine if switch to raw copy mode, It is used by Vision to calculate padding
type TrafficState struct {
	UserUUID               []byte
	NumberOfPacketToFilter int
	EnableXtls             bool
	IsTLS12orAbove         bool
	IsTLS                  bool
	Cipher                 uint16
	RemainingServerHello   int32

	// reader link state
	WithinPaddingBuffers     bool
	ReaderSwitchToDirectCopy bool
	RemainingCommand		 int32
	RemainingContent         int32
	RemainingPadding         int32
	CurrentCommand           int

	// write link state
	IsPadding                bool
	WriterSwitchToDirectCopy bool
}

func NewTrafficState(userUUID []byte) *TrafficState {
	return &TrafficState{
		UserUUID:                 userUUID,
		NumberOfPacketToFilter:   8,
		EnableXtls:               false,
		IsTLS12orAbove:           false,
		IsTLS:                    false,
		Cipher:                   0,
		RemainingServerHello:     -1,
		WithinPaddingBuffers:     true,
		ReaderSwitchToDirectCopy: false,
		RemainingCommand:         -1,
		RemainingContent:         -1,
		RemainingPadding:         -1,
		CurrentCommand:           0,
		IsPadding:                true,
		WriterSwitchToDirectCopy: false,
	}
}

// VisionReader is used to read xtls vision protocol
// Note Vision probably only make sense as the inner most layer of reader, since it need assess traffic state from origin proxy traffic
type VisionReader struct {
	buf.Reader
	trafficState *TrafficState
	ctx          context.Context
}

func NewVisionReader(reader buf.Reader, state *TrafficState, context context.Context) *VisionReader {
	return &VisionReader{
		Reader:       reader,
		trafficState: state,
		ctx:          context,
	}
}

func (w *VisionReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := w.Reader.ReadMultiBuffer()
	if !buffer.IsEmpty() {
		if w.trafficState.WithinPaddingBuffers || w.trafficState.NumberOfPacketToFilter > 0 {
			mb2 := make(buf.MultiBuffer, 0, len(buffer))
			for _, b := range buffer {
				newbuffer := XtlsUnpadding(b, w.trafficState, w.ctx)
				if newbuffer.Len() > 0 {
					mb2 = append(mb2, newbuffer)
				}
			}
			buffer = mb2
			if w.trafficState.RemainingContent > 0 || w.trafficState.RemainingPadding > 0 || w.trafficState.CurrentCommand == 0 {
				w.trafficState.WithinPaddingBuffers = true
			} else if w.trafficState.CurrentCommand == 1 {
				w.trafficState.WithinPaddingBuffers = false
			} else if w.trafficState.CurrentCommand == 2 {
				w.trafficState.WithinPaddingBuffers = false
				w.trafficState.ReaderSwitchToDirectCopy = true
			} else {
				newError("XtlsRead unknown command ", w.trafficState.CurrentCommand, buffer.Len()).WriteToLog(session.ExportIDToError(w.ctx))
			}
		}
		if w.trafficState.NumberOfPacketToFilter > 0 {
			XtlsFilterTls(buffer, w.trafficState, w.ctx)
		}
	}
	return buffer, err
}

// VisionWriter is used to write xtls vision protocol
// Note Vision probably only make sense as the inner most layer of writer, since it need assess traffic state from origin proxy traffic
type VisionWriter struct {
	buf.Writer
	trafficState      *TrafficState
	ctx               context.Context
	writeOnceUserUUID []byte
}

func NewVisionWriter(writer buf.Writer, state *TrafficState, context context.Context) *VisionWriter {
	w := make([]byte, len(state.UserUUID))
	copy(w, state.UserUUID)
	return &VisionWriter{
		Writer:            writer,
		trafficState:      state,
		ctx:               context,
		writeOnceUserUUID: w,
	}
}

func (w *VisionWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.trafficState.NumberOfPacketToFilter > 0 {
		XtlsFilterTls(mb, w.trafficState, w.ctx)
	}
	if w.trafficState.IsPadding {
		if len(mb) == 1 && mb[0] == nil {
			mb[0] = XtlsPadding(nil, CommandPaddingContinue, &w.writeOnceUserUUID, true, w.ctx) // we do a long padding to hide vless header
			return w.Writer.WriteMultiBuffer(mb)
		}
		mb = ReshapeMultiBuffer(w.ctx, mb)
		longPadding := w.trafficState.IsTLS
		for i, b := range mb {
			if w.trafficState.IsTLS && b.Len() >= 6 && bytes.Equal(TlsApplicationDataStart, b.BytesTo(3)) {
				if w.trafficState.EnableXtls {
					w.trafficState.WriterSwitchToDirectCopy = true
				}
				var command byte = CommandPaddingContinue
				if i == len(mb) - 1 {
					command = CommandPaddingEnd
					if w.trafficState.EnableXtls {
						command = CommandPaddingDirect
					}
				}
				mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, true, w.ctx)
				w.trafficState.IsPadding = false // padding going to end
				longPadding = false
				continue
			} else if !w.trafficState.IsTLS12orAbove && w.trafficState.NumberOfPacketToFilter <= 1 { // For compatibility with earlier vision receiver, we finish padding 1 packet early
				w.trafficState.IsPadding = false
				mb[i] = XtlsPadding(b, CommandPaddingEnd, &w.writeOnceUserUUID, longPadding, w.ctx)
				break
			}
			var command byte = CommandPaddingContinue
			if i == len(mb) - 1 && !w.trafficState.IsPadding {
				command = CommandPaddingEnd
				if w.trafficState.EnableXtls {
					command = CommandPaddingDirect
				}
			}
			mb[i] = XtlsPadding(b, command, &w.writeOnceUserUUID, longPadding, w.ctx)
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// ReshapeMultiBuffer prepare multi buffer for padding stucture (max 21 bytes)
func ReshapeMultiBuffer(ctx context.Context, buffer buf.MultiBuffer) buf.MultiBuffer {
	needReshape := 0
	for _, b := range buffer {
		if b.Len() >= buf.Size-21 {
			needReshape += 1
		}
	}
	if needReshape == 0 {
		return buffer
	}
	mb2 := make(buf.MultiBuffer, 0, len(buffer)+needReshape)
	toPrint := ""
	for i, buffer1 := range buffer {
		if buffer1.Len() >= buf.Size-21 {
			index := int32(bytes.LastIndex(buffer1.Bytes(), TlsApplicationDataStart))
			if index < 21 || index > buf.Size-21 {
				index = buf.Size / 2
			}
			buffer2 := buf.New()
			buffer2.Write(buffer1.BytesFrom(index))
			buffer1.Resize(0, index)
			mb2 = append(mb2, buffer1, buffer2)
			toPrint += " " + strconv.Itoa(int(buffer1.Len())) + " " + strconv.Itoa(int(buffer2.Len()))
		} else {
			mb2 = append(mb2, buffer1)
			toPrint += " " + strconv.Itoa(int(buffer1.Len()))
		}
		buffer[i] = nil
	}
	buffer = buffer[:0]
	newError("ReshapeMultiBuffer ", toPrint).WriteToLog(session.ExportIDToError(ctx))
	return mb2
}

// XtlsPadding add padding to eliminate length siganature during tls handshake
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, longPadding bool, ctx context.Context) *buf.Buffer {
	var contentLen int32 = 0
	var paddingLen int32 = 0
	if b != nil {
		contentLen = b.Len()
	}
	if contentLen < 900 && longPadding {
		l, err := rand.Int(rand.Reader, big.NewInt(500))
		if err != nil {
			newError("failed to generate padding").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
		paddingLen = int32(l.Int64()) + 900 - contentLen
	} else {
		l, err := rand.Int(rand.Reader, big.NewInt(256))
		if err != nil {
			newError("failed to generate padding").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
		paddingLen = int32(l.Int64())
	}
	if paddingLen > buf.Size-21-contentLen {
		paddingLen = buf.Size - 21 - contentLen
	}
	newbuffer := buf.New()
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	newbuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)})
	if b != nil {
		newbuffer.Write(b.Bytes())
		b.Release()
		b = nil
	}
	newbuffer.Extend(paddingLen)
	newError("XtlsPadding ", contentLen, " ", paddingLen, " ", command).WriteToLog(session.ExportIDToError(ctx))
	return newbuffer
}

// XtlsUnpadding remove padding and parse command
func XtlsUnpadding(b *buf.Buffer, s *TrafficState, ctx context.Context) *buf.Buffer {
	if s.RemainingCommand == -1 && s.RemainingContent == -1 && s.RemainingPadding == -1 { // inital state
		if b.Len() >= 21 && bytes.Equal(s.UserUUID, b.BytesTo(16)) {
			b.Advance(16)
			s.RemainingCommand = 5
		} else {
			return b
		}
	}
	newbuffer := buf.New()
	for b.Len() > 0 {
		if s.RemainingCommand > 0 {
			data, err := b.ReadByte()
			if err != nil {
				return newbuffer
			}
			switch s.RemainingCommand {
			case 5:
				s.CurrentCommand = int(data)
			case 4:
				s.RemainingContent = int32(data)<<8
			case 3:
				s.RemainingContent = s.RemainingContent | int32(data)
			case 2:
				s.RemainingPadding = int32(data)<<8
			case 1:
				s.RemainingPadding = s.RemainingPadding | int32(data)
				newError("Xtls Unpadding new block, content ", s.RemainingContent, " padding ", s.RemainingPadding, " command ", s.CurrentCommand).WriteToLog(session.ExportIDToError(ctx))
			}
			s.RemainingCommand--
		} else if s.RemainingContent > 0 {
			len := s.RemainingContent
			if b.Len() < len {
				len = b.Len()
			}
			data, err := b.ReadBytes(len)
			if err != nil {
				return newbuffer
			}
			newbuffer.Write(data)
			s.RemainingContent -= len
		} else { // remainingPadding > 0
			len := s.RemainingPadding
			if b.Len() < len {
				len = b.Len()
			}
			b.Advance(len)
			s.RemainingPadding -= len
		}
		if s.RemainingCommand <= 0 && s.RemainingContent <= 0 && s.RemainingPadding <= 0 { // this block done
			if s.CurrentCommand == 0 {
				s.RemainingCommand = 5
			} else {
				s.RemainingCommand = -1 // set to initial state
				s.RemainingContent = -1
				s.RemainingPadding = -1
				if b.Len() > 0 { // shouldn't happen
					newbuffer.Write(b.Bytes())
				}
				break
			}
		}
	}
	b.Release()
	b = nil
	return newbuffer
}

// XtlsFilterTls filter and recognize tls 1.3 and other info
func XtlsFilterTls(buffer buf.MultiBuffer, trafficState *TrafficState, ctx context.Context) {
	for _, b := range buffer {
		if b == nil {
			continue
		}
		trafficState.NumberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(TlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == TlsHandshakeTypeServerHello {
				trafficState.RemainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
				trafficState.IsTLS12orAbove = true
				trafficState.IsTLS = true
				if b.Len() >= 79 && trafficState.RemainingServerHello >= 79 {
					sessionIdLen := int32(b.Byte(43))
					cipherSuite := b.BytesRange(43+sessionIdLen+1, 43+sessionIdLen+3)
					trafficState.Cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
				} else {
					newError("XtlsFilterTls short server hello, tls 1.2 or older? ", b.Len(), " ", trafficState.RemainingServerHello).WriteToLog(session.ExportIDToError(ctx))
				}
			} else if bytes.Equal(TlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == TlsHandshakeTypeClientHello {
				trafficState.IsTLS = true
				newError("XtlsFilterTls found tls client hello! ", buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
			}
		}
		if trafficState.RemainingServerHello > 0 {
			end := trafficState.RemainingServerHello
			if end > b.Len() {
				end = b.Len()
			}
			trafficState.RemainingServerHello -= b.Len()
			if bytes.Contains(b.BytesTo(end), Tls13SupportedVersions) {
				v, ok := Tls13CipherSuiteDic[trafficState.Cipher]
				if !ok {
					v = "Old cipher: " + strconv.FormatUint(uint64(trafficState.Cipher), 16)
				} else if v != "TLS_AES_128_CCM_8_SHA256" {
					trafficState.EnableXtls = true
				}
				newError("XtlsFilterTls found tls 1.3! ", b.Len(), " ", v).WriteToLog(session.ExportIDToError(ctx))
				trafficState.NumberOfPacketToFilter = 0
				return
			} else if trafficState.RemainingServerHello <= 0 {
				newError("XtlsFilterTls found tls 1.2! ", b.Len()).WriteToLog(session.ExportIDToError(ctx))
				trafficState.NumberOfPacketToFilter = 0
				return
			}
			newError("XtlsFilterTls inconclusive server hello ", b.Len(), " ", trafficState.RemainingServerHello).WriteToLog(session.ExportIDToError(ctx))
		}
		if trafficState.NumberOfPacketToFilter <= 0 {
			newError("XtlsFilterTls stop filtering", buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
		}
	}
}

// UnwrapRawConn support unwrap stats, tls, utls, reality and proxyproto conn and get raw tcp conn from it
func UnwrapRawConn(conn net.Conn) (net.Conn, stats.Counter, stats.Counter) {
	var readCounter, writerCounter stats.Counter
	if conn != nil {
		statConn, ok := conn.(*stat.CounterConnection)
		if ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}
		if xc, ok := conn.(*tls.Conn); ok {
			conn = xc.NetConn()
		} else if utlsConn, ok := conn.(*tls.UConn); ok {
			conn = utlsConn.NetConn()
		} else if realityConn, ok := conn.(*reality.Conn); ok {
			conn = realityConn.NetConn()
		} else if realityUConn, ok := conn.(*reality.UConn); ok {
			conn = realityUConn.NetConn()
		}
		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
			// 8192 > 4096, there is no need to process pc's bufReader
		}
	}
	return conn, readCounter, writerCounter
}

// CopyRawConnIfExist use the most efficient copy method.
// - If caller don't want to turn on splice, do not pass in both reader conn and writer conn
// - writer are from *transport.Link
func CopyRawConnIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer signal.ActivityUpdater) error {
	readerConn, readCounter, _ := UnwrapRawConn(readerConn)
	writerConn, _, writeCounter := UnwrapRawConn(writerConn)
	reader := buf.NewReader(readerConn)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if tc, ok := writerConn.(*net.TCPConn); ok && readerConn != nil && writerConn != nil && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
			for inbound.CanSpliceCopy != 3 {
				if inbound.CanSpliceCopy == 1 {
					newError("CopyRawConn splice").WriteToLog(session.ExportIDToError(ctx))
					runtime.Gosched() // necessary
					w, err := tc.ReadFrom(readerConn)
					if readCounter != nil {
						readCounter.Add(w)
					}
					if writeCounter != nil {
						writeCounter.Add(w)
					}
					if err != nil && errors.Cause(err) != io.EOF {
						return err
					}
					return nil
				}
				buffer, err := reader.ReadMultiBuffer()
				if !buffer.IsEmpty() {
					if readCounter != nil {
						readCounter.Add(int64(buffer.Len()))
					}
					timer.Update()
					if werr := writer.WriteMultiBuffer(buffer); werr != nil {
						return werr
					}
				}
				if err != nil {
					return err
				}
			}
		}
	}
	newError("CopyRawConn readv").WriteToLog(session.ExportIDToError(ctx))
	if err := buf.Copy(reader, writer, buf.UpdateActivity(timer), buf.AddToStatCounter(readCounter)); err != nil {
		return newError("failed to process response").Base(err)
	}
	return nil
}
