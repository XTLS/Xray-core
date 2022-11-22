package encoding

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/xtls"
)

const (
	Version = byte(0)
)

var tls13SupportedVersions = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
var tlsClientHandShakeStart = []byte{0x16, 0x03}
var tlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
var tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

// EncodeRequestHeader writes encoded request header into the given writer.
func EncodeRequestHeader(writer io.Writer, request *protocol.RequestHeader, requestAddons *Addons) error {
	buffer := buf.StackNew()
	defer buffer.Release()

	if err := buffer.WriteByte(request.Version); err != nil {
		return newError("failed to write request version").Base(err)
	}

	if _, err := buffer.Write(request.User.Account.(*vless.MemoryAccount).ID.Bytes()); err != nil {
		return newError("failed to write request user id").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, requestAddons); err != nil {
		return newError("failed to encode request header addons").Base(err)
	}

	if err := buffer.WriteByte(byte(request.Command)); err != nil {
		return newError("failed to write request command").Base(err)
	}

	if request.Command != protocol.RequestCommandMux {
		if err := addrParser.WriteAddressPort(&buffer, request.Address, request.Port); err != nil {
			return newError("failed to write request address and port").Base(err)
		}
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return newError("failed to write request header").Base(err)
	}

	return nil
}

// DecodeRequestHeader decodes and returns (if successful) a RequestHeader from an input stream.
func DecodeRequestHeader(isfb bool, first *buf.Buffer, reader io.Reader, validator *vless.Validator) (*protocol.RequestHeader, *Addons, bool, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	request := new(protocol.RequestHeader)

	if isfb {
		request.Version = first.Byte(0)
	} else {
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, false, newError("failed to read request version").Base(err)
		}
		request.Version = buffer.Byte(0)
	}

	switch request.Version {
	case 0:

		var id [16]byte

		if isfb {
			copy(id[:], first.BytesRange(1, 17))
		} else {
			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, 16); err != nil {
				return nil, nil, false, newError("failed to read request user id").Base(err)
			}
			copy(id[:], buffer.Bytes())
		}

		if request.User = validator.Get(id); request.User == nil {
			return nil, nil, isfb, newError("invalid request user id")
		}

		if isfb {
			first.Advance(17)
		}

		requestAddons, err := DecodeHeaderAddons(&buffer, reader)
		if err != nil {
			return nil, nil, false, newError("failed to decode request header addons").Base(err)
		}

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, false, newError("failed to read request command").Base(err)
		}

		request.Command = protocol.RequestCommand(buffer.Byte(0))
		switch request.Command {
		case protocol.RequestCommandMux:
			request.Address = net.DomainAddress("v1.mux.cool")
			request.Port = 0
		case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
			if addr, port, err := addrParser.ReadAddressPort(&buffer, reader); err == nil {
				request.Address = addr
				request.Port = port
			}
		}
		if request.Address == nil {
			return nil, nil, false, newError("invalid request address")
		}
		return request, requestAddons, false, nil
	default:
		return nil, nil, isfb, newError("invalid request version")
	}
}

// EncodeResponseHeader writes encoded response header into the given writer.
func EncodeResponseHeader(writer io.Writer, request *protocol.RequestHeader, responseAddons *Addons) error {
	buffer := buf.StackNew()
	defer buffer.Release()

	if err := buffer.WriteByte(request.Version); err != nil {
		return newError("failed to write response version").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, responseAddons); err != nil {
		return newError("failed to encode response header addons").Base(err)
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return newError("failed to write response header").Base(err)
	}

	return nil
}

// DecodeResponseHeader decodes and returns (if successful) a ResponseHeader from an input stream.
func DecodeResponseHeader(reader io.Reader, request *protocol.RequestHeader) (*Addons, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, newError("failed to read response version").Base(err)
	}

	if buffer.Byte(0) != request.Version {
		return nil, newError("unexpected response version. Expecting ", int(request.Version), " but actually ", int(buffer.Byte(0)))
	}

	responseAddons, err := DecodeHeaderAddons(&buffer, reader)
	if err != nil {
		return nil, newError("failed to decode response header addons").Base(err)
	}

	return responseAddons, nil
}

func ReadV(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn *xtls.Conn, rawConn syscall.RawConn, counter stats.Counter, ctx context.Context) error {
	err := func() error {
		var ct stats.Counter
		for {
			if conn.DirectIn {
				conn.DirectIn = false
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
					iConn := inbound.Conn
					statConn, ok := iConn.(*stat.CounterConnection)
					if ok {
						iConn = statConn.Connection
					}
					if xc, ok := iConn.(*xtls.Conn); ok {
						iConn = xc.NetConn()
					}
					if tc, ok := iConn.(*net.TCPConn); ok {
						if conn.SHOW {
							fmt.Println(conn.MARK, "Splice")
						}
						runtime.Gosched() // necessary
						w, err := tc.ReadFrom(conn.NetConn())
						if counter != nil {
							counter.Add(w)
						}
						if statConn != nil && statConn.WriteCounter != nil {
							statConn.WriteCounter.Add(w)
						}
						return err
					} else {
						panic("XTLS Splice: not TCP inbound")
					}
				}
				reader = buf.NewReadVReader(conn.NetConn(), rawConn, nil)
				ct = counter
				if conn.SHOW {
					fmt.Println(conn.MARK, "ReadV")
				}
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if ct != nil {
					ct.Add(int64(buffer.Len()))
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
	}()
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

// XtlsRead filter and read xtls protocol
func XtlsRead(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn net.Conn, rawConn syscall.RawConn, 
	counter stats.Counter, ctx context.Context, userUUID []byte, numberOfPacketToFilter *int, enableXtls *bool, 
	isTLS12orAbove *bool, isTLS *bool, cipher *uint16, remainingServerHello *int32) error {
	err := func() error {
		var ct stats.Counter
		filterUUID := true
		shouldSwitchToDirectCopy := false
		var remainingContent int32 = -1
		var remainingPadding int32 = -1
		currentCommand := 0
		for {
			if shouldSwitchToDirectCopy {
				shouldSwitchToDirectCopy = false
				if runtime.GOOS == "linux" || runtime.GOOS == "android" {
					if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
						iConn := inbound.Conn
						statConn, ok := iConn.(*stat.CounterConnection)
						if ok {
							iConn = statConn.Connection
						}
						if xc, ok := iConn.(*tls.Conn); ok {
							iConn = xc.NetConn()
						}
						if tc, ok := iConn.(*net.TCPConn); ok {
							newError("XtlsRead splice").WriteToLog(session.ExportIDToError(ctx))
							runtime.Gosched() // necessary
							w, err := tc.ReadFrom(conn)
							if counter != nil {
								counter.Add(w)
							}
							if statConn != nil && statConn.WriteCounter != nil {
								statConn.WriteCounter.Add(w)
							}
							return err
						} else {
							panic("XTLS Splice: not TCP inbound")
						}
					} else {
						// panic("XTLS Splice: nil inbound or nil inbound.Conn")
					}
				}
				reader = buf.NewReadVReader(conn, rawConn, nil)
				ct = counter
				newError("XtlsRead readV").WriteToLog(session.ExportIDToError(ctx))
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if filterUUID && (*isTLS || *numberOfPacketToFilter > 0) {
					buffer = XtlsUnpadding(ctx, buffer, userUUID, &remainingContent, &remainingPadding, &currentCommand)
					if remainingContent == 0 && remainingPadding == 0 {
						if currentCommand == 1 {
							filterUUID = false
						} else if currentCommand == 2 {
							filterUUID = false
							shouldSwitchToDirectCopy = true
						} else if currentCommand != 0 {
							newError("XtlsRead unknown command ", currentCommand, buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
						}
					}
				}
				if *numberOfPacketToFilter > 0 {
					XtlsFilterTls(buffer, numberOfPacketToFilter, enableXtls, isTLS12orAbove, isTLS, cipher, remainingServerHello, ctx)
				}
				if ct != nil {
					ct.Add(int64(buffer.Len()))
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
	}()
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

// XtlsWrite filter and write xtls protocol
func XtlsWrite(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn net.Conn, counter stats.Counter, 
	ctx context.Context, userUUID *[]byte, numberOfPacketToFilter *int, enableXtls *bool, isTLS12orAbove *bool, isTLS *bool, 
	cipher *uint16, remainingServerHello *int32) error {
	err := func() error {
		var ct stats.Counter
		filterTlsApplicationData := true
		shouldSwitchToDirectCopy := false
		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if *numberOfPacketToFilter > 0 {
					XtlsFilterTls(buffer, numberOfPacketToFilter, enableXtls, isTLS12orAbove, isTLS, cipher, remainingServerHello, ctx)
				}
				if filterTlsApplicationData && *isTLS {
					buffer = ReshapeMultiBuffer(ctx, buffer)
					var xtlsSpecIndex int
					for i, b := range buffer {
						if b.Len() >= 6 && bytes.Equal(tlsApplicationDataStart, b.BytesTo(3)) {
							var command byte = 0x01
							if *enableXtls {
								shouldSwitchToDirectCopy = true
								xtlsSpecIndex = i
								command = 0x02
							}
							filterTlsApplicationData = false
							buffer[i] = XtlsPadding(b, command, userUUID, ctx)
							break
						} else if !*isTLS12orAbove && *numberOfPacketToFilter <= 0 {
							//maybe tls 1.1 or 1.0
							filterTlsApplicationData = false
							buffer[i] = XtlsPadding(b, 0x01, userUUID, ctx)
							break
						}
						buffer[i] = XtlsPadding(b, 0x00, userUUID, ctx)
					}
					if shouldSwitchToDirectCopy {
						encryptBuffer, directBuffer := buf.SplitMulti(buffer, xtlsSpecIndex+1)
						length := encryptBuffer.Len()
						if !encryptBuffer.IsEmpty() {
							timer.Update()
							if werr := writer.WriteMultiBuffer(encryptBuffer); werr != nil {
								return werr
							}
						}
						buffer = directBuffer
						writer = buf.NewWriter(conn)
						ct = counter
						newError("XtlsWrite writeV ", xtlsSpecIndex, " ", length, " ", buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
						time.Sleep(5 * time.Millisecond) // for some device, the first xtls direct packet fails without this delay
					}
				}
				if !buffer.IsEmpty() {
					if ct != nil {
						ct.Add(int64(buffer.Len()))
					}
					timer.Update()
					if werr := writer.WriteMultiBuffer(buffer); werr != nil {
						return werr
					}
				}
			}
			if err != nil {
				return err
			}
		}
	}()
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}

// XtlsFilterTls filter and recognize tls 1.3 and other info
func XtlsFilterTls(buffer buf.MultiBuffer, numberOfPacketToFilter *int, enableXtls *bool, isTLS12orAbove *bool, isTLS *bool, 
	cipher *uint16, remainingServerHello *int32, ctx context.Context) {
	for _, b := range buffer {
		*numberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(tlsServerHandShakeStart, startsBytes[:3]) && startsBytes[5] == 0x02 {
				*remainingServerHello = (int32(startsBytes[3])<<8 | int32(startsBytes[4])) + 5
				*isTLS12orAbove = true
				*isTLS = true
				if b.Len() >= 79 && *remainingServerHello >= 79 {
					sessionIdLen := int32(b.Byte(43))
					cipherSuite := b.BytesRange(43 + sessionIdLen + 1, 43 + sessionIdLen + 3)
					*cipher = uint16(cipherSuite[0]) << 8 | uint16(cipherSuite[1])
				} else {
					newError("XtlsFilterTls short server hello, tls 1.2 or older? ", b.Len(), " ", *remainingServerHello).WriteToLog(session.ExportIDToError(ctx))
				}
			} else if bytes.Equal(tlsClientHandShakeStart, startsBytes[:2]) && startsBytes[5] == 0x01 {
				*isTLS = true
				newError("XtlsFilterTls found tls client hello! ", buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
			}
		}
		if *remainingServerHello > 0 {
			end := *remainingServerHello
			if end > b.Len() {
				end = b.Len()
			}
			*remainingServerHello -= b.Len()
			if bytes.Contains(b.BytesTo(end), tls13SupportedVersions) {
				v, ok := Tls13CipherSuiteDic[*cipher]
				if !ok {
					v = "Old cipher: " + strconv.FormatUint(uint64(*cipher), 16)
				} else if (v != "TLS_AES_128_CCM_8_SHA256") {
					*enableXtls = true
				}
				newError("XtlsFilterTls found tls 1.3! ", b.Len(), " ", v).WriteToLog(session.ExportIDToError(ctx))
				*numberOfPacketToFilter = 0
				return
			} else if *remainingServerHello <= 0 {
				newError("XtlsFilterTls found tls 1.2! ", b.Len()).WriteToLog(session.ExportIDToError(ctx))
				*numberOfPacketToFilter = 0
				return
			}
			newError("XtlsFilterTls inclusive server hello ", b.Len(), " ", *remainingServerHello).WriteToLog(session.ExportIDToError(ctx))
		}
		if *numberOfPacketToFilter <= 0 {
			newError("XtlsFilterTls stop filtering", buffer.Len()).WriteToLog(session.ExportIDToError(ctx))
		}
	}
}

// ReshapeMultiBuffer prepare multi buffer for padding stucture (max 21 bytes)
func ReshapeMultiBuffer(ctx context.Context, buffer buf.MultiBuffer) buf.MultiBuffer {
	needReshape := false
	for _, b := range buffer {
		if b.Len() >= buf.Size-21 {
			needReshape = true
		}
	}
	if !needReshape {
		return buffer
	}
	mb2 := make(buf.MultiBuffer, 0, len(buffer))
	print := ""
	for _, b := range buffer {
		if b.Len() >= buf.Size-21 {
			index := int32(bytes.LastIndex(b.Bytes(), tlsApplicationDataStart))
			if index <= 0 {
				index = buf.Size / 2
			}
			buffer1 := buf.New()
			buffer2 := buf.New()
			buffer1.Write(b.BytesTo(index))
			buffer2.Write(b.BytesFrom(index))
			mb2 = append(mb2, buffer1, buffer2)
			print += " " + strconv.Itoa(int(buffer1.Len())) + " " + strconv.Itoa(int(buffer2.Len()))
		} else {
			newbuffer := buf.New()
			newbuffer.Write(b.Bytes())
			mb2 = append(mb2, newbuffer)
			print += " " + strconv.Itoa(int(b.Len()))
		}
	}
	buf.ReleaseMulti(buffer)
	newError("ReshapeMultiBuffer ", print).WriteToLog(session.ExportIDToError(ctx))
	return mb2
}

// XtlsPadding add padding to eliminate length siganature during tls handshake
func XtlsPadding(b *buf.Buffer, command byte, userUUID *[]byte, ctx context.Context) *buf.Buffer {
	var length int32 = 0
	if b.Len() < 900 {
		l, err := rand.Int(rand.Reader, big.NewInt(500))
		if err != nil {
			newError("failed to generate padding").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
		length = int32(l.Int64()) + 900 - b.Len()
	}
	newbuffer := buf.New()
	if userUUID != nil {
		newbuffer.Write(*userUUID)
		*userUUID = nil
	}
	newbuffer.Write([]byte{command, byte(b.Len() >> 8), byte(b.Len()), byte(length >> 8), byte(length)})
	newbuffer.Write(b.Bytes())
	newbuffer.Extend(length)
	newError("XtlsPadding ", b.Len(), " ", length, " ", command).WriteToLog(session.ExportIDToError(ctx))
	b.Release()
	b = nil
	return newbuffer
}

// XtlsUnpadding remove padding and parse command
func XtlsUnpadding(ctx context.Context, buffer buf.MultiBuffer, userUUID []byte, remainingContent *int32, remainingPadding *int32, currentCommand *int) buf.MultiBuffer {
	posindex := 0
	var posByte int32 = 0
	if *remainingContent == -1 && *remainingPadding == -1 {
		for i, b := range buffer {
			if b.Len() >= 21 && bytes.Equal(userUUID, b.BytesTo(16)) {
				posindex = i
				posByte = 16
				*remainingContent = 0
				*remainingPadding = 0
				break
			}
		}
	}
	if *remainingContent == -1 && *remainingPadding == -1 {
		return buffer
	}
	mb2 := make(buf.MultiBuffer, 0, len(buffer))
	for i := 0; i < posindex; i++ {
		newbuffer := buf.New()
		newbuffer.Write(buffer[i].Bytes())
		mb2 = append(mb2, newbuffer)
	}
	for i := posindex; i < len(buffer); i++ {
		b := buffer[i]
		for posByte < b.Len() {
			if *remainingContent <= 0 && *remainingPadding <= 0 {
				if *currentCommand == 1 { // possible buffer after padding, no need to worry about xtls (command 2)
					len := b.Len() - posByte
					newbuffer := buf.New()
					newbuffer.Write(b.BytesRange(posByte, posByte+len))
					mb2 = append(mb2, newbuffer)
					posByte += len
				} else {
					paddingInfo := b.BytesRange(posByte, posByte+5)
					*currentCommand = int(paddingInfo[0])
					*remainingContent = int32(paddingInfo[1])<<8 | int32(paddingInfo[2])
					*remainingPadding = int32(paddingInfo[3])<<8 | int32(paddingInfo[4])
					newError("Xtls Unpadding new block", i, " ", posByte, " content ", *remainingContent, " padding ", *remainingPadding, " ", paddingInfo[0]).WriteToLog(session.ExportIDToError(ctx))
					posByte += 5
				}
			} else if *remainingContent > 0 {
				len := *remainingContent
				if b.Len() < posByte+*remainingContent {
					len = b.Len() - posByte
				}
				newbuffer := buf.New()
				newbuffer.Write(b.BytesRange(posByte, posByte+len))
				mb2 = append(mb2, newbuffer)
				*remainingContent -= len
				posByte += len
			} else { // remainingPadding > 0
				len := *remainingPadding
				if b.Len() < posByte+*remainingPadding {
					len = b.Len() - posByte
				}
				*remainingPadding -= len
				posByte += len
			}
			if posByte == b.Len() {
				posByte = 0
				break
			}
		}
	}
	buf.ReleaseMulti(buffer)
	return mb2
}

var Tls13CipherSuiteDic = map[uint16]string{
	0x1301 : "TLS_AES_128_GCM_SHA256",
	0x1302 : "TLS_AES_256_GCM_SHA384",
	0x1303 : "TLS_CHACHA20_POLY1305_SHA256",
	0x1304 : "TLS_AES_128_CCM_SHA256",
	0x1305 : "TLS_AES_128_CCM_8_SHA256",
}
