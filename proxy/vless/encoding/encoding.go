package encoding

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"syscall"

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
var tlsHandShakeStart = []byte{0x16, 0x03, 0x03}
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

func ReadV(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn *xtls.Conn, rawConn syscall.RawConn, counter stats.Counter, sctx context.Context) error {
	err := func() error {
		var ct stats.Counter
		for {
			if conn.DirectIn {
				conn.DirectIn = false
				if sctx != nil {
					if inbound := session.InboundFromContext(sctx); inbound != nil && inbound.Conn != nil {
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
					} else {
						// panic("XTLS Splice: nil inbound or nil inbound.Conn")
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
func XtlsRead(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn *tls.Conn, rawConn syscall.RawConn, counter stats.Counter, sctx context.Context, userUUID []byte, filterServerHello bool, isTLS13Connection *bool) error {
	err := func() error {
		var ct stats.Counter
		numberOfPacketToFilter := 0
		if filterServerHello {
			numberOfPacketToFilter = 5
		}
		filterUUID := true
		shouldSwitchToDirectCopy := false
		for {
			if shouldSwitchToDirectCopy {
				shouldSwitchToDirectCopy = false
				if sctx != nil && (runtime.GOOS == "linux" || runtime.GOOS == "android") {
					if inbound := session.InboundFromContext(sctx); inbound != nil && inbound.Conn != nil {
						iConn := inbound.Conn
						statConn, ok := iConn.(*stat.CounterConnection)
						if ok {
							iConn = statConn.Connection
						}
						if xc, ok := iConn.(*tls.Conn); ok {
							iConn = xc.NetConn()
						}
						if tc, ok := iConn.(*net.TCPConn); ok {
							newError("XtlsRead splice").WriteToLog()
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
					} else {
						// panic("XTLS Splice: nil inbound or nil inbound.Conn")
					}
				}
				reader = buf.NewReadVReader(conn.NetConn(), rawConn, nil)
				ct = counter
				newError("XtlsRead readV").WriteToLog()
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if numberOfPacketToFilter > 0 {
					XtlsFilterTls13(buffer, &numberOfPacketToFilter, isTLS13Connection)
				}
				if filterUUID && *isTLS13Connection {
					for i, b := range buffer {
						if b.Len() >= 16 && bytes.Equal(userUUID, b.BytesFrom(b.Len() - 16)) {
							shouldSwitchToDirectCopy = true
							filterUUID = false
							b.Resize(0, b.Len() - 16)
							newError("XtlsRead found UUID ", i, " ", b.Len()).WriteToLog()
						}
					}
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

// XtlsRead filter and write xtls protocol
func XtlsWrite(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn *tls.Conn, counter stats.Counter, userUUID []byte, filterServerHello bool, isTLS13Connection *bool) error {
	err := func() error {
		var ct stats.Counter
		numberOfPacketToFilter := 0
		if filterServerHello && !*isTLS13Connection {
			numberOfPacketToFilter = 5
		}
		filterTlsApplicationData := true
		shouldSwitchToDirectCopy := false
		for {
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				if numberOfPacketToFilter > 0 {
					XtlsFilterTls13(buffer, &numberOfPacketToFilter, isTLS13Connection)
				}
				if filterTlsApplicationData && *isTLS13Connection {
					var xtlsSpecIndex int
					for i, b := range buffer {
						if b.Len() >= 6 && bytes.Equal(tlsApplicationDataStart, b.BytesTo(3)) {
							shouldSwitchToDirectCopy = true
							filterTlsApplicationData = false
							b.Write(userUUID)
							xtlsSpecIndex = i
							break
						}
					}
					if shouldSwitchToDirectCopy {
						encryptBuffer, directBuffer := buf.SplitMulti(buffer, xtlsSpecIndex + 1)
						length := encryptBuffer.Len()
						if !encryptBuffer.IsEmpty() {
							timer.Update()
							if werr := writer.WriteMultiBuffer(encryptBuffer); werr != nil {
								return werr
							}
						}
						buffer = directBuffer
						writer = buf.NewWriter(conn.NetConn())
						ct = counter
						newError("XtlsWrite writeV ", xtlsSpecIndex, " ", length, " ", buffer.Len()).WriteToLog()
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

// XtlsFilterTls13 filter and recognize tls 1.3
func XtlsFilterTls13(buffer buf.MultiBuffer, numberOfPacketToFilter *int, isTLS13Connection *bool) {
	for _, b := range buffer {
		*numberOfPacketToFilter--
		if b.Len() >= 6 {
			startsBytes := b.BytesTo(6)
			if bytes.Equal(tlsHandShakeStart, startsBytes[:3]) && startsBytes[5] == 0x02 {
				total := (int(startsBytes[3])<<8 | int(startsBytes[4])) + 5
				if b.Len() >= int32(total) {
					if (bytes.Contains(b.BytesTo(int32(total)), tls13SupportedVersions)) {
						*isTLS13Connection = true
						newError("XtlsFilterTls13 found tls 1.3! ", buffer.Len()).WriteToLog()
					} else {
						*isTLS13Connection = false
						newError("XtlsFilterTls13 found tls 1.2! ", buffer.Len()).WriteToLog()
					}
					*numberOfPacketToFilter = 0
					return
				}
			}
		}
		if (*numberOfPacketToFilter == 0) {
			newError("XtlsFilterTls13 stop filtering, did not find internal tls connection ", buffer.Len()).WriteToLog()
		}
	}
}
