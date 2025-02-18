package encoding

import (
	"bytes"
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
)

const (
	Version = byte(0)
)

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
		return errors.New("failed to write request version").Base(err)
	}

	if _, err := buffer.Write(request.User.Account.(*vless.MemoryAccount).ID.Bytes()); err != nil {
		return errors.New("failed to write request user id").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, requestAddons); err != nil {
		return errors.New("failed to encode request header addons").Base(err)
	}

	if err := buffer.WriteByte(byte(request.Command)); err != nil {
		return errors.New("failed to write request command").Base(err)
	}

	if request.Command != protocol.RequestCommandMux {
		if err := addrParser.WriteAddressPort(&buffer, request.Address, request.Port); err != nil {
			return errors.New("failed to write request address and port").Base(err)
		}
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return errors.New("failed to write request header").Base(err)
	}

	return nil
}

// DecodeRequestHeader decodes and returns (if successful) a RequestHeader from an input stream.
func DecodeRequestHeader(isfb bool, first *buf.Buffer, reader io.Reader, validator vless.Validator) (*protocol.RequestHeader, *Addons, bool, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	request := new(protocol.RequestHeader)

	if isfb {
		request.Version = first.Byte(0)
	} else {
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, false, errors.New("failed to read request version").Base(err)
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
				return nil, nil, false, errors.New("failed to read request user id").Base(err)
			}
			copy(id[:], buffer.Bytes())
		}

		if request.User = validator.Get(id); request.User == nil {
			return nil, nil, isfb, errors.New("invalid request user id")
		}

		if isfb {
			first.Advance(17)
		}

		requestAddons, err := DecodeHeaderAddons(&buffer, reader)
		if err != nil {
			return nil, nil, false, errors.New("failed to decode request header addons").Base(err)
		}

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, false, errors.New("failed to read request command").Base(err)
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
			return nil, nil, false, errors.New("invalid request address")
		}
		return request, requestAddons, false, nil
	default:
		return nil, nil, isfb, errors.New("invalid request version")
	}
}

// EncodeResponseHeader writes encoded response header into the given writer.
func EncodeResponseHeader(writer io.Writer, request *protocol.RequestHeader, responseAddons *Addons) error {
	buffer := buf.StackNew()
	defer buffer.Release()

	if err := buffer.WriteByte(request.Version); err != nil {
		return errors.New("failed to write response version").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, responseAddons); err != nil {
		return errors.New("failed to encode response header addons").Base(err)
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return errors.New("failed to write response header").Base(err)
	}

	return nil
}

// DecodeResponseHeader decodes and returns (if successful) a ResponseHeader from an input stream.
func DecodeResponseHeader(reader io.Reader, request *protocol.RequestHeader) (*Addons, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, errors.New("failed to read response version").Base(err)
	}

	if buffer.Byte(0) != request.Version {
		return nil, errors.New("unexpected response version. Expecting ", int(request.Version), " but actually ", int(buffer.Byte(0)))
	}

	responseAddons, err := DecodeHeaderAddons(&buffer, reader)
	if err != nil {
		return nil, errors.New("failed to decode response header addons").Base(err)
	}

	return responseAddons, nil
}

// XtlsRead filter and read xtls protocol
func XtlsRead(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, conn net.Conn, input *bytes.Reader, rawInput *bytes.Buffer, trafficState *proxy.TrafficState, ob *session.Outbound, isUplink bool, ctx context.Context) error {
	err := func() error {
		for {
			if isUplink && trafficState.Inbound.UplinkReaderDirectCopy || !isUplink && trafficState.Outbound.DownlinkReaderDirectCopy {
				var writerConn net.Conn
				var inTimer *signal.ActivityTimer
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
					writerConn = inbound.Conn
					inTimer = inbound.Timer
					if isUplink && inbound.CanSpliceCopy == 2 {
						inbound.CanSpliceCopy = 1
					}
					if !isUplink && ob != nil && ob.CanSpliceCopy == 2 { // ob need to be passed in due to context can change
						ob.CanSpliceCopy = 1
					}
				}
				return proxy.CopyRawConnIfExist(ctx, conn, writerConn, writer, timer, inTimer)
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				if isUplink && trafficState.Inbound.UplinkReaderDirectCopy || !isUplink && trafficState.Outbound.DownlinkReaderDirectCopy {
					// XTLS Vision processes struct TLS Conn's input and rawInput
					if inputBuffer, err := buf.ReadFrom(input); err == nil {
						if !inputBuffer.IsEmpty() {
							buffer, _ = buf.MergeMulti(buffer, inputBuffer)
						}
					}
					if rawInputBuffer, err := buf.ReadFrom(rawInput); err == nil {
						if !rawInputBuffer.IsEmpty() {
							buffer, _ = buf.MergeMulti(buffer, rawInputBuffer)
						}
					}
				}
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
func XtlsWrite(reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, conn net.Conn, trafficState *proxy.TrafficState, ob *session.Outbound, isUplink bool, ctx context.Context) error {
	err := func() error {
		var ct stats.Counter
		for {
			buffer, err := reader.ReadMultiBuffer()
			if isUplink && trafficState.Outbound.UplinkWriterDirectCopy || !isUplink && trafficState.Inbound.DownlinkWriterDirectCopy {
				if inbound := session.InboundFromContext(ctx); inbound != nil {
					if !isUplink && inbound.CanSpliceCopy == 2 {
						inbound.CanSpliceCopy = 1
					}
					if isUplink && ob != nil && ob.CanSpliceCopy == 2 {
						ob.CanSpliceCopy = 1
					}
				}
				rawConn, _, writerCounter := proxy.UnwrapRawConn(conn)
				writer = buf.NewWriter(rawConn)
				ct = writerCounter
				if isUplink {
					trafficState.Outbound.UplinkWriterDirectCopy = false
				} else {
					trafficState.Inbound.DownlinkWriterDirectCopy = false
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
