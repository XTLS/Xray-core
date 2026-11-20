package encoding_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
)

func testSessions(t *testing.T) (*protocol.MemoryUser, *encoding.ClientSession, *encoding.ServerSession) {
	t.Helper()
	id := uuid.New()
	account, err := (&vmess.Account{Id: id.String()}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	user := &protocol.MemoryUser{Email: "test@example.com", Account: account}
	history := encoding.NewSessionHistory()
	t.Cleanup(func() { history.Close() })
	validator := vmess.NewTimedUserValidator()
	if err := validator.Add(user); err != nil {
		t.Fatal(err)
	}
	return user, encoding.NewClientSession(t.Context(), 0), encoding.NewServerSession(validator, history)
}

func testRequest(user *protocol.MemoryUser, command protocol.RequestCommand) *protocol.RequestHeader {
	return &protocol.RequestHeader{
		Version: 1, User: user, Command: command, Security: protocol.SecurityType_AES128_GCM,
		Address: net.DomainAddress("www.example.com"), Port: 443,
	}
}

func TestRequestSerialization(t *testing.T) {
	user, client, server := testSessions(t)
	want := testRequest(user, protocol.RequestCommandTCP)
	var wire bytes.Buffer
	if err := client.EncodeRequestHeader(want, &wire); err != nil {
		t.Fatal(err)
	}
	repeated := bytes.NewReader(bytes.Clone(wire.Bytes()))
	got, err := server.DecodeRequestHeader(&wire, false)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(protocol.ID{})); diff != "" {
		t.Errorf("request header (-want +got):\n%s", diff)
	}
	if _, err := server.DecodeRequestHeader(repeated, false); err == nil {
		t.Error("duplicate request header was accepted")
	}
}

func TestInvalidRequest(t *testing.T) {
	user, client, server := testSessions(t)
	var wire bytes.Buffer
	if err := client.EncodeRequestHeader(testRequest(user, protocol.RequestCommand(100)), &wire); err != nil {
		t.Fatal(err)
	}
	if _, err := server.DecodeRequestHeader(&wire, false); err == nil {
		t.Error("unsupported request command was accepted")
	}
}

func TestMuxRequest(t *testing.T) {
	user, client, server := testSessions(t)
	want := testRequest(user, protocol.RequestCommandMux)
	want.Address, want.Port = nil, 0
	var wire bytes.Buffer
	if err := client.EncodeRequestHeader(want, &wire); err != nil {
		t.Fatal(err)
	}
	got, err := server.DecodeRequestHeader(&wire, false)
	if err != nil {
		t.Fatal(err)
	}
	want.Address = net.DomainAddress("v1.mux.cool")
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(protocol.ID{})); diff != "" {
		t.Errorf("Mux header (-want +got):\n%s", diff)
	}
}

func TestBodyRoundTrip(t *testing.T) {
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305} {
		for _, network := range []struct {
			name    string
			command protocol.RequestCommand
		}{{"tcp", protocol.RequestCommandTCP}, {"udp", protocol.RequestCommandUDP}} {
			for _, length := range []struct {
				name          string
				authenticated bool
			}{{"masked-length", false}, {"authenticated-length", true}} {
				t.Run(security.String()+"/"+network.name+"/"+length.name, func(t *testing.T) {
					user, client, server := testSessions(t)
					request := testRequest(user, network.command)
					request.Security = security
					request.Option.Set(protocol.RequestOptionChunkStream | protocol.RequestOptionChunkMasking | protocol.RequestOptionGlobalPadding)
					if length.authenticated {
						request.Option.Set(protocol.RequestOptionAuthenticatedLength)
					}
					var wire bytes.Buffer
					if err := client.EncodeRequestHeader(request, &wire); err != nil {
						t.Fatal(err)
					}
					decoded, err := server.DecodeRequestHeader(&wire, false)
					if err != nil {
						t.Fatal(err)
					}
					uplink, err := client.EncodeRequestBody(request, &wire)
					if err != nil {
						t.Fatal(err)
					}
					uplinkReader, err := server.DecodeRequestBody(decoded, &wire)
					if err != nil {
						t.Fatal(err)
					}
					testBody(t, uplink, uplinkReader, network.command, 1)

					wire.Reset()
					server.EncodeResponseHeader(&protocol.ResponseHeader{}, &wire)
					if _, err := client.DecodeResponseHeader(&wire); err != nil {
						t.Fatal(err)
					}
					downlink, err := server.EncodeResponseBody(decoded, &wire)
					if err != nil {
						t.Fatal(err)
					}
					downlinkReader, err := client.DecodeResponseBody(request, &wire)
					if err != nil {
						t.Fatal(err)
					}
					testBody(t, downlink, downlinkReader, network.command, 2)
				})
			}
		}
	}
}

func testBody(t *testing.T, writer buf.Writer, reader buf.Reader, command protocol.RequestCommand, value byte) {
	t.Helper()
	packet := command == protocol.RequestCommandUDP
	size := 2*buf.Size + 19
	if packet {
		size = 1024
	}
	first := bytes.Repeat([]byte{value}, size)
	second := bytes.Repeat([]byte{value + 10}, 257)
	for _, data := range [][]byte{first, second} {
		if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, data)); err != nil {
			t.Fatal(err)
		}
	}
	if packet {
		var received buf.MultiBuffer
		defer func() { buf.ReleaseMulti(received) }()
		for len(received) < 2 {
			batch, err := reader.ReadMultiBuffer()
			received = append(received, batch...)
			if err != nil || len(batch) == 0 {
				t.Fatalf("read UDP datagrams: got %d, err = %v", len(received), err)
			}
		}
		if len(received) != 2 || !bytes.Equal(received[0].Bytes(), first) || !bytes.Equal(received[1].Bytes(), second) {
			t.Fatal("UDP datagram payloads or boundaries changed")
		}
		return
	}
	stream := &buf.BufferedReader{Reader: reader}
	defer func() { buf.ReleaseMulti(stream.Buffer) }()
	got := make([]byte, len(first)+len(second))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, append(first, second...)) {
		t.Fatalf("TCP payload mismatch: want %d bytes, read error: %v", len(got), err)
	}
}
