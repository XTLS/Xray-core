package xmc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestPaddingReaderPreservesFollowingPackets(t *testing.T) {
	for _, isClient := range []bool{true, false} {
		packetID := paddingFramePacketID(!isClient)
		var wire bytes.Buffer
		paddingChannel := String(paddingFrameChannel)
		padding := RestBytes(make([]byte, 1024))
		if err := writePacket(&wire, packetID, &paddingChannel, &padding); err != nil {
			t.Fatal(err)
		}
		var want bytes.Buffer
		unknownChannel := String("other:channel")
		payload := RestBytes("preserve unknown custom payloads")
		if err := writePacket(&want, packetID, &unknownChannel, &payload); err != nil {
			t.Fatal(err)
		}
		id := Long(42)
		if err := writePacket(&want, configurationKeepAlive, &id); err != nil {
			t.Fatal(err)
		}
		channel := String(packetChannel)
		if err := writePacket(&want, packetID, &channel, &payload); err != nil {
			t.Fatal(err)
		}
		wire.Write(want.Bytes())
		got, err := io.ReadAll(newPaddingReader(&wire, isClient))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("client=%v: non-padding packets changed", isClient)
		}
	}
}

func TestPaddingReaderReadErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
		err  error
	}{
		{name: "eof", err: io.EOF},
		{name: "truncated", wire: []byte{2, 1}, err: io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := newPaddingReader(bytes.NewReader(test.wire), true)
			if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, test.err) {
				t.Fatalf("got %v, want %v", err, test.err)
			}
		})
	}
}

func TestPaddingReaderUnblocksOnClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	reader := newPaddingReader(client, true)
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed read = %v", err)
	}
}
