package multiplex

import (
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/pipe"
)

func readAll(reader buf.Reader) (buf.MultiBuffer, error) {
	var mb buf.MultiBuffer
	for {
		b, err := reader.ReadMultiBuffer()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		mb = append(mb, b...)
	}
	return mb, nil
}

func TestReaderWriter(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))

	dest := net.TCPDestination(net.DomainAddress("example.com"), 80)
	s1 := &Session{ID: 1, target: dest, transferType: protocol.TransferTypeStream, inbound: &session.Inbound{}, first: true}

	dest2 := net.TCPDestination(net.LocalHostIP, 443)
	s2 := &Session{ID: 2, target: dest2, transferType: protocol.TransferTypeStream, inbound: &session.Inbound{}, first: true}

	dest3 := net.TCPDestination(net.LocalHostIPv6, 18374)
	s3 := &Session{ID: 3, target: dest3, transferType: protocol.TransferTypeStream, inbound: &session.Inbound{}, first: true}

	writePayload := func(s *Session, payload ...byte) error {
		b := buf.New()
		b.Write(payload)
		data := buf.MultiBuffer{b}
		defer func() { buf.ReleaseMulti(data) }()
		frames, err := s.encodeBatch(&data)
		if err != nil {
			buf.ReleaseMulti(frames)
			return err
		}
		return pWriter.WriteMultiBuffer(frames)
	}

	common.Must(writePayload(s1, 'a', 'b', 'c', 'd'))
	common.Must(writePayload(s2))

	common.Must(writePayload(s1, 'e', 'f', 'g', 'h'))
	common.Must(writePayload(s3, 'x'))

	common.Must(pWriter.WriteMultiBuffer(endFrame(s1.ID, false)))
	common.Must(pWriter.WriteMultiBuffer(endFrame(s3.ID, false)))

	common.Must(writePayload(s2, 'y'))
	common.Must(pWriter.WriteMultiBuffer(endFrame(s2.ID, false)))

	bytesReader := &buf.BufferedReader{Reader: pReader}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     1,
			SessionStatus: SessionStatusNew,
			Target:        dest,
			Option:        OptionData,
		}); r != "" {
			t.Error("metadata: ", r)
		}

		data, err := readAll(crypto.NewChunkStreamReaderWithChunkCount(crypto.PlainChunkSizeParser{}, bytesReader, 1))
		common.Must(err)
		if s := data.String(); s != "abcd" {
			t.Error("data: ", s)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionStatus: SessionStatusNew,
			SessionID:     2,
			Option:        0,
			Target:        dest2,
		}); r != "" {
			t.Error("meta: ", r)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     1,
			SessionStatus: SessionStatusKeep,
			Option:        1,
		}); r != "" {
			t.Error("meta: ", r)
		}

		data, err := readAll(crypto.NewChunkStreamReaderWithChunkCount(crypto.PlainChunkSizeParser{}, bytesReader, 1))
		common.Must(err)
		if s := data.String(); s != "efgh" {
			t.Error("data: ", s)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     3,
			SessionStatus: SessionStatusNew,
			Option:        1,
			Target:        dest3,
		}); r != "" {
			t.Error("meta: ", r)
		}

		data, err := readAll(crypto.NewChunkStreamReaderWithChunkCount(crypto.PlainChunkSizeParser{}, bytesReader, 1))
		common.Must(err)
		if s := data.String(); s != "x" {
			t.Error("data: ", s)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     1,
			SessionStatus: SessionStatusEnd,
			Option:        0,
		}); r != "" {
			t.Error("meta: ", r)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     3,
			SessionStatus: SessionStatusEnd,
			Option:        0,
		}); r != "" {
			t.Error("meta: ", r)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     2,
			SessionStatus: SessionStatusKeep,
			Option:        1,
		}); r != "" {
			t.Error("meta: ", r)
		}

		data, err := readAll(crypto.NewChunkStreamReaderWithChunkCount(crypto.PlainChunkSizeParser{}, bytesReader, 1))
		common.Must(err)
		if s := data.String(); s != "y" {
			t.Error("data: ", s)
		}
	}

	{
		var meta FrameMetadata
		common.Must(meta.Unmarshal(bytesReader, false))
		if r := cmp.Diff(meta, FrameMetadata{
			SessionID:     2,
			SessionStatus: SessionStatusEnd,
			Option:        0,
		}); r != "" {
			t.Error("meta: ", r)
		}
	}

	pWriter.Close()

	{
		var meta FrameMetadata
		err := meta.Unmarshal(bytesReader, false)
		if err == nil {
			t.Error("nil error")
		}
	}
}
