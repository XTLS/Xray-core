package encoding

import (
	"bytes"
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
)

func EncodeHeaderAddons(buffer *buf.Buffer, addons *Addons) error {
	if addons.Flow == vless.XRV || len(addons.Seed) > 0 {
		bytes, err := proto.Marshal(addons)
		if err != nil {
			return errors.New("failed to marshal addons protobuf value").Base(err)
		}
		if err := buffer.WriteByte(byte(len(bytes))); err != nil {
			return errors.New("failed to write addons protobuf length").Base(err)
		}
		if _, err := buffer.Write(bytes); err != nil {
			return errors.New("failed to write addons protobuf value").Base(err)
		}
	} else {
		if err := buffer.WriteByte(0); err != nil {
			return errors.New("failed to write addons protobuf length").Base(err)
		}
	}
	return nil
}

func DecodeHeaderAddons(buffer *buf.Buffer, reader io.Reader) (*Addons, error) {
	addons := new(Addons)
	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, errors.New("failed to read addons protobuf length").Base(err)
	}

	if length := int32(buffer.Byte(0)); length != 0 {
		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, length); err != nil {
			return nil, errors.New("failed to read addons protobuf value").Base(err)
		}

		if err := proto.Unmarshal(buffer.Bytes(), addons); err != nil {
			return nil, errors.New("failed to unmarshal addons protobuf value").Base(err)
		}
	}

	return addons, nil
}

// EncodeBodyAddons returns a Writer that auto-encrypt content written by caller.
func EncodeBodyAddons(writer io.Writer, request *protocol.RequestHeader, requestAddons *Addons, state *proxy.TrafficState, context context.Context) buf.Writer {
	if request.Command == protocol.RequestCommandUDP {
		return NewMultiLengthPacketWriter(writer.(buf.Writer))
	}
	w := buf.NewWriter(writer)
	if requestAddons.Flow == vless.XRV {
		w = proxy.NewVisionWriter(w, state, context)
	}
	return w
}

// DecodeBodyAddons returns a Reader from which caller can fetch decrypted body.
func DecodeBodyAddons(reader io.Reader, request *protocol.RequestHeader, addons *Addons) buf.Reader {
	if request.Command == protocol.RequestCommandUDP {
		return NewLengthPacketReader(reader)
	}
	return buf.NewReader(reader)
}

func NewMultiLengthPacketWriter(writer buf.Writer) *MultiLengthPacketWriter {
	return &MultiLengthPacketWriter{
		Writer: writer,
	}
}

type MultiLengthPacketWriter struct {
	buf.Writer
}

func (w *MultiLengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	mb2Write := make(buf.MultiBuffer, 0, len(mb)+1)
	for _, b := range mb {
		length := b.Len()
		if length == 0 || length+2 > buf.Size {
			continue
		}
		eb := buf.New()
		if err := eb.WriteByte(byte(length >> 8)); err != nil {
			eb.Release()
			continue
		}
		if err := eb.WriteByte(byte(length)); err != nil {
			eb.Release()
			continue
		}
		if _, err := eb.Write(b.Bytes()); err != nil {
			eb.Release()
			continue
		}
		mb2Write = append(mb2Write, eb)
	}
	if mb2Write.IsEmpty() {
		return nil
	}
	return w.Writer.WriteMultiBuffer(mb2Write)
}

func NewLengthPacketWriter(writer io.Writer) *LengthPacketWriter {
	return &LengthPacketWriter{
		Writer: writer,
		cache:  make([]byte, 0, 65536),
	}
}

type LengthPacketWriter struct {
	io.Writer
	cache []byte
}

func (w *LengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	length := mb.Len() // none of mb is nil
	// fmt.Println("Write", length)
	if length == 0 {
		return nil
	}
	defer func() {
		w.cache = w.cache[:0]
	}()
	w.cache = append(w.cache, byte(length>>8), byte(length))
	for i, b := range mb {
		w.cache = append(w.cache, b.Bytes()...)
		b.Release()
		mb[i] = nil
	}
	if _, err := w.Write(w.cache); err != nil {
		return errors.New("failed to write a packet").Base(err)
	}
	return nil
}

func NewLengthPacketReader(reader io.Reader) *LengthPacketReader {
	return &LengthPacketReader{
		Reader: reader,
		cache:  make([]byte, 2),
	}
}

type LengthPacketReader struct {
	io.Reader
	cache []byte
}

func (r *LengthPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if _, err := io.ReadFull(r.Reader, r.cache); err != nil { // maybe EOF
		return nil, errors.New("failed to read packet length").Base(err)
	}
	length := int32(r.cache[0])<<8 | int32(r.cache[1])
	// fmt.Println("Read", length)
	mb := make(buf.MultiBuffer, 0, length/buf.Size+1)
	for length > 0 {
		size := length
		if size > buf.Size {
			size = buf.Size
		}
		length -= size
		b := buf.New()
		if _, err := b.ReadFullFrom(r.Reader, size); err != nil {
			return nil, errors.New("failed to read packet payload").Base(err)
		}
		mb = append(mb, b)
	}
	return mb, nil
}

func PopulateSeed(seed string, addons *Addons) {
	if len(seed) > 0 {
		addons.Seed = []byte {1} // only turn on, more TBD
		addons.Mode = SeedMode_PaddingPlusDelay
		addons.Duration = "0-8"
		addons.Padding = &PaddingConfig{
			RegularMin: 0,
			RegularMax: 256,
			LongMin:    900,
			LongMax:    1400,
		}
		addons.Delay = &DelayConfig{
			IsRandom: true,
			MinMillis: 100,
			MaxMillis: 500,
		}
		addons.Scheduler = &SchedulerConfig{
			TimeoutMillis: 600,
		}
	}
}

func CheckSeed(requestAddons *Addons, responseAddons *Addons) error {
	if !bytes.Equal(requestAddons.Seed, responseAddons.Seed) {
		return newError("Seed bytes not match", requestAddons.Seed, responseAddons.Seed)
	}
	if requestAddons.Mode != responseAddons.Mode {
		return newError("Mode not match", requestAddons.Mode, responseAddons.Mode)
	}
	if requestAddons.Duration != responseAddons.Duration {
		return newError("Duration not match", requestAddons.Duration, responseAddons.Duration)
	}
	if requestAddons.Padding != nil && responseAddons.Padding != nil {
		if requestAddons.Padding.RegularMin != responseAddons.Padding.RegularMin || 
		requestAddons.Padding.RegularMax != responseAddons.Padding.RegularMax || 
		requestAddons.Padding.LongMin != responseAddons.Padding.LongMin || 
		requestAddons.Padding.LongMax != responseAddons.Padding.LongMax {
			return newError("Padding not match")
		}
	} else if requestAddons.Padding != nil || responseAddons.Padding != nil {
		return newError("Padding of one is nil but the other is not nil")
	}
	if requestAddons.Delay != nil && responseAddons.Delay != nil {
		if requestAddons.Delay.IsRandom != responseAddons.Delay.IsRandom || 
		requestAddons.Delay.MinMillis != responseAddons.Delay.MinMillis || 
		requestAddons.Delay.MaxMillis != responseAddons.Delay.MaxMillis {
			return newError("Delay not match")
		}
	} else if requestAddons.Delay != nil || responseAddons.Delay != nil {
		return newError("Delay of one is nil but the other is not nil")
	}
	if requestAddons.Scheduler != nil && responseAddons.Scheduler != nil {
		if requestAddons.Scheduler.TimeoutMillis != responseAddons.Scheduler.TimeoutMillis {
			return newError("Scheduler not match")
		}
	} else if requestAddons.Scheduler != nil || responseAddons.Scheduler != nil {
		return newError("Scheduler of one is nil but the other is not nil")
	}
	return nil
}
