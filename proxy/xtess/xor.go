package xtess

import (
	"github.com/xtls/xray-core/common/buf"
)

var DefaultXORKey = []byte{0x5A}

// TransformFunc transforms the provided byte slice in-place.
type TransformFunc func(b []byte)

//type TransformFunc func([]byte)

//var DefaultXORKey byte = 0x5A

// MakeXORTransform returns a TransformFunc that XORs every byte with a single-byte key.
func MakeXORTransformByte(key byte) TransformFunc {
	return func(b []byte) {
		for i := 0; i < len(b); i++ {
			b[i] ^= key
		}
	}
}

type TransformWriter struct {
	writer    buf.Writer
	transform TransformFunc
}

func NewTransformWriter(w buf.Writer, t TransformFunc) buf.Writer {
	return &TransformWriter{writer: w, transform: t}
}

func (w *TransformWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		data := b.Bytes()
		if len(data) > 0 && w.transform != nil {
			w.transform(data)
		}
		if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

type TransformReader struct {
	reader    buf.Reader
	transform TransformFunc
}

func NewTransformReader(r buf.Reader, t TransformFunc) buf.Reader {
	return &TransformReader{reader: r, transform: t}
}

func (r *TransformReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}
	for i := range mb {
		b := mb[i]
		data := b.Bytes()
		if len(data) > 0 && r.transform != nil {
			r.transform(data)
		}
	}
	return mb, nil
}

func EncryptString(input string, key byte) string {
	encrypted := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		encrypted[i] = input[i] ^ key
	}
	return string(encrypted)
}

func DecryptString(encrypted string, key byte) (string, error) {
	decrypted := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i++ {
		decrypted[i] = encrypted[i] ^ key
	}
	return string(decrypted), nil
}
