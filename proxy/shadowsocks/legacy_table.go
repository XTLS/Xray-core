package shadowsocks

import (
	"crypto/md5"
	"encoding/binary"
	"io"
	"sort"

	"github.com/xtls/xray-core/common/buf"
)

type TableCipher struct {
	encryptTable [256]byte
	decryptTable [256]byte
}

type tableSorter struct {
	table []byte
	a     uint64
	i     uint64
}

func (s *tableSorter) Len() int      { return len(s.table) }
func (s *tableSorter) Swap(x, y int) { s.table[x], s.table[y] = s.table[y], s.table[x] }
func (s *tableSorter) Less(x, y int) bool {
	vx := s.a % (uint64(s.table[x]) + s.i)
	vy := s.a % (uint64(s.table[y]) + s.i)
	return vx < vy
}

func NewTableCipher(key string) *TableCipher {
	h := md5.Sum([]byte(key))
	a := binary.LittleEndian.Uint64(h[:8])

	table := make([]byte, 256)
	for i := 0; i < 256; i++ {
		table[i] = byte(i)
	}

	for i := 1; i < 1024; i++ {
		sort.Stable(&tableSorter{
			table: table,
			a:     a,
			i:     uint64(i),
		})
	}

	c := &TableCipher{}
	for i := 0; i < 256; i++ {
		c.encryptTable[i] = table[i]
		c.decryptTable[table[i]] = byte(i)
	}
	return c
}

func (c *TableCipher) KeySize() int32 {
	return 0
}

func (c *TableCipher) IVSize() int32 {
	return 0
}

func (c *TableCipher) IsAEAD() bool {
	return false
}

type tableWriter struct {
	writer io.Writer
	table  *[256]byte
}

func (w *tableWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		data := b.Bytes()
		for i, v := range data {
			data[i] = w.table[v]
		}
	}
	return buf.NewWriter(w.writer).WriteMultiBuffer(mb)
}

func (c *TableCipher) NewEncryptionWriter(key []byte, iv []byte, writer io.Writer) (buf.Writer, error) {
	return &tableWriter{
		writer: writer,
		table:  &c.encryptTable,
	}, nil
}

type tableReader struct {
	reader io.Reader
	table  *[256]byte
}

func (r *tableReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := buf.NewReader(r.reader).ReadMultiBuffer()
	if mb != nil {
		for _, b := range mb {
			data := b.Bytes()
			for i, v := range data {
				data[i] = r.table[v]
			}
		}
	}
	return mb, err
}

func (c *TableCipher) NewDecryptionReader(key []byte, iv []byte, reader io.Reader) (buf.Reader, error) {
	return &tableReader{
		reader: reader,
		table:  &c.decryptTable,
	}, nil
}

func (c *TableCipher) EncodePacket(key []byte, b *buf.Buffer) error {
	data := b.Bytes()
	for i, v := range data {
		data[i] = c.encryptTable[v]
	}
	return nil
}

func (c *TableCipher) DecodePacket(key []byte, b *buf.Buffer) error {
	data := b.Bytes()
	for i, v := range data {
		data[i] = c.decryptTable[v]
	}
	return nil
}
