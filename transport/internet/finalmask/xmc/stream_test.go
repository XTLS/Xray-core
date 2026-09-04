package xmc

import (
	"bytes"
	"io"
	"testing"
)

type dataAndEOFReader struct {
	data []byte
}

func (r *dataAndEOFReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, io.EOF
}

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:len(p)/2]
	}
	return w.Buffer.Write(p)
}

func TestCryptoReaderPreservesDataReturnedWithEOF(t *testing.T) {
	secret := []byte("0123456789abcdef")
	plaintext := []byte("payload returned with EOF")
	var encrypted bytes.Buffer
	writer, err := newCryptoWriter(&encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}

	reader, err := newCryptoReader(&dataAndEOFReader{data: encrypted.Bytes()}, secret)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	n, err := reader.Read(got)
	if err == nil || n != len(plaintext) {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if !bytes.Equal(got[:n], plaintext) {
		t.Fatalf("plaintext = %q", got[:n])
	}
}

func TestCryptoWriterHandlesShortWrites(t *testing.T) {
	secret := []byte("0123456789abcdef")
	plaintext := bytes.Repeat([]byte("short-write"), 100)
	var dst shortWriter
	writer, err := newCryptoWriter(&dst, secret)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write(plaintext); err != nil || n != len(plaintext) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	reader, err := newCryptoReader(bytes.NewReader(dst.Bytes()), secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted payload mismatch")
	}
}
