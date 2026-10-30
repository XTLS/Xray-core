package mux

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
)

// SOCKS mux responses share one writer. Check both progress and frame integrity.
func TestMuxWriterConcurrentTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			done <- err
			return
		}
		seen := make(map[uint64]bool)
		for i := 0; i < 8001; i++ {
			frame := make([]byte, 136)
			if _, err = io.ReadFull(c, frame); err != nil {
				done <- err
				return
			}
			id := binary.BigEndian.Uint64(frame[:8])
			stream := id >> 32
			if seen[id] || (stream > 7 && id != ^uint64(0)) {
				t.Error("invalid/duplicated frame", id)
			}
			seen[id] = true
			if !bytes.Equal(frame[8:], bytes.Repeat([]byte{byte(stream)}, 128)) {
				t.Error("interleaved frame payload", id)
			}
		}
		var extra [1]byte
		n, err := c.Read(extra[:])
		if n != 0 || err != io.EOF {
			t.Error("unexpected trailing bytes")
		}
		done <- nil
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writer := workerWriter(t, "server", buf.NewWriter(conn))
	write := func(stream, sequence uint32) error {
		header := make([]byte, 8)
		binary.BigEndian.PutUint64(header, uint64(stream)<<32|uint64(sequence))
		return writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(header), buf.FromBytes(bytes.Repeat([]byte{byte(stream)}, 128))})
	}
	if err = write(^uint32(0), ^uint32(0)); err != nil {
		t.Fatal(err)
	} // warm reusable vector cache
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if err := write(id, uint32(j)); err != nil {
					t.Error(err)
					return
				}
			}
		}(uint32(i))
	}
	wg.Wait()
	conn.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkMuxWriterTCP(b *testing.B) {
	for _, size := range []int{128, 4096, 8192} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for _, locked := range []bool{false, true} {
				name := "direct"
				if locked {
					name = "locked"
				}
				b.Run(name, func(b *testing.B) {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						b.Fatal(err)
					}
					defer listener.Close()
					done := make(chan error, 1)
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							done <- err
							return
						}
						defer conn.Close()
						_, err = io.Copy(io.Discard, conn)
						done <- err
					}()
					conn, err := net.Dial("tcp", listener.Addr().String())
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() {
						_ = conn.Close()
						if err := <-done; err != nil {
							b.Error(err)
						}
					})
					if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
						b.Fatal(err)
					}
					var out buf.Writer = buf.NewWriter(conn)
					if locked {
						out = newMuxWriter(out)
					}
					writer := NewResponseWriter(1, out, protocol.TransferTypeStream)
					payload := bytes.Repeat([]byte{1}, size)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if err := writer.WriteMultiBuffer(buf.MergeBytes(nil, payload)); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
