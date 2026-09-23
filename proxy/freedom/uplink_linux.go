//go:build linux && !android

package freedom

import (
	"io"
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sys/unix"
)

func copyUplink(reader buf.Reader, writer buf.Writer, conn net.Conn, timer signal.ActivityUpdater) error {
	source, ok := reader.(buf.SpliceReader)
	dst, tcp := stat.TryUnwrapStatsConn(conn).(*net.TCPConn)
	if !ok || !tcp {
		return buf.Copy(reader, writer, buf.UpdateActivity(timer))
	}
	for {
		if src, counters := source.SpliceSource(); src != nil {
			onRead := func(n int64) {
				for _, counter := range counters {
					counter.Add(n)
				}
				timer.Update()
			}
			onWrite := func(n int64) {
				if conn, ok := conn.(*stat.CounterConnection); ok && conn.WriteCounter != nil {
					conn.WriteCounter.Add(n)
				}
			}
			if handled, err := spliceUplink(dst, src, onRead, onWrite); handled {
				return err
			}
			return buf.Copy(reader, writer, buf.UpdateActivity(timer))
		}
		mb, err := reader.ReadMultiBuffer()
		if !mb.IsEmpty() {
			timer.Update()
			if err := writer.WriteMultiBuffer(mb); err != nil {
				return err
			}
		}
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
	}
}

// TCPConn.ReadFrom hides intermediate reads and writes. Keep the same empty-pipe
// invariant as Go's splice loop, but account for reads before a write can block.
func spliceUplink(dst, src *net.TCPConn, onRead, onWrite func(int64)) (bool, error) {
	rawSrc, err := src.SyscallConn()
	if err != nil {
		return false, nil
	}
	rawDst, err := dst.SyscallConn()
	if err != nil {
		return false, nil
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return false, nil
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])

	handled := false
	for {
		var n int64
		var syscallErr error
		err := rawSrc.Read(func(fd uintptr) bool {
			for {
				n, syscallErr = unix.Splice(int(fd), nil, pipe[1], nil, 1<<20, unix.SPLICE_F_NONBLOCK)
				if syscallErr != unix.EINTR {
					return syscallErr != unix.EAGAIN
				}
			}
		})
		if err != nil {
			return true, err
		}
		if syscallErr != nil {
			if !handled && syscallErr == unix.EINVAL {
				return false, nil // No data was consumed; the buffered path is still safe.
			}
			return true, syscallErr
		}
		if n == 0 {
			return true, nil
		}
		handled = true
		onRead(n)
		for remaining := n; remaining > 0; {
			n = 0 // RawConn.Write can fail before invoking its callback.
			err := rawDst.Write(func(fd uintptr) bool {
				for {
					n, syscallErr = unix.Splice(pipe[0], nil, int(fd), nil, int(remaining), unix.SPLICE_F_NONBLOCK)
					if syscallErr != unix.EINTR {
						return syscallErr != unix.EAGAIN
					}
				}
			})
			if n > 0 {
				remaining -= n
				onWrite(n)
			}
			if err != nil {
				return true, err
			}
			if syscallErr != nil {
				return true, syscallErr
			}
			if n == 0 {
				return true, io.ErrShortWrite
			}
		}
	}
}
