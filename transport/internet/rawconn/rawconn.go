package rawconn

import (
	"context"
	"io"
	"runtime"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func IsRAW(conn stat.Connection) bool {
	if conn == nil {
		return false
	}
	iConn := stat.TryUnwrapStatsConn(conn)
	iConn = finalmask.UnwrapTcpMask(iConn)
	_, ok1 := iConn.(*proxyproto.Conn)
	_, ok2 := iConn.(*net.TCPConn)
	_, ok3 := iConn.(*internet.UnixConnWrapper)
	return ok1 || ok2 || ok3
}

func Unwrap(conn net.Conn) (net.Conn, stats.Counter, stats.Counter) {
	var readCounter, writerCounter stats.Counter
	if conn != nil {
		isEncryption := false
		if commonConn, ok := conn.(*encryption.CommonConn); ok {
			conn = commonConn.Conn
			isEncryption = true
		}
		if xorConn, ok := conn.(*encryption.XorConn); ok {
			return xorConn, nil, nil
		}
		if statConn, ok := conn.(*stat.CounterConnection); ok {
			conn = statConn.Connection
			readCounter = statConn.ReadCounter
			writerCounter = statConn.WriteCounter
		}

		if !isEncryption {
			if xc, ok := conn.(*tls.Conn); ok {
				conn = xc.NetConn()
			} else if utlsConn, ok := conn.(*tls.UConn); ok {
				conn = utlsConn.NetConn()
			} else if realityConn, ok := conn.(*reality.Conn); ok {
				conn = realityConn.NetConn()
			} else if realityUConn, ok := conn.(*reality.UConn); ok {
				conn = realityUConn.NetConn()
			}
		}

		conn = finalmask.UnwrapTcpMask(conn)

		if pc, ok := conn.(*proxyproto.Conn); ok {
			conn = pc.Raw()
		}
		if uc, ok := conn.(*internet.UnixConnWrapper); ok {
			conn = uc.UnixConn
		}
	}
	return conn, readCounter, writerCounter
}

func CopyIfExist(ctx context.Context, readerConn net.Conn, writerConn net.Conn, writer buf.Writer, timer, inTimer *signal.ActivityTimer) error {
	readerConn, readCounter, _ := Unwrap(readerConn)
	writerConn, _, writeCounter := Unwrap(writerConn)
	reader := buf.NewReader(readerConn)
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return readV(ctx, reader, writer, timer, readCounter)
	}
	tc, ok := writerConn.(*net.TCPConn)
	if !ok || readerConn == nil || writerConn == nil {
		return readV(ctx, reader, writer, timer, readCounter)
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.CanSpliceCopy == 3 {
		return readV(ctx, reader, writer, timer, readCounter)
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return readV(ctx, reader, writer, timer, readCounter)
	}
	for _, ob := range outbounds {
		if ob.CanSpliceCopy == 3 {
			return readV(ctx, reader, writer, timer, readCounter)
		}
	}

	for {
		inbound := session.InboundFromContext(ctx)
		outbounds := session.OutboundsFromContext(ctx)
		splice := inbound.CanSpliceCopy == 1
		for _, ob := range outbounds {
			if ob.CanSpliceCopy != 1 {
				splice = false
			}
		}
		if splice {
			errors.LogDebug(ctx, "rawconn: splice")
			statWriter, _ := writer.(*dispatcher.SizeStatWriter)
			timer.SetTimeout(24 * time.Hour)
			if inTimer != nil {
				inTimer.SetTimeout(24 * time.Hour)
			}
			w, err := tc.ReadFrom(readerConn)
			if readCounter != nil {
				readCounter.Add(w)
			}
			if writeCounter != nil {
				writeCounter.Add(w)
			}
			if statWriter != nil {
				statWriter.Counter.Add(w)
			}
			if err != nil && errors.Cause(err) != io.EOF {
				return err
			}
			return nil
		}
		buffer, err := reader.ReadMultiBuffer()
		if !buffer.IsEmpty() {
			if readCounter != nil {
				readCounter.Add(int64(buffer.Len()))
			}
			timer.Update()
			if werr := writer.WriteMultiBuffer(buffer); werr != nil {
				return werr
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

func readV(ctx context.Context, reader buf.Reader, writer buf.Writer, timer signal.ActivityUpdater, readCounter stats.Counter) error {
	errors.LogDebug(ctx, "rawconn: copy (maybe) readv")
	if err := buf.Copy(reader, writer, buf.UpdateActivity(timer), buf.AddToStatCounter(readCounter)); err != nil {
		return errors.New("failed to process response").Base(err)
	}
	return nil
}
