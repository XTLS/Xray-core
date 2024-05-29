package proxy

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type FallbackMap = map[string]map[string]map[string]*Fallback

func BuildFallbackMap(fallbacks []*Fallback) FallbackMap {
	fbmap := make(map[string]map[string]map[string]*Fallback)
	for _, fb := range fallbacks {
		if fbmap[fb.Name] == nil {
			fbmap[fb.Name] = make(map[string]map[string]*Fallback)
		}
		if fbmap[fb.Name][fb.Alpn] == nil {
			fbmap[fb.Name][fb.Alpn] = make(map[string]*Fallback)
		}
		fbmap[fb.Name][fb.Alpn][fb.Path] = fb
	}
	if fbmap[""] != nil {
		for name, apfb := range fbmap {
			if name != "" {
				for alpn := range fbmap[""] {
					if apfb[alpn] == nil {
						apfb[alpn] = make(map[string]*Fallback)
					}
				}
			}
		}
	}
	for _, apfb := range fbmap {
		if apfb[""] != nil {
			for alpn, pfb := range apfb {
				if alpn != "" { // && alpn != "h2" {
					for path, fb := range apfb[""] {
						if pfb[path] == nil {
							pfb[path] = fb
						}
					}
				}
			}
		}
	}
	if fbmap[""] != nil {
		for name, apfb := range fbmap {
			if name != "" {
				for alpn, pfb := range fbmap[""] {
					for path, fb := range pfb {
						if apfb[alpn][path] == nil {
							apfb[alpn][path] = fb
						}
					}
				}
			}
		}
	}
	return fbmap
}

func SearchFallbackMap(ctx context.Context, napfb FallbackMap, buf *buf.Buffer, bufLen int64, name string, alpn string) (*Fallback, error) {
	if len(napfb) > 1 || napfb[""] == nil {
		if name != "" && napfb[name] == nil {
			match := ""
			for n := range napfb {
				if n != "" && strings.Contains(name, n) && len(n) > len(match) {
					match = n
				}
			}
			name = match
		}
	}

	if napfb[name] == nil {
		name = ""
	}
	apfb := napfb[name]
	if apfb == nil {
		return nil, newError(`failed to find the default "name" config`).AtWarning()
	}

	if apfb[alpn] == nil {
		alpn = ""
	}
	pfb := apfb[alpn]
	if pfb == nil {
		return nil, newError(`failed to find the default "alpn" config`).AtWarning()
	}

	path := ""
	if len(pfb) > 1 || pfb[""] == nil {
		if bufLen >= 18 && buf.Byte(4) != '*' { // not h2c
			bufBytes := buf.Bytes()
			for i := 4; i <= 8; i++ { // 5 -> 9
				if bufBytes[i] == '/' && bufBytes[i-1] == ' ' {
					search := len(bufBytes)
					if search > 64 {
						search = 64 // up to about 60
					}
					for j := i + 1; j < search; j++ {
						k := bufBytes[j]
						if k == '\r' || k == '\n' { // avoid logging \r or \n
							break
						}
						if k == '?' || k == ' ' {
							path = string(bufBytes[i:j])
							if ctx != nil {
								sid := session.ExportIDToError(ctx)
								newError("realPath = " + path).AtInfo().WriteToLog(sid)
							}
							if pfb[path] == nil {
								path = ""
							}
							break
						}
					}
					break
				}
			}
		}
	}
	fb := pfb[path]
	if fb == nil {
		return nil, newError(`failed to find the default "path" config`).AtWarning()
	}
	return fb, nil
}

func ApplyFallback(ctx context.Context, sessionPolicy policy.Session, connection stat.Connection, iConn stat.Connection, fbMap FallbackMap, first *buf.Buffer, firstLen int64, reader buf.Reader) error {
	sid := session.ExportIDToError(ctx)

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		newError("unable to set back read deadline").Base(err).AtWarning().WriteToLog(sid)
	}

	name := ""
	alpn := ""
	if tlsConn, ok := iConn.(*tls.Conn); ok {
		cs := tlsConn.ConnectionState()
		name = cs.ServerName
		alpn = cs.NegotiatedProtocol
		newError("realName = " + name).AtInfo().WriteToLog(sid)
		newError("realAlpn = " + alpn).AtInfo().WriteToLog(sid)
	} else if realityConn, ok := iConn.(*reality.Conn); ok {
		cs := realityConn.ConnectionState()
		name = cs.ServerName
		alpn = cs.NegotiatedProtocol
		newError("realName = " + name).AtInfo().WriteToLog(sid)
		newError("realAlpn = " + alpn).AtInfo().WriteToLog(sid)
	}
	name = strings.ToLower(name)
	alpn = strings.ToLower(alpn)

	fb, err := SearchFallbackMap(ctx, fbMap, first, firstLen, name, alpn)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

	var conn net.Conn
	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return newError("failed to dial to " + fb.Dest).Base(err).AtWarning()
	}
	defer conn.Close()

	serverReader := buf.NewReader(conn)
	serverWriter := buf.NewWriter(conn)

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		if fb.Xver != 0 {
			ipType := 4
			remoteAddr, remotePort, err := net.SplitHostPort(connection.RemoteAddr().String())
			if err != nil {
				ipType = 0
			}
			localAddr, localPort, err := net.SplitHostPort(connection.LocalAddr().String())
			if err != nil {
				ipType = 0
			}
			if ipType == 4 {
				for i := 0; i < len(remoteAddr); i++ {
					if remoteAddr[i] == ':' {
						ipType = 6
						break
					}
				}
			}
			pro := buf.New()
			defer pro.Release()
			switch fb.Xver {
			case 1:
				if ipType == 0 {
					common.Must2(pro.Write([]byte("PROXY UNKNOWN\r\n")))
					break
				}
				if ipType == 4 {
					common.Must2(pro.Write([]byte("PROXY TCP4 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n")))
				} else {
					common.Must2(pro.Write([]byte("PROXY TCP6 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n")))
				}
			case 2:
				common.Must2(pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"))) // signature
				if ipType == 0 {
					common.Must2(pro.Write([]byte("\x20\x00\x00\x00"))) // v2 + LOCAL + UNSPEC + UNSPEC + 0 bytes
					break
				}
				if ipType == 4 {
					common.Must2(pro.Write([]byte("\x21\x11\x00\x0C"))) // v2 + PROXY + AF_INET + STREAM + 12 bytes
					common.Must2(pro.Write(net.ParseIP(remoteAddr).To4()))
					common.Must2(pro.Write(net.ParseIP(localAddr).To4()))
				} else {
					common.Must2(pro.Write([]byte("\x21\x21\x00\x24"))) // v2 + PROXY + AF_INET6 + STREAM + 36 bytes
					common.Must2(pro.Write(net.ParseIP(remoteAddr).To16()))
					common.Must2(pro.Write(net.ParseIP(localAddr).To16()))
				}
				p1, _ := strconv.ParseUint(remotePort, 10, 16)
				p2, _ := strconv.ParseUint(localPort, 10, 16)
				common.Must2(pro.Write([]byte{byte(p1 >> 8), byte(p1), byte(p2 >> 8), byte(p2)}))
			}
			if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro}); err != nil {
				return newError("failed to set PROXY protocol v", fb.Xver).Base(err).AtWarning()
			}
		}
		if err := buf.Copy(reader, serverWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to fallback request payload").Base(err).AtInfo()
		}
		return nil
	}

	writer := buf.NewWriter(connection)

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		if err := buf.Copy(serverReader, writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to deliver response payload").Base(err).AtInfo()
		}
		return nil
	}

	if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(writer))); err != nil {
		common.Must(common.Interrupt(serverReader))
		common.Must(common.Interrupt(serverWriter))
		return newError("fallback ends").Base(err).AtInfo()
	}

	return nil
}
