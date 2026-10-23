package reality

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

// Reality specifc file, used for target detection

var (
	GlobalPostHandshakeRecordsLens sync.Map
	GlobalMaxCSSMsgCount           sync.Map
)

func DetectPostHandshakeRecordsLens(config *Config) {
	for sni := range config.ServerNames {
		for alpn := range 3 { // 0, 1, 2
			key := config.Dest + " " + sni + " " + strconv.Itoa(alpn)
			if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(key, false); !loaded {
				go func() {
					defer func() {
						val, _ := GlobalPostHandshakeRecordsLens.Load(key)
						if _, ok := val.(bool); ok {
							GlobalPostHandshakeRecordsLens.Store(key, []int{})
						}
					}()
					target, err := net.Dial(config.Type, config.Dest)
					if err != nil {
						return
					}
					defer target.Close()
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					detectConn := &PostHandshakeRecordDetectConn{
						Conn: target,
						Key:  key,
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					uConn := utls.UClient(detectConn, &utls.Config{
						ServerName: sni, // needs new loopvar behaviour
						NextProtos: nextProtos,
					}, fingerprint)
					if err = uConn.Handshake(); err != nil {
						return
					}
					io.Copy(io.Discard, uConn)
				}()
				go func() {
					target, err := net.Dial(config.Type, config.Dest)
					if err != nil {
						return
					}
					defer target.Close()
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					conn := &CCSDetectConn{
						Conn: target,
						Key:  key,
					}
					uConn := utls.UClient(conn, &utls.Config{
						ServerName: sni, // needs new loopvar behaviour
						NextProtos: nextProtos,
					}, fingerprint)
					if err = uConn.Handshake(); err != nil {
						return
					}
				}()
			}
		}
	}
}

type PostHandshakeRecordDetectConn struct {
	net.Conn
	Key     string
	CcsSent bool
}

func (c *PostHandshakeRecordDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *PostHandshakeRecordDetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	var postHandshakeRecordsLens []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			// illegal dada
			if length > len(data) {
				break
			}
			postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
			data = data[length:]
		} else {
			break
		}
	}
	GlobalPostHandshakeRecordsLens.Store(c.Key, postHandshakeRecordsLens)
	return 0, io.EOF
}

var CCSMsg = []byte{0x14, 0x3, 0x3, 0x0, 0x1, 0x1}

type CCSDetectConn struct {
	net.Conn
	Key string
}

func (c *CCSDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		var hasAlert atomic.Bool
		go func() {
			defer hasAlert.Store(true)
			buf := make([]byte, 512)
			for {
				_, err := c.Conn.Read(buf)
				if err != nil {
					return
				}
				if buf[0] == 0x15 {
					return
				}
			}
		}()
		sendProbePayload := func(count int) bool {
			msg := bytes.Repeat(CCSMsg, count)
			c.Conn.Write(msg)
			time.Sleep(1 * time.Second)
			if hasAlert.Load() {
				return true
			}
			return false
		}
		if sendProbePayload(2) {
			GlobalMaxCSSMsgCount.Store(c.Key, 1)
			return c.Conn.Write(b)
		}
		if sendProbePayload(15) {
			GlobalMaxCSSMsgCount.Store(c.Key, 16)
			return c.Conn.Write(b)
		}
		if sendProbePayload(16) {
			GlobalMaxCSSMsgCount.Store(c.Key, 32)
			return c.Conn.Write(b)
		}
		GlobalMaxCSSMsgCount.Store(c.Key, math.MaxInt)
		return c.Conn.Write(b)
	}
	return c.Conn.Write(b)
}
