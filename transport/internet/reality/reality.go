package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

//go:linkname aesgcmPreferred github.com/refraction-networking/utls.aesgcmPreferred
func aesgcmPreferred(ciphers []uint16) bool

type Conn struct {
	*reality.Conn
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func Server(c net.Conn, config *reality.Config) (net.Conn, error) {
	realityConn, err := reality.Server(context.Background(), c, config)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	ServerName string
	AuthKey    []byte
	Verified   bool
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func (c *UConn) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func UClient(c net.Conn, config *Config, ctx context.Context, dest net.Destination) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn := &UConn{}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  uConn.VerifyPeerCertificate,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = dest.Address.String()
	}
	uConn.ServerName = utlsConfig.ServerName
	fingerprint := tls.GetFingerprint(config.Fingerprint)
	if fingerprint == nil {
		return nil, newError("REALITY: failed to get fingerprint").AtError()
	}
	uConn.UConn = utls.UClient(c, utlsConfig, *fingerprint)
	{
		uConn.BuildHandshakeState()
		hello := uConn.HandshakeState.Hello
		hello.SessionId = make([]byte, 32)
		copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
		hello.SessionId[0] = core.Version_x
		hello.SessionId[1] = core.Version_y
		hello.SessionId[2] = core.Version_z
		hello.SessionId[3] = 0 // reserved
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
		copy(hello.SessionId[8:], config.ShortId)
		if config.Show {
			newError(fmt.Sprintf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])).WriteToLog(session.ExportIDToError(ctx))
		}
		publicKey, _ := ecdh.X25519().NewPublicKey(config.PublicKey)
		uConn.AuthKey, _ = uConn.HandshakeState.State13.EcdheKey.ECDH(publicKey)
		if uConn.AuthKey == nil {
			return nil, errors.New("REALITY: SharedKey == nil")
		}
		if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
			return nil, err
		}
		var aead cipher.AEAD
		if aesgcmPreferred(hello.CipherSuites) {
			block, _ := aes.NewCipher(uConn.AuthKey)
			aead, _ = cipher.NewGCM(block)
		} else {
			aead, _ = chacha20poly1305.New(uConn.AuthKey)
		}
		if config.Show {
			newError(fmt.Sprintf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD: %T\n", localAddr, uConn.AuthKey[:16], aead)).WriteToLog(session.ExportIDToError(ctx))
		}
		aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if config.Show {
		newError(fmt.Sprintf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)).WriteToLog(session.ExportIDToError(ctx))
	}
	if !uConn.Verified {
		go func() {
			client := &http.Client{
				Transport: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
						newError(fmt.Sprintf("REALITY localAddr: %v\tDialTLSContext\n", localAddr)).WriteToLog(session.ExportIDToError(ctx))
						return uConn, nil
					},
				},
			}
			prefix := []byte("https://" + uConn.ServerName)
			maps.Lock()
			if maps.maps == nil {
				maps.maps = make(map[string]map[string]bool)
			}
			paths := maps.maps[uConn.ServerName]
			if paths == nil {
				paths = make(map[string]bool)
				paths[config.SpiderX] = true
				maps.maps[uConn.ServerName] = paths
			}
			firstURL := string(prefix) + getPathLocked(paths)
			maps.Unlock()
			get := func(first bool) {
				var (
					req  *http.Request
					resp *http.Response
					err  error
					body []byte
				)
				if first {
					req, _ = http.NewRequest("GET", firstURL, nil)
				} else {
					maps.Lock()
					req, _ = http.NewRequest("GET", string(prefix)+getPathLocked(paths), nil)
					maps.Unlock()
				}
				req.Header.Set("User-Agent", fingerprint.Client) // TODO: User-Agent map
				if first && config.Show {
					newError(fmt.Sprintf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())).WriteToLog(session.ExportIDToError(ctx))
				}
				times := 1
				if !first {
					times = int(randBetween(config.SpiderY[4], config.SpiderY[5]))
				}
				for j := 0; j < times; j++ {
					if !first && j == 0 {
						req.Header.Set("Referer", firstURL)
					}
					req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(randBetween(config.SpiderY[0], config.SpiderY[1])))})
					if resp, err = client.Do(req); err != nil {
						break
					}
					req.Header.Set("Referer", req.URL.String())
					if body, err = io.ReadAll(resp.Body); err != nil {
						break
					}
					maps.Lock()
					for _, m := range href.FindAllSubmatch(body, -1) {
						m[1] = bytes.TrimPrefix(m[1], prefix)
						if !bytes.Contains(m[1], dot) {
							paths[string(m[1])] = true
						}
					}
					req.URL.Path = getPathLocked(paths)
					if config.Show {
						newError(fmt.Sprintf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())).WriteToLog(session.ExportIDToError(ctx))
						newError(fmt.Sprintf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))).WriteToLog(session.ExportIDToError(ctx))
						newError(fmt.Sprintf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))).WriteToLog(session.ExportIDToError(ctx))
					}
					maps.Unlock()
					if !first {
						time.Sleep(time.Duration(randBetween(config.SpiderY[6], config.SpiderY[7])) * time.Millisecond) // interval
					}
				}
			}
			get(true)
			concurrency := int(randBetween(config.SpiderY[2], config.SpiderY[3]))
			for i := 0; i < concurrency; i++ {
				go get(false)
			}
			// Do not close the connection
		}()
		time.Sleep(time.Duration(randBetween(config.SpiderY[8], config.SpiderY[9])) * time.Millisecond) // return
		return nil, errors.New("REALITY: processed invalid connection")
	}
	return uConn, nil
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]bool
}

func getPathLocked(paths map[string]bool) string {
	stopAt := int(randBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}

func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}
