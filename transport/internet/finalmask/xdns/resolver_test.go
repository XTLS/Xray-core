package xdns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func resolverTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "resolver.test"}, DNSNames: []string{"resolver.test", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil { t.Fatal(err) }
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil { t.Fatal(err) }
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(root, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}))
	if err != nil { t.Fatal(err) }
	return pair, root
}

func resolverTestQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	p, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil { t.Fatal(err) }
	return p
}

func resolverTestReply(p []byte) []byte {
	response := append([]byte(nil), p...)
	response[2] |= 0x80
	return response
}

func TestRequestResolverOwnsInputAndContinuesAfterFailure(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	failed := make(chan struct{})
	r := newRequestResolver(&net.UDPAddr{}, func(ctx context.Context, p []byte) ([]byte, error) {
		var query dnsmessage.Message
		if err := query.Unpack(p); err != nil { return nil, err }
		if strings.HasPrefix(query.Questions[0].Name.String(), "fail.") { close(failed); return nil, errors.New("failed query") }
		close(entered)
		select { case <-release: case <-ctx.Done(): return nil, ctx.Err() }
		return resolverTestReply(p), nil
	}, nil)
	defer r.Close()
	if err := r.Send(resolverTestQuery(t, 99, "fail.resolver.test.")); err != nil { t.Fatal(err) }
	<-failed
	query := resolverTestQuery(t, 100, "copy.resolver.test.")
	original := append([]byte(nil), query...)
	if err := r.Send(query); err != nil { t.Fatal(err) }
	<-entered
	clear(query)
	close(release)
	buf := make([]byte, maxDNSMessageSize)
	n, err := r.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], resolverTestReply(original)) { t.Fatalf("input was overwritten: %x, %v", buf[:n], err) }
}

func TestRequestResolverAdmissionAndClose(t *testing.T) {
	entered := make(chan struct{}, resolverConcurrency)
	r := newRequestResolver(&net.UDPAddr{}, func(ctx context.Context, p []byte) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	query := resolverTestQuery(t, 1, "queue.resolver.test.")
	for range resolverConcurrency { if err := r.Send(query); err != nil { t.Fatal(err) } }
	for range resolverConcurrency { <-entered }
	for range resolverQueueSize { if err := r.Send(query); err != nil { t.Fatal(err) } }
	if err := r.Send(query); err == nil { t.Fatal("full queue accepted another request") }
	var wg sync.WaitGroup
	for range 3 { wg.Add(1); go func() { defer wg.Done(); r.Close() }() }
	closed := make(chan struct{})
	go func() { wg.Wait(); close(closed) }()
	select { case <-closed: case <-time.After(time.Second): t.Fatal("Close did not cancel exchanges") }
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) { t.Fatalf("Read after Close: %v", err) }
	if err := r.Send(query); !errors.Is(err, io.ErrClosedPipe) { t.Fatalf("Send after Close: %v", err) }
}

func TestRequestResolverShortBufferAndQuestionValidation(t *testing.T) {
	query := resolverTestQuery(t, 1, "short.resolver.test.")
	wrong := resolverTestReply(resolverTestQuery(t, 1, "other.resolver.test."))
	if validateDNSResponse(query, wrong) == nil { t.Fatal("accepted the wrong Question") }
	r := newRequestResolver(&net.UDPAddr{}, func(ctx context.Context, p []byte) ([]byte, error) { return resolverTestReply(p), nil }, nil)
	defer r.Close()
	if err := r.Send(query); err != nil { t.Fatal(err) }
	if n, err := r.Read(make([]byte, 2)); n != 0 || !errors.Is(err, io.ErrShortBuffer) { t.Fatalf("short Read = %d, %v", n, err) }
	if err := r.Send(query); err != nil { t.Fatal(err) }
	buf := make([]byte, maxDNSMessageSize)
	if n, err := r.Read(buf); err != nil || n != len(query) { t.Fatalf("Read after short buffer = %d, %v", n, err) }
}

type partialFrameWriter struct { bytes.Buffer }
func (w *partialFrameWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:min(3, len(p))]) }

func TestDNSFramePartialWritesAndTruncation(t *testing.T) {
	query := resolverTestQuery(t, 5, "frame.resolver.test.")
	var writer partialFrameWriter
	if err := writeDNSFrame(&writer, query); err != nil { t.Fatal(err) }
	packet, err := readDNSFrame(bytes.NewReader(writer.Bytes()))
	if err != nil || !bytes.Equal(packet, query) { t.Fatalf("frame round trip failed: %v", err) }
	if _, err := readDNSFrame(bytes.NewReader(writer.Bytes()[:writer.Len()-1])); !errors.Is(err, io.ErrUnexpectedEOF) { t.Fatalf("half frame: %v", err) }
}

func TestRequestResolverDNSFailuresRemainNonterminal(t *testing.T) {
	for _, tc := range []struct { name string; code dnsmessage.RCode; truncated bool }{{"SERVFAIL", dnsmessage.RCodeServerFailure, false}, {"TC", dnsmessage.RCodeSuccess, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequestResolver(&net.UDPAddr{}, func(ctx context.Context, p []byte) ([]byte, error) {
				var msg dnsmessage.Message
				if err := msg.Unpack(p); err != nil { return nil, err }
				msg.Response = true
				if msg.ID == 1 { msg.RCode = tc.code; msg.Truncated = tc.truncated }
				return msg.Pack()
			}, nil)
			defer r.Close()
			for _, id := range []uint16{1,2} {
				if err := r.Send(resolverTestQuery(t, id, "errors.resolver.test.")); err != nil { t.Fatal(err) }
				buf := make([]byte, maxDNSMessageSize)
				n, err := r.Read(buf)
				if err != nil { t.Fatal(err) }
				var msg dnsmessage.Message
				if err := msg.Unpack(buf[:n]); err != nil { t.Fatal(err) }
				if msg.ID != id || (id == 1 && (msg.RCode != tc.code || msg.Truncated != tc.truncated)) || (id == 2 && (msg.RCode != dnsmessage.RCodeSuccess || msg.Truncated)) { t.Fatalf("DNS failure changed wire or stopped later request: %+v", msg.Header) }
			}
		})
	}
}
