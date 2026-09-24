/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"context"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

type requestStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetWriteDeadline(time.Time) error
}

type http3Stream interface {
	requestStream
	StreamID() quic.StreamID
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

const maxQueuedCapsules = 128

var errCapsuleLimit = goerrors.New("connect-ip: capsule limit exceeded")

type streamWrite struct {
	Data []byte
	Fin  bool
}

type Conn struct {
	str         requestStream
	h3          http3Stream
	writeNotify chan struct{}
	writeDone   chan error

	assignedAddressUpdates chan []AssignedAddress
	addressRequests        chan *addressRequestCapsule
	availableRouteUpdates  chan []IPRoute

	mu                   sync.Mutex
	queuedWrites         []streamWrite
	peerAddresses        []netip.Prefix
	localRoutes          []IPRoute
	assignedAddresses    []netip.Prefix
	lastAddressRequestID AddressRequestID

	closeChan chan struct{}
	closeErr  error

	closeOnce   sync.Once
	closeResult error

	datagramCapsuleOnce sync.Once
}

func newProxiedConn(str http3Stream) *Conn {
	c := &Conn{
		str:                    str,
		h3:                     str,
		writeNotify:            make(chan struct{}, 1),
		writeDone:              make(chan error, 1),
		assignedAddressUpdates: make(chan []AssignedAddress, maxQueuedCapsules),
		addressRequests:        make(chan *addressRequestCapsule, maxQueuedCapsules),
		availableRouteUpdates:  make(chan []IPRoute, 1),
		closeChan:              make(chan struct{}),
	}
	go func() {
		err := c.readFromStream()
		c.mu.Lock()
		closing := c.closeErr != nil
		if !closing {
			c.closeErr = &CloseError{Remote: true}
			close(c.closeChan)
			if err != nil {
				code := http3.ErrCodeMessageError
				var streamErr *quic.StreamError
				var h3Err *http3.Error
				switch {
				case goerrors.Is(err, errCapsuleLimit):
					code = http3.ErrCodeExcessiveLoad
				case goerrors.As(err, &streamErr) && streamErr.Remote, goerrors.As(err, &h3Err) && h3Err.Remote:
					code = http3.ErrCodeRequestCanceled
				}
				c.str.CancelRead(quic.StreamErrorCode(code))
				c.str.CancelWrite(quic.StreamErrorCode(code))
				close(c.writeNotify)
			} else {
				c.queueFin()
			}
		}
		c.mu.Unlock()
		if err != nil && !closing {
			errors.LogInfoInner(context.Background(), err, "reading capsules failed")
		}
	}()
	go func() {
		err := c.writeToStream()
		if err != nil {
			c.mu.Lock()
			closing := c.closeErr != nil
			if !closing {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
				c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
			} else {
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
			}
			c.mu.Unlock()
			if !closing {
				errors.LogInfoInner(context.Background(), err, "writing capsules failed")
			}
		}
		c.writeDone <- err
		close(c.writeDone)
	}()
	return c
}

func (c *Conn) AdvertiseRoute(routes []IPRoute) error {
	for i, route := range routes {
		err := route.validate()
		if err == nil && i > 0 {
			err = checkRouteOrder(routes[i-1], route)
		}
		if err != nil {
			return fmt.Errorf("connect-ip: invalid route %d: %w", i, err)
		}
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	routes = slices.Clone(routes)
	err := c.queueWrite(streamWrite{Data: (&routeAdvertisementCapsule{IPAddressRanges: routes}).append(nil)})
	if err == nil {
		c.localRoutes = routes
	}
	c.mu.Unlock()
	if err != nil {
		c.Close()
		return err
	}
	return nil
}

func (c *Conn) RequestAddresses(prefixes []netip.Prefix) ([]AddressRequestID, error) {
	if len(prefixes) == 0 {
		return nil, goerrors.New("connect-ip: address request must contain at least one prefix")
	}
	for i, p := range prefixes {
		if !p.IsValid() || p != p.Masked() {
			return nil, fmt.Errorf("connect-ip: invalid requested prefix %d: %s", i, p)
		}
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return nil, err
	}
	ids := make([]AddressRequestID, len(prefixes))
	for i := range ids {
		ids[i] = c.lastAddressRequestID + AddressRequestID(i) + 1
	}
	capsule := &addressRequestCapsule{RequestIDs: ids, Prefixes: prefixes}
	err := c.queueWrite(streamWrite{Data: capsule.append(nil)})
	if err == nil {
		c.lastAddressRequestID = ids[len(ids)-1]
	}
	c.mu.Unlock()
	if err != nil {
		c.Close()
		return nil, err
	}
	return ids, nil
}

func (c *Conn) ReceiveAddressAssignment(ctx context.Context) ([]AssignedAddress, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case assignment := <-c.assignedAddressUpdates:
		return assignment, nil
	case <-c.closeChan:
		select {
		case assignment := <-c.assignedAddressUpdates:
			return assignment, nil
		default:
			return nil, c.closeErr
		}
	}
}

func (c *Conn) ReceiveAddressRequest(ctx context.Context) (*AddressRequest, error) {
	var requested *addressRequestCapsule
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case requested = <-c.addressRequests:
	case <-c.closeChan:
		select {
		case requested = <-c.addressRequests:
		default:
			return nil, c.closeErr
		}
	}
	return newAddressRequest(c, requested), nil
}

func (c *Conn) AssignAddresses(prefixes []netip.Prefix) error {
	capsule := &addressAssignCapsule{}
	if prefixes != nil {
		capsule.AssignedAddresses = make([]AssignedAddress, len(prefixes))
		for i, p := range prefixes {
			capsule.AssignedAddresses[i] = AssignedAddress{IPPrefix: p}
		}
	}
	return c.sendAddressAssignment(capsule, true)
}

func (c *Conn) sendAddressAssignment(capsule *addressAssignCapsule, restrictPeer bool) error {
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	if err := c.queueWrite(streamWrite{Data: capsule.append(nil)}); err != nil {
		c.mu.Unlock()
		c.Close()
		return err
	}

	if !restrictPeer && c.peerAddresses == nil {
		c.mu.Unlock()
		return nil
	}
	var prefixes []netip.Prefix
	if capsule.AssignedAddresses != nil {
		prefixes = make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
	}
	for _, assigned := range capsule.AssignedAddresses {
		if !assigned.Rejected() {
			prefixes = append(prefixes, assigned.IPPrefix)
		}
	}
	c.peerAddresses = prefixes
	c.mu.Unlock()
	return nil
}

func (c *Conn) queueWrite(w streamWrite) error {
	if len(c.queuedWrites) >= maxQueuedCapsules {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
		close(c.writeNotify)
		return goerrors.New("connect-ip: capsule queue full")
	}
	c.queuedWrites = append(c.queuedWrites, w)
	c.notifyWriter()
	return nil
}

func (c *Conn) queueFin() {
	c.str.SetWriteDeadline(time.Now())
	c.queuedWrites = append(c.queuedWrites, streamWrite{Fin: true})
	c.notifyWriter()
}

func (c *Conn) notifyWriter() {
	select {
	case c.writeNotify <- struct{}{}:
	default:
	}
}

func queueLatest[T any](ch chan T, value T) {
	for {
		select {
		case ch <- value:
			return
		case <-ch:
		}
	}
}

func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case routes := <-c.availableRouteUpdates:
		return routes, nil
	}
}

func (c *Conn) readFromStream() error {
	p := http3.NewCapsuleParser(c.str)
	for {
		t, cr, err := p.Next()
		if goerrors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				if !assigned.Rejected() {
					prefixes = append(prefixes, assigned.IPPrefix)
				}
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			select {
			case c.assignedAddressUpdates <- capsule.AssignedAddresses:
			default:
				return fmt.Errorf("%w: address assignment queue full", errCapsuleLimit)
			}
		case capsuleTypeAddressRequest:
			capsule, err := parseAddressRequestCapsule(cr)
			if err != nil {
				return err
			}
			select {
			case c.addressRequests <- capsule:
			default:
				return fmt.Errorf("%w: address request queue full", errCapsuleLimit)
			}
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.availableRouteUpdates, capsule.IPAddressRanges)
		case capsuleTypeDatagram:
			c.datagramCapsuleOnce.Do(func() {
				errors.LogWarning(context.Background(), "connect-ip: dropping IP packets sent in DATAGRAM capsules, only QUIC DATAGRAM frames are supported")
			})
			if err := cr.Discard(); err != nil {
				return err
			}
		default:
			if err := cr.Discard(); err != nil {
				return err
			}
		}
	}
}

func (c *Conn) writeToStream() error {
	for range c.writeNotify {
		for {
			c.mu.Lock()
			if len(c.queuedWrites) == 0 {
				c.mu.Unlock()
				break
			}
			w := c.queuedWrites[0]
			c.queuedWrites[0] = streamWrite{}
			c.queuedWrites = c.queuedWrites[1:]
			c.mu.Unlock()

			if w.Fin {
				return c.str.Close()
			}
			if _, err := c.str.Write(w.Data); err != nil {
				return err
			}
		}
	}
	return c.closeErr
}

func (c *Conn) ReadPacket(b []byte) (int, error) {
	for {
		select {
		case <-c.closeChan:
			return 0, c.closeErr
		default:
		}
		data, err := c.h3.ReceiveDatagram(context.Background())
		if err != nil {
			select {
			case <-c.closeChan:
				return 0, c.closeErr
			default:
				return 0, err
			}
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			errors.LogDebugInner(context.Background(), err, "dropping malformed datagram")
			continue
		}
		if contextID != 0 {
			continue
		}
		packet := data[n:]
		if err := c.handleIncomingProxiedPacket(packet); err != nil {
			errors.LogDebugInner(context.Background(), err, "dropping proxied packet")
			continue
		}
		if len(packet) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, packet), nil
	}
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return goerrors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	c.mu.Unlock()

	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			if (ipVersion(data) == 4 && ipProto == ipProtoICMP) || (ipVersion(data) == 6 && ipProto == ipProtoICMPv6) {
				return true
			}
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	select {
	case <-c.closeChan:
		return nil, c.closeErr
	default:
	}
	data, err := c.composeDatagram(b)
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "dropping proxied packet (", len(b), " bytes) that can't be proxied")
		return nil, nil
	}
	if err := c.h3.SendDatagram(data); err != nil {
		if tooLarge, ok := goerrors.AsType[*quic.DatagramTooLargeError](err); ok {
			icmpPacket, err := composeICMPTooLargePacket(b, int(tooLarge.MaxDatagramPayloadSize)-c.datagramOverhead())
			if err != nil {
				if goerrors.Is(err, ErrMTUTooSmall) {
					return nil, err
				}
				errors.LogDebugInner(context.Background(), err, "failed to compose ICMP Packet Too Big")
			}
			return icmpPacket, nil
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, goerrors.New("connect-ip: empty packet")
	}
	switch v := ipVersion(b); v {
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		hdrLen := int(b[0]&0x0f) << 2
		totalLen := int(binary.BigEndian.Uint16(b[2:4]))
		if hdrLen < ipv4.HeaderLen || hdrLen > totalLen || totalLen > len(b) {
			return nil, fmt.Errorf("connect-ip: malformed IPv4 header: header length %d, total length %d, packet length %d", hdrLen, totalLen, len(b))
		}
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]--
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(b[:hdrLen]))
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := b[7]
		if hopLimit <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		b[7]--
	}
	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return data, nil
}

func (c *Conn) datagramOverhead() int {
	return quicvarint.Len(uint64(c.h3.StreamID()/4)) + len(contextIDZero)
}

func (c *Conn) MaxPacketSize() int {
	select {
	case <-c.closeChan:
		return 0
	default:
	}
	err := c.h3.SendDatagram(make([]byte, 1<<16))
	tooLarge, ok := goerrors.AsType[*quic.DatagramTooLargeError](err)
	if !ok {
		return 0
	}
	return max(0, int(tooLarge.MaxDatagramPayloadSize)-c.datagramOverhead())
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		if c.closeErr == nil {
			c.closeErr = &CloseError{Remote: false}
			close(c.closeChan)
			c.queueFin()
		}
		c.mu.Unlock()
		c.closeResult = <-c.writeDone
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	})
	return c.closeResult
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
