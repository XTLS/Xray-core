package internet

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type result struct {
	err   error
	conn  net.Conn
	index int
}

// raceAttempt makes one connection attempt of a racing dial to the given IP.
type raceAttempt func(ctx context.Context, ip net.IP) (net.Conn, error)

func TcpRaceDial(ctx context.Context, src net.Address, ips []net.IP, port net.Port, sockopt *SocketConfig, domain string) (net.Conn, error) {
	return raceDial(ctx, ips, sockopt, domain, func(ctx context.Context, ip net.IP) (net.Conn, error) {
		return effectiveSystemDialer.Dial(ctx, src, net.Destination{Address: net.IPAddress(ip), Network: net.Network_TCP, Port: port}, sockopt)
	})
}

func raceDial(ctx context.Context, ips []net.IP, sockopt *SocketConfig, domain string, attempt raceAttempt) (net.Conn, error) {
	if len(ips) < 2 {
		panic("at least 2 ips is required to race dial")
	}

	prioritizeIPv6 := sockopt.HappyEyeballs.PrioritizeIpv6
	interleave := sockopt.HappyEyeballs.Interleave
	tryDelayMs := time.Duration(sockopt.HappyEyeballs.TryDelayMs) * time.Millisecond
	maxConcurrentTry := sockopt.HappyEyeballs.MaxConcurrentTry

	ips = sortIPs(ips, prioritizeIPv6, interleave)
	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	resultCh := make(chan *result, len(ips))
	nextTryIndex := 0
	activeNum := uint32(0)
	timer := time.NewTimer(0)
	var winConn net.Conn
	errors.LogDebug(ctx, "happy eyeballs racing dial for ", domain, " with IPs ", ips)
	for {
		select {
		case r := <-resultCh:
			activeNum--
			select {
			case <-ctx.Done():
				cancel()
				timer.Stop()
				if winConn != nil {
					winConn.Close()
				}
				if r.conn != nil {
					r.conn.Close()
				}
				if activeNum == 0 {
					return nil, ctx.Err()
				}
				continue
			default:
				if r.conn != nil {
					cancel()
					timer.Stop()
					if winConn == nil {
						winConn = r.conn
						errors.LogDebug(ctx, "happy eyeballs established connection for ", domain, " with IP ", ips[r.index])
					} else {
						r.conn.Close()
					}
				}
				if winConn != nil && activeNum == 0 {
					return winConn, nil
				}
				if winConn != nil {
					continue
				}
				if nextTryIndex < len(ips) {
					timer.Reset(0)
					continue
				}
				if activeNum == 0 {
					errors.LogDebugInner(ctx, r.err, "happy eyeballs no connection established for ", domain)
					return nil, r.err
				}
				timer.Stop()
				continue
			}

		case <-timer.C:
			if nextTryIndex == len(ips) || activeNum == maxConcurrentTry {
				panic("impossible situation")
			}
			go tryDial(newCtx, attempt, ips[nextTryIndex], nextTryIndex, resultCh)
			activeNum++
			nextTryIndex++
			if nextTryIndex == len(ips) || activeNum == maxConcurrentTry {
				timer.Stop()
			} else {
				timer.Reset(tryDelayMs)
			}
			continue
		}
	}
}

// sortIPs sort IPs according to rfc 8305.
func sortIPs(ips []net.IP, prioritizeIPv6 bool, interleave uint32) []net.IP {
	if len(ips) == 0 {
		return ips
	}
	ip4 := make([]net.IP, 0, len(ips))
	ip6 := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsedIp := net.IPAddress(ip).IP()
		if len(parsedIp) == net.IPv4len {
			ip4 = append(ip4, parsedIp)
		} else {
			ip6 = append(ip6, parsedIp)
		}
	}

	if len(ip4) == 0 || len(ip6) == 0 {
		return ips
	}

	newIPs := make([]net.IP, 0, len(ips))
	consumeIP4 := 0
	consumeIP6 := 0
	consumeTurn := uint32(0)
	ip4turn := true
	if prioritizeIPv6 {
		ip4turn = false
	}
	for {
		if ip4turn {
			newIPs = append(newIPs, ip4[consumeIP4])
			consumeIP4++
			if consumeIP4 == len(ip4) {
				newIPs = append(newIPs, ip6[consumeIP6:]...)
				break
			}
			consumeTurn++
			if consumeTurn == interleave {
				ip4turn = false
				consumeTurn = uint32(0)
			}
		} else {
			newIPs = append(newIPs, ip6[consumeIP6])
			consumeIP6++
			if consumeIP6 == len(ip6) {
				newIPs = append(newIPs, ip4[consumeIP4:]...)
				break
			}
			consumeTurn++
			if consumeTurn == interleave {
				ip4turn = true
				consumeTurn = uint32(0)
			}
		}
	}

	return newIPs
}

func tryDial(ctx context.Context, attempt raceAttempt, ip net.IP, index int, resultCh chan<- *result) {
	conn, err := attempt(ctx, ip)
	select {
	case <-ctx.Done():
		if conn != nil {
			conn.Close()
		}
		resultCh <- &result{err: ctx.Err(), index: index}
		return
	default:
		if err != nil {
			resultCh <- &result{err: err, index: index}
			return
		}
		resultCh <- &result{conn: conn, index: index}
		return
	}
}

// DialTCPWithHandshake dials a TCP connection to dest through FinalMask (if any)
// and the system dialer, and then passes it to handshake, which wraps it with
// TLS or REALITY and returns the connection ready for the transport. handshake
// is nil when the transport uses neither TLS nor REALITY.
//
// When happyEyeballs.successDefinition is tlsHandshakeComplete and dest is a
// domain resolving to several IPs, each IP is tried through the TCP dial,
// FinalMask and handshake, and the first connection that completes the
// handshake wins, as recommended in section 6.1 of
// https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/.
// handshake is called once per attempt and must build TLS or REALITY from dest
// rather than from the address of the connection it is given.
func DialTCPWithHandshake(ctx context.Context, dest net.Destination, streamSettings *MemoryStreamConfig, handshake func(context.Context, net.Conn) (net.Conn, error)) (net.Conn, error) {
	dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
		if streamSettings.FinalMask != nil {
			return streamSettings.FinalMask.DialTCP(ctx, dest)
		}
		return DialSystem(ctx, dest, streamSettings.SocketSettings)
	}

	if handshake == nil {
		// Without TLS or REALITY, DialSystem races TCP connections as usual.
		conn, err := dialTCP(ctx, dest)
		if err != nil {
			return nil, errors.New("failed to dial to dest").Base(err)
		}
		return conn, nil
	}

	if ips, port := handshakeRaceIPs(ctx, dest, streamSettings.SocketSettings); ips != nil {
		return raceDial(ctx, ips, streamSettings.SocketSettings, dest.Address.String(), func(ctx context.Context, ip net.IP) (net.Conn, error) {
			return handshakeTryDial(ctx, net.TCPDestination(net.IPAddress(ip), port), dialTCP, handshake)
		})
	}

	conn, err := dialTCP(ctx, dest)
	if err != nil {
		return nil, errors.New("failed to dial to dest").Base(err)
	}
	return handshake(ctx, conn)
}

// handshakeRaceIPs returns the IPs to race TLS handshakes over, or nil if dest
// should be dialed as usual. It mirrors the conditions under which DialSystem
// races TCP connections.
func handshakeRaceIPs(ctx context.Context, dest net.Destination, sockopt *SocketConfig) ([]net.IP, net.Port) {
	if sockopt == nil || sockopt.HappyEyeballs == nil || sockopt.HappyEyeballs.SuccessDefinition != HappyEyeballsConfig_TlsHandshakeComplete ||
		sockopt.HappyEyeballs.TryDelayMs == 0 || sockopt.HappyEyeballs.MaxConcurrentTry == 0 ||
		len(sockopt.DialerProxy) > 0 || dest.Network != net.Network_TCP || !sockopt.DomainStrategy.HasStrategy() {
		return nil, 0
	}
	if newDest, err := checkAddressPortStrategy(ctx, dest, sockopt); err == nil && newDest != nil {
		dest = *newDest
	}
	if !dest.Address.Family().IsDomain() {
		return nil, 0
	}
	var src net.Address
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		src = outbounds[len(outbounds)-1].Gateway
	}
	ips, err := LookupForIP(dest.Address.Domain(), sockopt.DomainStrategy, src)
	if err != nil || len(ips) < 2 {
		// DialSystem resolves dest again and handles the error or the single IP.
		return nil, 0
	}
	return ips, dest.Port
}

// handshakeTryDial makes one attempt of a TLS handshake race to dest, which
// holds the IP being tried.
func handshakeTryDial(ctx context.Context, dest net.Destination, dialTCP func(context.Context, net.Destination) (net.Conn, error), handshake func(context.Context, net.Conn) (net.Conn, error)) (net.Conn, error) {
	rawConn, err := dialTCP(ctx, dest)
	if err != nil {
		err = errors.New("failed to dial TCP to ", dest.Address).Base(err)
		errors.LogDebugInner(ctx, err, "happy eyeballs attempt failed")
		return nil, err
	}

	// An attempt that loses the race is stopped by closing its connection,
	// which ends whatever stage it is in, including FinalMask wrappers, which
	// take no context.
	stop := context.AfterFunc(ctx, func() { rawConn.Close() })
	conn, err := handshake(ctx, rawConn)
	if err == nil {
		// Some transports leave the handshake to the first write; the race has
		// to finish it here.
		if c, ok := conn.(interface{ HandshakeContext(context.Context) error }); ok {
			err = c.HandshakeContext(ctx)
		}
	}
	if !stop() {
		// Another attempt has won or the dial was canceled, and the connection
		// has been closed.
		if err == nil {
			err = errors.New("completed handshake with ", dest.Address, " after the race ended").Base(ctx.Err())
		} else {
			err = errors.New("handshake with ", dest.Address, " did not complete before the race ended").Base(ctx.Err())
		}
		errors.LogDebugInner(ctx, err, "happy eyeballs attempt failed")
		return nil, err
	}
	if err != nil {
		// The connection is left to handshake as it would be without the race,
		// e.g. REALITY keeps using it after a failed verification.
		err = errors.New("failed to complete handshake with ", dest.Address).Base(err)
		errors.LogDebugInner(ctx, err, "happy eyeballs attempt failed")
		return nil, err
	}
	return conn, nil
}
