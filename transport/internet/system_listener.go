package internet

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing/common/control"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

var effectiveListener = DefaultListener{}

type DefaultListener struct {
	controllers []control.Func
}

type combinedListener struct {
	net.Listener
	locker *FileLocker // for unix domain socket
}

func (cl *combinedListener) Close() error {
	if cl.locker != nil {
		cl.locker.Release()
		cl.locker = nil
	}
	return cl.Listener.Close()
}

func getControlFunc(ctx context.Context, sockopt *SocketConfig, controllers []control.Func) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			for _, controller := range controllers {
				if err := controller(network, address, c); err != nil {
					newError("failed to apply external controller").Base(err).WriteToLog(session.ExportIDToError(ctx))
				}
			}

			if sockopt != nil {
				if err := applyInboundSocketOptions(network, fd, sockopt); err != nil {
					newError("failed to apply socket options to incoming connection").Base(err).WriteToLog(session.ExportIDToError(ctx))
				}
			}

			setReusePort(fd)
		})
	}
}

func (dl *DefaultListener) Listen(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (l net.Listener, err error) {
	var lc net.ListenConfig
	var network, address string
	// callback is called after the Listen function returns
	callback := func(l net.Listener, err error) (net.Listener, error) {
		return l, err
	}

	switch addr := addr.(type) {
	case *net.TCPAddr:
		network = addr.Network()
		address = addr.String()
		lc.Control = getControlFunc(ctx, sockopt, dl.controllers)
		if sockopt != nil {
			if sockopt.TcpKeepAliveInterval != 0 || sockopt.TcpKeepAliveIdle != 0 {
				lc.KeepAlive = time.Duration(-1)
			}
			if sockopt.TcpMptcp {
				lc.SetMultipathTCP(true)
			}
		}
	case *net.UnixAddr:
		lc.Control = nil
		network = addr.Network()
		address = addr.Name

		if (runtime.GOOS == "linux" || runtime.GOOS == "android") && address[0] == '@' {
			// linux abstract unix domain socket is lockfree
			if len(address) > 1 && address[1] == '@' {
				// but may need padding to work with haproxy
				fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
				copy(fullAddr, address[1:])
				address = string(fullAddr)
			}
		} else {
			// split permission from address
			var filePerm *os.FileMode
			if s := strings.Split(address, ","); len(s) == 2 {
				address = s[0]
				perm, perr := strconv.ParseUint(s[1], 8, 32)
				if perr != nil {
					return nil, newError("failed to parse permission: " + s[1]).Base(perr)
				}

				mode := os.FileMode(perm)
				filePerm = &mode
			}
			// normal unix domain socket needs lock
			locker := &FileLocker{
				path: address + ".lock",
			}
			if err := locker.Acquire(); err != nil {
				return nil, err
			}

			// set callback to combine listener and set permission
			callback = func(l net.Listener, err error) (net.Listener, error) {
				if err != nil {
					locker.Release()
					return l, err
				}
				l = &combinedListener{Listener: l, locker: locker}
				if filePerm == nil {
					return l, nil
				}
				err = os.Chmod(address, *filePerm)
				if err != nil {
					l.Close()
					return nil, newError("failed to set permission for " + address).Base(err)
				}
				return l, nil
			}
		}
	}

	l, err = lc.Listen(ctx, network, address)
	l, err = callback(l, err)
	if sockopt != nil && sockopt.AcceptProxyProtocol {
		policyFunc := func(upstream net.Addr) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil }
		l = &proxyproto.Listener{Listener: l, Policy: policyFunc}
	}
	return l, err
}

func (dl *DefaultListener) ListenPacket(ctx context.Context, addr net.Addr, sockopt *SocketConfig) (net.PacketConn, error) {
	var lc net.ListenConfig

	lc.Control = getControlFunc(ctx, sockopt, dl.controllers)

	return lc.ListenPacket(ctx, addr.Network(), addr.String())
}

// RegisterListenerController adds a controller to the effective system listener.
// The controller can be used to operate on file descriptors before they are put into use.
//
// xray:api:beta
func RegisterListenerController(controller control.Func) error {
	if controller == nil {
		return newError("nil listener controller")
	}

	effectiveListener.controllers = append(effectiveListener.controllers, controller)
	return nil
}
