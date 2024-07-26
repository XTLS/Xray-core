//go:build !windows && !wasm
// +build !windows,!wasm

package domainsocket

import (
	"context"
	gotls "crypto/tls"
	"os"
	"strings"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/reality"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
	goreality "github.com/xtls/reality"
	"golang.org/x/sys/unix"
)

type Listener struct {
	addr          *net.UnixAddr
	ln            net.Listener
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config
	config        *Config
	addConn       internet.ConnHandler
	locker        *fileLocker
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	settings := streamSettings.ProtocolSettings.(*Config)
	addr, err := settings.GetUnixAddr()
	if err != nil {
		return nil, err
	}

	unixListener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, errors.New("failed to listen domain socket").Base(err).AtWarning()
	}

	ln := &Listener{
		addr:    addr,
		ln:      unixListener,
		config:  settings,
		addConn: handler,
	}

	if !settings.Abstract {
		ln.locker = &fileLocker{
			path: settings.Path + ".lock",
		}
		if err := ln.locker.Acquire(); err != nil {
			unixListener.Close()
			return nil, err
		}
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		ln.tlsConfig = config.GetTLSConfig()
	}
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		ln.realityConfig = config.GetREALITYConfig()
	}

	go ln.run()

	return ln, nil
}

func (ln *Listener) Addr() net.Addr {
	return ln.addr
}

func (ln *Listener) Close() error {
	if ln.locker != nil {
		ln.locker.Release()
	}
	return ln.ln.Close()
}

func (ln *Listener) run() {
	for {
		conn, err := ln.ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "failed to accepted raw connections")
			continue
		}
		go func() {
			if ln.tlsConfig != nil {
				conn = tls.Server(conn, ln.tlsConfig)
			} else if ln.realityConfig != nil {
				if conn, err = reality.Server(conn, ln.realityConfig); err != nil {
					errors.LogInfo(context.Background(), err.Error())
					return
				}
			}
			ln.addConn(stat.Connection(conn))
		}()
	}
}

type fileLocker struct {
	path string
	file *os.File
}

func (fl *fileLocker) Acquire() error {
	f, err := os.Create(fl.path)
	if err != nil {
		return err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return errors.New("failed to lock file: ", fl.path).Base(err)
	}
	fl.file = f
	return nil
}

func (fl *fileLocker) Release() {
	if err := unix.Flock(int(fl.file.Fd()), unix.LOCK_UN); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to unlock file: ", fl.path)
	}
	if err := fl.file.Close(); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to close file: ", fl.path)
	}
	if err := os.Remove(fl.path); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to remove file: ", fl.path)
	}
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
