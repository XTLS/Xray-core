package freedom

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net/packetaddr"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport/internet"
)

// HandleUnixSocketRedirect handles redirect to Unix socket
func (h *Handler) handleUnixSocketRedirect(ctx context.Context, dest net.Destination, reader io.Reader, writer io.Writer) error {
	// Parse Unix socket target
	unixConfig, err := ParseUnixSocketTarget(h.config.Redirect)
	if err != nil {
		return errors.New("failed to parse unix socket target: ", err)
	}

	// Dial Unix socket
	conn, err := DialUnixSocket(unixConfig)
	if err != nil {
		return errors.New("failed to connect to unix socket: ", err)
	}
	defer conn.Close()

	// Set deadline if needed
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// Create error channel for goroutines
	errChan := make(chan error, 2)

	// Copy from reader to socket
	go func() {
		_, err := io.Copy(conn, reader)
		errChan <- err
	}()

	// Copy from socket to writer
	go func() {
		_, err := io.Copy(writer, conn)
		errChan <- err
	}()

	// Wait for first error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			return errors.New("unix socket redirect failed: ", err)
		}
	}

	return nil
}

// IsUnixSocketRedirect checks if redirect target is a Unix socket
func (h *Handler) IsUnixSocketRedirect() bool {
	if h.config.Redirect == "" {
		return false
	}
	return IsUnixSocketTarget(h.config.Redirect)
}