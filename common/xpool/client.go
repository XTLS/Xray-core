package xpool

import (
	"context"
	"io"
	"math/rand"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/transport"
)

type ClientConfig struct {
	Enabled     bool
	MaxIdle     int
	IdleTimeout time.Duration
}

type ClientManager struct {
	Enabled bool
	Pool    *ConnectionPool
}

func NewClientManager(config *ClientConfig, dialer func() (io.ReadWriteCloser, error)) *ClientManager {
	if config == nil || !config.Enabled {
		return &ClientManager{Enabled: false}
	}

	poolConfig := PoolConfig{
		MaxIdle:     config.MaxIdle,
		IdleTimeout: config.IdleTimeout,
	}

	return &ClientManager{
		Enabled: true,
		Pool:    NewConnectionPool(poolConfig, dialer),
	}
}

func (m *ClientManager) Dispatch(ctx context.Context, link *transport.Link) error {
	if !m.Enabled {
		return errors.New("XPool disabled")
	}

	sid := rand.Uint32()
	for sid == 0 {
		sid = rand.Uint32()
	}

	session := NewClientSession(sid, m.Pool)
	defer session.Close()

	m.Pool.RegisterSession(session)

	conn, err := m.Pool.Get(sid)
	if err != nil {
		return err
	}
	session.SetConn(conn)

	requestDone := func() error {
		err := buf.Copy(link.Reader, session)
		session.CloseWrite()
		return err
	}

	responseDone := func() error {
		return buf.Copy(session, link.Writer)
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}
