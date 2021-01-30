package connman

import (
	"context"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"sync"
)

type SetupConnection func(connection internet.Connection, header *protocol.RequestHeader) (internet.Connection, error)

type SmuxManager struct {
	access           sync.RWMutex
	muxConnectionMap map[net.Destination]internet.Connection
}

func NewSmuxManager() *SmuxManager {
	return &SmuxManager{
		muxConnectionMap: make(map[net.Destination]internet.Connection),
	}
}

func (sm *SmuxManager) dialConnection(ctx context.Context, dest net.Destination, dialer internet.Dialer) (internet.Connection, error) {
	if conn, err := dialer.Dial(ctx, dest); err != nil {
		return nil, err
	} else {
		return conn, nil
	}
}

func (sm *SmuxManager) setConnection(dest net.Destination, connection internet.Connection) {
	if conn, ok := sm.muxConnectionMap[dest]; ok {
		_ = conn.Close()
	}
	sm.muxConnectionMap[dest] = connection
}

func (sm *SmuxManager) GetConnection(ctx context.Context, dest net.Destination, dialer internet.Dialer, header *protocol.RequestHeader, connSetup SetupConnection) (internet.Connection, error) {
	sm.access.Lock()
	defer sm.access.Unlock()

	if conn, ok := sm.muxConnectionMap[dest]; ok {
		return conn, nil
	}

	conn, err := sm.dialConnection(ctx, dest, dialer)
	if err != nil {
		return nil, err
	}

	conn, err = connSetup(conn, header)
	if err != nil {
		return nil, err
	}

	sm.setConnection(dest, conn)
	return conn, nil
}

func (sm *SmuxManager) RemoveConnection(dest net.Destination) {
	sm.access.Lock()
	defer sm.access.Unlock()

	if conn, ok := sm.muxConnectionMap[dest]; ok {
		_ = conn.Close()
		delete(sm.muxConnectionMap, dest)
	}
}
