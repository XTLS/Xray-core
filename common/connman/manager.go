package connman

import (
	"context"
	"fmt"
	"github.com/xtaci/smux"
	"github.com/xtls/xray-core/common/connman/connection"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"sync"
)

const SMUX_CONCURRENT_CONNECTIONS = 8

type SetupConnection func(connection internet.Connection, header *protocol.RequestHeader) (internet.Connection, error)

type SmuxManager struct {
	ctr              uint8
	access           sync.RWMutex
	muxConnectionMap map[net.Destination][SMUX_CONCURRENT_CONNECTIONS]*connection.SmuxConnection
}

func NewSmuxManager() *SmuxManager {
	return &SmuxManager{
		muxConnectionMap: make(map[net.Destination][SMUX_CONCURRENT_CONNECTIONS]*connection.SmuxConnection),
	}
}

// Dial new connection and upgrade the connection to Smux connection
func (sm *SmuxManager) dialSmuxConnection(ctx context.Context, dest net.Destination, dialer internet.Dialer, header *protocol.RequestHeader, connSetup SetupConnection) (*connection.SmuxConnection, error) {
	// Dial new connection if there isn't an existing connection
	baseConn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}

	// Setup connection
	conn, err := connSetup(baseConn, header)
	if err != nil {
		_ = baseConn.Close()
		return nil, err
	}

	// Establish Smux session
	smuxSession, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Create SmuxConnection instance and save in server list
	smuxConnection := &connection.SmuxConnection{
		Conn:        conn,
		SmuxSession: smuxSession,
	}

	return smuxConnection, nil
}

func (sm *SmuxManager) setConnection(dest net.Destination, smuxConnection *connection.SmuxConnection, ctr uint8) {
	if connArray, ok := sm.muxConnectionMap[dest]; ok {
		if connArray[ctr] != nil {
			_ = connArray[ctr].Close()
		}
		connArray[ctr] = smuxConnection
		sm.muxConnectionMap[dest] = connArray
	} else {
		connArray = [SMUX_CONCURRENT_CONNECTIONS]*connection.SmuxConnection{}
		connArray[ctr] = smuxConnection
		sm.muxConnectionMap[dest] = connArray
	}
}

func (sm *SmuxManager) removeConnection(dest net.Destination, ctr uint8) {
	if connArray, ok := sm.muxConnectionMap[dest]; ok {
		conn := connArray[ctr]
		if conn != nil {
			_ = conn.Close()
		}
		connArray[ctr] = nil
		sm.muxConnectionMap[dest] = connArray
	}
}

func (sm *SmuxManager) GetConnection(ctx context.Context, dest net.Destination, dialer internet.Dialer, header *protocol.RequestHeader, connSetup SetupConnection) (internet.Connection, error) {
	sm.access.Lock()
	defer sm.access.Unlock()

	// Check if the destination is already in the connection map
	if _, ok := sm.muxConnectionMap[dest]; !ok {
		sm.muxConnectionMap[dest] = [SMUX_CONCURRENT_CONNECTIONS]*connection.SmuxConnection{}
	}

	fmt.Println(dest)
	fmt.Println(sm.muxConnectionMap)

	// Return the existing connection if possible
	index := sm.ctr % SMUX_CONCURRENT_CONNECTIONS
	if smuxConn := sm.muxConnectionMap[dest][index]; smuxConn != nil {
		if smuxStream, err := smuxConn.SmuxSession.OpenStream(); err == nil {
			return smuxStream, nil
		}
	}

	// Remove if stream fails to open
	sm.removeConnection(dest, sm.ctr%SMUX_CONCURRENT_CONNECTIONS)

	// Dial new Smux Connection
	smuxConnection, err := sm.dialSmuxConnection(ctx, dest, dialer, header, connSetup)
	if err != nil {
		return nil, err
	}

	// Open new stream from the Smux connection session
	smuxStream, err := smuxConnection.SmuxSession.OpenStream()
	if err != nil {
		_ = smuxConnection.Close()
		return nil, err
	}

	// Save connection
	sm.setConnection(dest, smuxConnection, sm.ctr%SMUX_CONCURRENT_CONNECTIONS)
	sm.ctr += 1

	return smuxStream, nil
}
