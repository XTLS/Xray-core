// Status probe used to pick the protocol version of the peer.
package xmc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	// protocolProbeTimeout bounds one status round trip. A peer that cannot
	// answer status in this time is not going to answer the login either.
	protocolProbeTimeout = 5 * time.Second
	// protocolProbeTTL keeps detection off the connection path: a real client
	// refreshes a server's status in its server list, not once per join.
	protocolProbeTTL = 10 * time.Minute
	// maxProtocolProbeEntries bounds the cache. A proxy can dial many different
	// destinations, and each entry is three words.
	maxProtocolProbeEntries = 256
)

// statusVersion is the part of the status JSON the probe reads. Vanilla reports
// its own protocol version there, and the login it accepts is that version.
type statusVersion struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int32  `json:"protocol"`
	} `json:"version"`
}

type protocolProbeEntry struct {
	number  Varint
	name    string
	expires time.Time
}

var protocolProbeCache = struct {
	mu      sync.Mutex
	entries map[string]protocolProbeEntry
}{entries: make(map[string]protocolProbeEntry)}

// probeProtocolVersion asks the peer for its status and returns the protocol
// number and release name it reports.
//
// The probe is a second TCP connection to the same destination, exactly what a
// client does when it refreshes a server in its list, so the peer sees nothing
// unusual. It only works when the destination speaks plain Minecraft: for a
// destination behind another transport, set protocol_version instead.
func probeProtocolVersion(dest *xnet.Destination, hostname string, dialer *finalmask.Dialer) (Varint, string, error) {
	if dest == nil {
		return 0, "", fmt.Errorf("status probe: no destination")
	}
	if dialer == nil || dialer.DialTCP == nil {
		return 0, "", fmt.Errorf("status probe: no TCP dialer")
	}

	conn, err := dialer.DialTCP(*dest)
	if err != nil {
		return 0, "", fmt.Errorf("status probe: dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(protocolProbeTimeout)); err != nil {
		return 0, "", fmt.Errorf("status probe: set deadline: %w", err)
	}

	address := String(hostname)
	if address == "" {
		address = String(dest.Address.String())
	}
	var (
		protocolNumber Varint        = latestProtocolVersion.number
		port           UnsignedShort = UnsignedShort(dest.Port.Value())
		nextState      Varint        = 1 // status
	)
	if err := writePacket(conn, handshakeServerboundIntention, &protocolNumber, &address, &port, &nextState); err != nil {
		return 0, "", fmt.Errorf("status probe: write handshake: %w", err)
	}
	if err := writePacket(conn, statusServerboundRequest); err != nil {
		return 0, "", fmt.Errorf("status probe: write status request: %w", err)
	}

	packet, err := readPacket(conn)
	if err != nil {
		return 0, "", fmt.Errorf("status probe: read status response: %w", err)
	}
	if packet.packetID != statusClientboundResponse {
		return 0, "", fmt.Errorf("status probe: unexpected status packet id: 0x%02x", packet.packetID)
	}
	var payload String
	if err := packet.readFields(&payload); err != nil {
		return 0, "", fmt.Errorf("status probe: read status payload: %w", err)
	}
	var status statusVersion
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		return 0, "", fmt.Errorf("status probe: decode status response: %w", err)
	}
	if status.Version.Protocol <= 0 {
		return 0, "", fmt.Errorf("status probe: status response has no version")
	}
	return Varint(status.Version.Protocol), status.Version.Name, nil
}

// detectProtocolVersion returns the peer's protocol version, reusing a recent
// probe for the same destination.
func detectProtocolVersion(dest *xnet.Destination, hostname string, dialer *finalmask.Dialer) (Varint, string, error) {
	key := protocolProbeKey(dest)
	now := time.Now()

	protocolProbeCache.mu.Lock()
	if entry, ok := protocolProbeCache.entries[key]; ok && entry.expires.After(now) {
		protocolProbeCache.mu.Unlock()
		return entry.number, entry.name, nil
	}
	protocolProbeCache.mu.Unlock()

	number, name, err := probeProtocolVersion(dest, hostname, dialer)
	if err != nil {
		return 0, "", err
	}

	protocolProbeCache.mu.Lock()
	if len(protocolProbeCache.entries) >= maxProtocolProbeEntries {
		for cachedKey, entry := range protocolProbeCache.entries {
			if entry.expires.Before(now) {
				delete(protocolProbeCache.entries, cachedKey)
			}
		}
		if len(protocolProbeCache.entries) >= maxProtocolProbeEntries {
			clear(protocolProbeCache.entries)
		}
	}
	protocolProbeCache.entries[key] = protocolProbeEntry{number: number, name: name, expires: now.Add(protocolProbeTTL)}
	protocolProbeCache.mu.Unlock()
	return number, name, nil
}

func protocolProbeKey(dest *xnet.Destination) string {
	return dest.Network.String() + "|" + dest.Address.String() + "|" + strconv.Itoa(int(dest.Port.Value()))
}
