// Minecraft protocol table.
//
// Every packet id XMC writes or matches is the registration order of the packet
// type in that version's protocol builder, not a value observed in a capture:
// LoginProtocols and ConfigurationProtocols call addPacket in source order and
// both ends dispatch on that index. The table keeps those ids in one place and
// per version, so a new release is a row instead of an edit spread over the
// login, configuration and padding code.
//
// Rows come from two independent sources, and neither is a packet capture:
//
//   - 767..775 (1.21.1 .. 26.1): minecraft-data's per-version protocol.json
//     (data/pc/<version>/protocol.json), which stores the same registration
//     order as a {hex id: packet name} mapping;
//   - 776..777 (26.2, 26.3): the official jars, LoginProtocols and
//     ConfigurationProtocols.
//
// 26.3 is the reason this table exists. It inserts ClientboundPostEffectsPacket
// into the configuration clientbound list at 0x0a, after the keep-alive and
// before store_cookie, so every id behind it moves by one. Every id XMC uses
// stayed put, which is luck rather than design: the list grows by one or two
// packets per release (17 clientbound configuration packets in 1.21.1, 21 in
// 26.3), and an insertion in front of 0x04 would silently break the tunnel.
// Adding a version means adding a row here and an expectation in
// protocol_table_test.go, after diffing the two registration lists.
package xmc

import "fmt"

// handshaking and status packet ids. These have not moved since 1.7 and are
// fixed for every version the table covers.
const (
	handshakeServerboundIntention = 0x00
	statusServerboundRequest      = 0x00
	statusServerboundPing         = 0x01
	statusClientboundResponse     = 0x00
	statusClientboundPong         = 0x01
)

// loginPacketIDs is the login state of one version.
type loginPacketIDs struct {
	// Serverbound (client to server).
	serverboundLoginStart        int
	serverboundKey               int
	serverboundCustomQueryAnswer int
	serverboundLoginAcknowledged int
	serverboundCookieResponse    int

	// Clientbound (server to client).
	clientboundLoginDisconnect  int
	clientboundHello            int
	clientboundLoginFinished    int
	clientboundLoginCompression int
	clientboundCustomQuery      int
	clientboundCookieRequest    int
}

// configurationPacketIDs is the part of the configuration state XMC uses: the
// custom payload pair that carries the tunnel, the keep-alive and ping that
// keep the connection alive like a real one, and the packets that a peer can
// send before the tunnel starts, so that they are recognised instead of being
// mistaken for tunnel data.
type configurationPacketIDs struct {
	// Serverbound (client to server).
	serverboundClientInformation int
	serverboundCookieResponse    int
	serverboundCustomPayload     int
	serverboundKeepAlive         int
	serverboundPong              int

	// Clientbound (server to client).
	clientboundCookieRequest int
	clientboundCustomPayload int
	clientboundDisconnect    int
	clientboundKeepAlive     int
	clientboundPing          int
}

// protocolVersion describes one Minecraft release for the part of the protocol
// the finalmask depends on.
type protocolVersion struct {
	// number is the network protocol version advertised in the handshake and
	// reported by the status response.
	number Varint
	// name is the release name, for example "26.3", as the status response
	// reports it.
	name string

	login         loginPacketIDs
	configuration configurationPacketIDs

	// loginFinishedSessionID is set from 26.2 (776) on: Login Finished appends
	// the connection session id after the game profile, so the client has to
	// read it and the server has to write it.
	loginFinishedSessionID bool
}

// The login and configuration ids that 767..777 share. 26.2 added the session
// id field, and 26.3 inserted a clientbound configuration packet, but none of
// the ids below moved between 1.21.1 and 26.3.
var (
	loginPacketIDs121 = loginPacketIDs{
		serverboundLoginStart:        0x00,
		serverboundKey:               0x01,
		serverboundCustomQueryAnswer: 0x02,
		serverboundLoginAcknowledged: 0x03,
		serverboundCookieResponse:    0x04,

		clientboundLoginDisconnect:  0x00,
		clientboundHello:            0x01,
		clientboundLoginFinished:    0x02,
		clientboundLoginCompression: 0x03,
		clientboundCustomQuery:      0x04,
		clientboundCookieRequest:    0x05,
	}

	configurationPacketIDs121 = configurationPacketIDs{
		serverboundClientInformation: 0x00,
		serverboundCookieResponse:    0x01,
		serverboundCustomPayload:     0x02,
		serverboundKeepAlive:         0x04,
		serverboundPong:              0x05,

		clientboundCookieRequest: 0x00,
		clientboundCustomPayload: 0x01,
		clientboundDisconnect:    0x02,
		clientboundKeepAlive:     0x04,
		clientboundPing:          0x05,
	}
)

// protocolVersions is ordered by protocol number, oldest first. Only releases
// the mod's branches target are listed: the configuration state starts at 1.20.5
// (766), and XMC is only useful from 1.21 on, so 767 is the oldest row.
//
// Releases that share a protocol number share a row and cannot be told apart on
// the wire; the name is the one the mod's branches use (1.21.2 is 768 like
// 1.21.3, 1.21.7 is 772 like 1.21.8, 1.21.10 is 773 like 1.21.9, and 26.1.1 /
// 26.1.2 are 775 like 26.1).
var protocolVersions = []protocolVersion{
	{number: 767, name: "1.21.1", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 768, name: "1.21.3", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 769, name: "1.21.4", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 770, name: "1.21.5", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 771, name: "1.21.6", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 772, name: "1.21.8", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 773, name: "1.21.9", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 774, name: "1.21.11", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 775, name: "26.1", login: loginPacketIDs121, configuration: configurationPacketIDs121},
	{number: 776, name: "26.2", login: loginPacketIDs121, configuration: configurationPacketIDs121, loginFinishedSessionID: true},
	{number: 777, name: "26.3", login: loginPacketIDs121, configuration: configurationPacketIDs121, loginFinishedSessionID: true},
}

// latestProtocolVersion is the newest row. It is what the client advertises
// unless a version is configured, and what the server reports in its status
// response.
var latestProtocolVersion = protocolVersions[len(protocolVersions)-1]

// protocolVersionByNumber finds a row. An unknown number is an error rather
// than a guess: a wrong packet id breaks the login in a way that looks like a
// network failure, so the configuration has to name a version the table knows.
func protocolVersionByNumber(number Varint) (protocolVersion, bool) {
	for _, version := range protocolVersions {
		if version.number == number {
			return version, true
		}
	}
	return protocolVersion{}, false
}

// ValidateProtocolVersion checks a configured network protocol number. Zero is
// valid and selects the newest row. Configuration is validated when it is built,
// so a version that is not in the table fails before a connection is attempted.
func ValidateProtocolVersion(number uint32) error {
	if number == 0 {
		return nil
	}
	if _, ok := protocolVersionByNumber(Varint(number)); !ok {
		return fmt.Errorf("unsupported protocol version %d (supported: %s)", number, protocolVersionRange())
	}
	return nil
}

// protocolVersionRange describes the supported versions for error messages.
func protocolVersionRange() string {
	first, last := protocolVersions[0], protocolVersions[len(protocolVersions)-1]
	return fmt.Sprintf("%d (%s) to %d (%s)", first.number, first.name, last.number, last.name)
}

// loginRejectReason is the Login Disconnect reason a vanilla server sends for a
// protocol version it does not speak. Vanilla splits the message at 1.20.5
// (754): older clients are told to update, newer ones that the server is
// incompatible.
func loginRejectReason(number Varint) string {
	if number < 754 {
		return fmt.Sprintf(`{"translate":"multiplayer.disconnect.outdated_client","with":[%q]}`, latestProtocolVersion.name)
	}
	return fmt.Sprintf(`{"translate":"multiplayer.disconnect.incompatible","with":[%q]}`, latestProtocolVersion.name)
}
