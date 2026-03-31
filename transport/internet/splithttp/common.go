package splithttp

const (
	ModeAuto      = "auto"
	ModePacketUp  = "packet-up"
	ModeStreamUp  = "stream-up"
	ModeStreamOne = "stream-one"
	ModeMasque    = "masque"

	MASQUEProtocolConnectUDP = "connect-udp"
	HeaderCapsuleProtocol    = "Capsule-Protocol"

	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
	PlacementAuto          = "auto"
)
