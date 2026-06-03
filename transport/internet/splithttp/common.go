package splithttp

const (
	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
	PlacementAuto          = "auto"
)

const (
	SessionIdFormatUUID         = "uuid"
	SessionIdFormatRandomHex    = "random-hex"
	SessionIdFormatRandomBase62 = "random-base62"
)
