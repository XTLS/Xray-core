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
	SessionIdFormatUuid      = "uuid"
	SessionIdFormatHex       = "hex"
	SessionIdFormatBase64Url = "base64url"
	SessionIdFormatBase32    = "base32"
	SessionIdFormatBase58    = "base58"
	SessionIdFormatAlnum     = "alnum"
)
