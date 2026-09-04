package header

type Header interface {
	Size() int
	Serialize(b []byte)
}

type HeaderID int

const (
	DNS HeaderID = iota
	DTLS
	SRTP
	UTP
	WECHAT
	WIREGUARD
)
