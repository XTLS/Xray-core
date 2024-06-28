package restriction

import (
	"net"
)

type UserMaxIp struct {
	User      string
	IpAddress net.IP
	Time      int64
}
