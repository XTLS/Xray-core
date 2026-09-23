//go:build !linux || android

package freedom

import (
	"net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

func copyUplink(reader buf.Reader, writer buf.Writer, conn net.Conn, timer signal.ActivityUpdater) error {
	return buf.Copy(reader, writer, buf.UpdateActivity(timer))
}
