package quic

import (
	"fmt"

	"github.com/xtls/xray-core/common/log"
)

type QlogWriter struct {
	connID []byte
}

func (w *QlogWriter) Write(b []byte) (int, error) {
	if len(b) > 1 { // skip line separator "0a" in qlog
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("[%x] %s", w.connID, b),
		})
	}
	return len(b), nil
}

func (w *QlogWriter) Close() error {
	// Noop
	return nil
}
