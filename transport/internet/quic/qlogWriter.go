package quic

import "github.com/quic-go/quic-go"

type QlogWriter struct {
	connID quic.ConnectionID
}

func (w *QlogWriter) Write(b []byte) (int, error) {
	// to much log, only turn on when debug Quic

	// if len(b) > 1 { // skip line separator "0a" in qlog
	// 	log.Record(&log.GeneralMessage{
	// 		Severity: log.Severity_Debug,
	// 		Content:  fmt.Sprintf("[%x] %s", w.connID, b),
	// 	})
	// }
	return len(b), nil
}

func (w *QlogWriter) Close() error {
	// Noop
	return nil
}
