package browser_dialer

import (
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
)

// Bound data pulled from HTTP but not yet consumed by Xray. A browser read may
// overshoot this window by one chunk. Acknowledgements at half the window allow
// the browser to continue reading while the next acknowledgement is in flight.
const streamReadWindow = 4 * 1024 * 1024

// DialGetStream opens a download with consumption acknowledgements. DialGet is
// retained for callers that need the raw WebSocket without this local protocol.
func DialGetStream(uri string, headers http.Header, cookies []*http.Cookie) (io.ReadCloser, net.Addr, net.Addr, error) {
	conn, err := dispatchTask(task{
		Method:         "GET",
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: true,
		ReadWindow:     streamReadWindow,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	stream, err := newStreamReader(conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	return stream, conn.RemoteAddr(), conn.LocalAddr(), nil
}

func newStreamReader(conn *websocket.Conn) (*streamReader, error) {
	_, response, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	switch string(response) {
	case "ok-read":
		return &streamReader{conn: conn, acknowledge: true}, nil
	case "ok":
		// A page left open from an older core does not understand read credits.
		return &streamReader{conn: conn}, nil
	default:
		return nil, errors.New(string(response))
	}
}

type streamReader struct {
	conn        *websocket.Conn
	reader      io.Reader
	acknowledge bool
	consumed    int
}

func (s *streamReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if s.reader == nil {
			_, reader, err := s.conn.NextReader()
			if err != nil {
				return 0, err
			}
			s.reader = reader
		}
		n, err := s.reader.Read(b)
		if err == io.EOF {
			s.reader = nil
			err = nil
		}
		if n > 0 {
			if s.acknowledge {
				s.consumed += n
				if s.consumed >= streamReadWindow/2 {
					if ackErr := s.conn.WriteMessage(websocket.TextMessage, []byte(strconv.Itoa(s.consumed))); ackErr != nil {
						return n, ackErr
					}
					s.consumed = 0
				}
			}
			return n, err
		}
		if err != nil {
			return n, err
		}
	}
}

func (s *streamReader) Close() error {
	return s.conn.Close()
}
