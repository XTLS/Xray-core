package websocket

import (
	"testing"

	"github.com/gorilla/websocket"
)

// It fails if gorilla moves what a connection looks into, which makes its reader hold a buffer again.
func TestConnectionFields(t *testing.T) {
	if c := NewConnection(new(websocket.Conn), nil, nil, 0); c.br == nil || c.remaining == nil {
		t.Error("unexpected fields in *websocket.Conn")
	}
}
