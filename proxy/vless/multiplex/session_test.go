package multiplex

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
)

func TestSessionManagerAdd(t *testing.T) {
	m := NewSessionManager()

	s := allocateTestSession(m, &ClientStrategy{}, nil, nil, protocol.TransferTypeStream)
	if s.ID != 1 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 1 {
		t.Error("size: ", m.Size())
	}

	s = allocateTestSession(m, &ClientStrategy{}, nil, nil, protocol.TransferTypeStream)
	if s.ID != 2 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 2 {
		t.Error("size: ", m.Size())
	}

	s = &Session{
		ID: 4,
	}
	m.Add(s)
	if s.ID != 4 {
		t.Error("id: ", s.ID)
	}
	if m.Size() != 3 {
		t.Error("size: ", m.Size())
	}
}

func TestSessionManagerClose(t *testing.T) {
	m := NewSessionManager()
	s := allocateTestSession(m, &ClientStrategy{}, nil, nil, protocol.TransferTypeStream)

	if m.CloseIfNoSessionAndIdle(m.Size(), m.Count()) {
		t.Error("able to close")
	}
	s.Close()
	if !m.CloseIfNoSessionAndIdle(m.Size(), m.Count()) {
		t.Error("not able to close")
	}
}

func allocateTestSession(m *SessionManager, strategy *ClientStrategy, input buf.Reader, output buf.Writer, transfer protocol.TransferType) *Session {
	m.Lock()
	defer m.Unlock()
	return m.allocate(strategy, input, output, transfer)
}
