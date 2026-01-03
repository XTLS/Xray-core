package xpool

import (
	"sync"
	"io"

	"github.com/xtls/xray-core/common/buf"
)

type Session interface {
	GetID() uint32
	GetNextSeq() uint32
	GetAck() uint32
	UpdateAck(seq uint32)
}

type BaseSession struct {
	ID      uint32
	NextSeq uint32
	Ack     uint32
	mu      sync.Mutex
}

func (s *BaseSession) GetID() uint32 {
	return s.ID
}

func (s *BaseSession) GetNextSeq() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.NextSeq
	s.NextSeq++
	return seq
}

func (s *BaseSession) GetAck() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Ack
}

func (s *BaseSession) UpdateAck(seq uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > s.Ack {
		s.Ack = seq
	}
}

type ClientSession struct {
	BaseSession
	SendBuffer *SendBuffer
	Pool       *ConnectionPool
	Conn       *GatewayConn
	Writer     *XPoolWriter

	recvChan chan *buf.Buffer
	done     chan struct{}
}

func NewClientSession(sid uint32, pool *ConnectionPool) *ClientSession {
	return &ClientSession{
		BaseSession: BaseSession{ID: sid},
		SendBuffer:  NewSendBuffer(128),
		Pool:        pool,
		recvChan:    make(chan *buf.Buffer, 128),
		done:        make(chan struct{}),
	}
}

func (s *ClientSession) SetConn(conn *GatewayConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Conn = conn
	s.Writer = NewXPoolWriter(conn, s.SendBuffer, s)
}

func (s *ClientSession) WriteMultiBuffer(mb buf.MultiBuffer) error {
	s.mu.Lock()
	writer := s.Writer
	s.mu.Unlock()
	if writer == nil {
		return io.ErrClosedPipe
	}
	return writer.WriteMultiBuffer(mb)
}

func (s *ClientSession) OnPeerAck(ack uint32) {
	s.SendBuffer.OnAck(ack)
}

func (s *ClientSession) OnSegment(seg *Segment) {
	s.OnPeerAck(seg.Ack)

	if seg.Payload != nil {
		s.UpdateAck(seg.Seq + 1)
		select {
		case s.recvChan <- seg.Payload:
		case <-s.done:
			seg.Payload.Release()
		}
	}

	if seg.Type == TypeRST || seg.Type == TypeEOF {
		select {
		case <-s.done:
		default:
			close(s.done)
			close(s.recvChan)
		}
	}
}

func (s *ClientSession) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case b, ok := <-s.recvChan:
		if !ok {
			return nil, io.EOF
		}
		return buf.MultiBuffer{b}, nil
	case <-s.done:
		return nil, io.EOF
	}
}

func (s *ClientSession) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}

	if s.Conn != nil {
		s.Pool.Return(s.ID, s.Conn)
		s.Conn = nil
	}
	s.Pool.UnregisterSession(s.ID)
	s.SendBuffer.Clear()
}

type ServerSession struct {
	BaseSession
	SendBuffer *SendBuffer
	ReplyConn  *GatewayConn
	TargetWriter buf.Writer

	recvChan chan *buf.Buffer
	done     chan struct{}
}

func NewServerSession(sid uint32, replyConn *GatewayConn) *ServerSession {
	return &ServerSession{
		BaseSession: BaseSession{ID: sid},
		SendBuffer:  NewSendBuffer(128),
		ReplyConn:   replyConn,
		recvChan:    make(chan *buf.Buffer, 128),
		done:        make(chan struct{}),
	}
}

func (s *ServerSession) OnPeerAck(ack uint32) {
	s.SendBuffer.OnAck(ack)
}

func (s *ServerSession) OnSegment(seg *Segment) {
	s.OnPeerAck(seg.Ack)

	if seg.Payload != nil {
		s.UpdateAck(seg.Seq + 1)
		select {
		case s.recvChan <- seg.Payload:
		case <-s.done:
			seg.Payload.Release()
		}
	}

	if seg.Type == TypeRST || seg.Type == TypeEOF {
		select {
		case <-s.done:
		default:
			close(s.done)
			close(s.recvChan)
		}
	}
}

func (s *ServerSession) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case b, ok := <-s.recvChan:
		if !ok {
			return nil, io.EOF
		}
		return buf.MultiBuffer{b}, nil
	case <-s.done:
		return nil, io.EOF
	}
}

func (s *ServerSession) WriteMultiBuffer(mb buf.MultiBuffer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ReplyConn == nil {
		return io.ErrClosedPipe
	}

	writer := NewXPoolWriter(s.ReplyConn, s.SendBuffer, s)
	return writer.WriteMultiBuffer(mb)
}

func (s *ServerSession) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.SendBuffer.Clear()
}
