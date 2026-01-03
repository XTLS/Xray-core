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
	OnSegment(conn *GatewayConn, seg *Segment)
	OnConnectionClose(conn *GatewayConn)
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
	connLost chan struct{}
}

func NewClientSession(sid uint32, pool *ConnectionPool) *ClientSession {
	return &ClientSession{
		BaseSession: BaseSession{ID: sid},
		SendBuffer:  NewSendBuffer(128),
		Pool:        pool,
		recvChan:    make(chan *buf.Buffer, 128),
		done:        make(chan struct{}),
		connLost:    make(chan struct{}, 1),
	}
}

func (s *ClientSession) SetConn(conn *GatewayConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Conn = conn
	s.Writer = NewXPoolWriter(conn, s.SendBuffer, s)
}

func (s *ClientSession) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i := 0; i < 5; i++ {
		s.mu.Lock()
		writer := s.Writer
		s.mu.Unlock()
		if writer == nil {
			return io.ErrClosedPipe
		}

		err := writer.WriteMultiBuffer(mb)
		if err == nil {
			return nil
		}

		if mErr := s.Migrate(); mErr != nil {
			return err
		}
	}
	return io.ErrClosedPipe
}

func (s *ClientSession) Migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Conn != nil {
		s.Pool.Remove(s.ID, s.Conn)
	}

	conn, err := s.Pool.Get(s.ID)
	if err != nil {
		return err
	}

	s.Conn = conn
	s.Writer = NewXPoolWriter(conn, s.SendBuffer, s)

	unacked := s.SendBuffer.GetUnacked()
	if len(unacked) == 0 {
		return s.Writer.WriteKeepAlive()
	}
	return s.Writer.Resend(unacked)
}

func (s *ClientSession) OnConnectionClose(conn *GatewayConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Conn == conn {
		select {
		case s.connLost <- struct{}{}:
		default:
		}
	}
}

func (s *ClientSession) OnPeerAck(ack uint32) {
	s.SendBuffer.OnAck(ack)
}

func (s *ClientSession) OnSegment(conn *GatewayConn, seg *Segment) {
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
	for {
		select {
		case b, ok := <-s.recvChan:
			if !ok {
				return nil, io.EOF
			}
			return buf.MultiBuffer{b}, nil
		case <-s.done:
			return nil, io.EOF
		case <-s.connLost:
			if err := s.Migrate(); err != nil {
				return nil, err
			}
		}
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

func (s *ServerSession) OnSegment(conn *GatewayConn, seg *Segment) {
	s.mu.Lock()
	if s.ReplyConn != conn {
		s.ReplyConn = conn
	}
	s.mu.Unlock()

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

func (s *ServerSession) OnConnectionClose(conn *GatewayConn) {
}

func (s *ClientSession) CloseWrite() error {
	s.mu.Lock()
	writer := s.Writer
	s.mu.Unlock()
	if writer == nil {
		return io.ErrClosedPipe
	}
	return writer.WriteEOF()
}

func (s *ServerSession) CloseWrite() error {
	s.mu.Lock()
	writer := NewXPoolWriter(s.ReplyConn, s.SendBuffer, s)
	s.mu.Unlock()
	return writer.WriteEOF()
}
