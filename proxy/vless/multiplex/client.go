package multiplex

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type ClientManager struct {
	Picker WorkerPicker
}

// Client owns the VLESS stream pools. A nil configuration disables multiplexing.
type Client struct {
	config *Config
	tcp    *ClientManager
	udp    *ClientManager
}

func NewClient(ctx context.Context, config *Config, network string, open func(context.Context, func(context.Context, *transport.Link) error) error) *Client {
	c := &Client{config: config}
	manager := func(concurrency int32) *ClientManager {
		return &ClientManager{Picker: &IncrementalWorkerPicker{Factory: &clientFactory{
			ctx: ctx, open: open,
			strategy: ClientStrategy{MaxConcurrency: uint32(concurrency), MaxConnection: 1024},
		}}}
	}
	concurrency := config.Concurrency
	if concurrency == 0 {
		concurrency = 8
	}
	if concurrency > 0 {
		if network == "xdrive" {
			concurrency = max(concurrency, 128)
		}
		c.tcp = manager(concurrency)
	}
	if config.XudpConcurrency > 0 {
		c.udp = manager(config.XudpConcurrency)
	}
	return c
}

func (c *Client) Close() {
	if c.tcp != nil {
		common.Close(c.tcp.Picker)
	}
	if c.udp != nil {
		common.Close(c.udp.Picker)
	}
}

func (c *Client) Dispatch(ctx context.Context, link *transport.Link) (bool, error) {
	if c == nil {
		return false, nil
	}
	manager := c.tcp
	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	if target.Network == net.Network_UDP {
		if target.Port == 443 {
			switch c.config.XudpProxyUDP443 {
			case "reject", "":
				return true, errors.New("XUDP rejected UDP/443 traffic")
			case "skip":
				return false, nil
			}
		}
		if c.config.XudpConcurrency < 0 {
			return false, nil
		}
		if c.udp != nil {
			manager = c.udp
		}
	}
	if manager == nil {
		return false, nil
	}
	return true, manager.Dispatch(ctx, link, true)
}

type clientFactory struct {
	ctx      context.Context
	open     func(context.Context, func(context.Context, *transport.Link) error) error
	strategy ClientStrategy
}

func (f *clientFactory) Create() (*ClientWorker, error) {
	type result struct {
		worker *ClientWorker
		err    error
	}
	ready := make(chan result, 1)
	ctx := session.ContextWithOutbounds(f.ctx, []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527),
	}})
	go func() {
		err := f.open(ctx, func(ctx context.Context, link *transport.Link) error {
			worker, err := NewClientWorker(*link, f.strategy)
			if err != nil {
				return err
			}
			defer worker.Close()
			ready <- result{worker: worker}
			select {
			case <-ctx.Done():
			case <-worker.WaitClosed():
			}
			return nil
		})
		if err != nil {
			ready <- result{err: err}
		}
	}()
	r := <-ready
	return r.worker, r.err
}

// Dispatch waits for the child when the caller owns its link lifetime.
func (m *ClientManager) Dispatch(ctx context.Context, link *transport.Link, wait bool) error {
	for i := 0; i < 16; i++ {
		worker, err := m.Picker.PickAvailable(ctx)
		if err != nil {
			return err
		}
		if worker.Dispatch(ctx, link, wait) {
			return nil
		}
	}

	return errors.New("unable to find an available mux client")
}

type WorkerPicker interface {
	PickAvailable(context.Context) (*ClientWorker, error)
}

type IncrementalWorkerPicker struct {
	Factory ClientWorkerFactory

	access       sync.Mutex
	workers      []*ClientWorker
	cleanupTimer *time.Timer
	closed       bool
	pending      *workerCreation
}

type workerCreation struct {
	done   chan struct{}
	worker *ClientWorker
	err    error
}

func (p *IncrementalWorkerPicker) cleanupFunc() {
	p.access.Lock()
	defer p.access.Unlock()

	if p.closed {
		return
	}
	p.cleanup()
	if len(p.workers) == 0 {
		p.cleanupTimer = nil
		return
	}
	p.cleanupTimer.Reset(30 * time.Second)
}

func (p *IncrementalWorkerPicker) cleanup() {
	var activeWorkers []*ClientWorker
	for _, w := range p.workers {
		if !w.Closed() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	p.workers = activeWorkers
}

func (p *IncrementalWorkerPicker) findAvailable() int {
	for idx, w := range p.workers {
		if !w.IsFull() {
			return idx
		}
	}

	return -1
}

func (p *IncrementalWorkerPicker) PickAvailable(ctx context.Context) (*ClientWorker, error) {
	p.access.Lock()

	if p.closed {
		p.access.Unlock()
		return nil, io.ErrClosedPipe
	}
	idx := p.findAvailable()
	if idx >= 0 {
		n := len(p.workers)
		if n > 1 && idx != n-1 {
			p.workers[n-1], p.workers[idx] = p.workers[idx], p.workers[n-1]
		}
		worker := p.workers[idx]
		p.access.Unlock()
		return worker, nil
	}

	p.cleanup()

	if p.pending == nil {
		p.pending = &workerCreation{done: make(chan struct{})}
		go p.create(p.pending)
	}
	pending := p.pending
	p.access.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-pending.done:
		return pending.worker, pending.err
	}
}

func (p *IncrementalWorkerPicker) create(pending *workerCreation) {
	worker, err := p.Factory.Create()
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		if worker != nil {
			worker.Close()
		}
		return
	}
	pending.worker, pending.err = worker, err
	if err == nil {
		p.workers = append(p.workers, worker)
	}
	if p.cleanupTimer == nil {
		p.cleanupTimer = time.AfterFunc(30*time.Second, p.cleanupFunc)
	}
	p.pending = nil
	close(pending.done)
	p.access.Unlock()
}

func (p *IncrementalWorkerPicker) Close() error {
	if p == nil {
		return nil
	}
	p.access.Lock()
	p.closed = true
	if p.pending != nil {
		p.pending.err = io.ErrClosedPipe
		close(p.pending.done)
		p.pending = nil
	}
	workers := p.workers
	p.workers = nil
	if p.cleanupTimer != nil {
		p.cleanupTimer.Stop()
		p.cleanupTimer = nil
	}
	p.access.Unlock()

	for _, worker := range workers {
		common.Must(worker.Close())
	}
	return nil
}

type ClientWorkerFactory interface {
	Create() (*ClientWorker, error)
}

type ClientStrategy struct {
	MaxConcurrency uint32
	MaxConnection  uint32
}

type ClientWorker struct {
	sessionManager *SessionManager
	link           transport.Link
	done           *done.Instance
	timer          *time.Ticker
	strategy       ClientStrategy
}

// NewClientWorker creates a new mux.Client.
func NewClientWorker(stream transport.Link, s ClientStrategy) (*ClientWorker, error) {
	if _, ok := stream.Writer.(*buf.BufferedWriter); !ok {
		writer := buf.NewBufferedWriter(stream.Writer)
		writer.SetBuffered(false)
		stream.Writer = writer
	}
	c := &ClientWorker{
		sessionManager: NewSessionManager(),
		link:           stream,
		done:           done.New(),
		timer:          time.NewTicker(time.Second * 16),
		strategy:       s,
	}

	go c.fetchOutput()
	go c.monitor()

	return c, nil
}

func (m *ClientWorker) TotalConnections() uint32 {
	return uint32(m.sessionManager.Count())
}

func (m *ClientWorker) ActiveConnections() uint32 {
	return uint32(m.sessionManager.Size())
}

// Closed returns true if this Client is closed.
func (m *ClientWorker) Closed() bool {
	return m.done.Done()
}

func (m *ClientWorker) WaitClosed() <-chan struct{} {
	return m.done.Wait()
}

func (m *ClientWorker) Close() error {
	return m.done.Close()
}

func (m *ClientWorker) monitor() {
	defer m.timer.Stop()

	for {
		checkSize := m.sessionManager.Size()
		checkCount := m.sessionManager.Count()
		select {
		case <-m.done.Wait():
			m.sessionManager.Close()
			common.Interrupt(m.link.Writer)
			common.Interrupt(m.link.Reader)
			return
		case <-m.timer.C:
			if m.sessionManager.CloseIfNoSessionAndIdle(checkSize, checkCount) {
				common.Must(m.done.Close())
			}
		}
	}
}

func writeFirstPayload(reader buf.Reader, writer *Writer) error {
	err := buf.CopyOnceTimeout(reader, writer, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return writer.WriteMultiBuffer(buf.MultiBuffer{})
	}

	if err != nil {
		return err
	}

	return nil
}

func fetchInput(ctx context.Context, s *Session, output buf.Writer) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	transferType := protocol.TransferTypeStream
	if ob.Target.Network == net.Network_UDP {
		transferType = protocol.TransferTypePacket
	}
	s.transferType = transferType
	var inbound *session.Inbound
	if session.IsReverseMuxFromContext(ctx) {
		inbound = session.InboundFromContext(ctx)
	}
	writer := NewWriter(s.ID, ob.Target, output, transferType, xudp.GetGlobalID(ctx), inbound)
	defer s.Close(false)
	defer writer.Close()

	errors.LogInfo(ctx, "dispatching request to ", ob.Target)
	if err := writeFirstPayload(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to write first payload")
		writer.hasError = true
		return
	}

	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to fetch all input")
		writer.hasError = true
		return
	}
}

func (m *ClientWorker) IsClosing() bool {
	sm := m.sessionManager
	if m.strategy.MaxConnection > 0 && sm.Count() >= int(m.strategy.MaxConnection) {
		return true
	}
	return false
}

// IsFull returns true if this ClientWorker is unable to accept more connections.
// it might be because it is closing, or the number of connections has reached the limit.
func (m *ClientWorker) IsFull() bool {
	if m.IsClosing() || m.Closed() {
		return true
	}

	sm := m.sessionManager
	if m.strategy.MaxConcurrency > 0 && sm.Size() >= int(m.strategy.MaxConcurrency) {
		return true
	}
	return false
}

func (m *ClientWorker) Dispatch(ctx context.Context, link *transport.Link, wait bool) bool {
	if ctx.Err() != nil || m.IsFull() {
		return false
	}
	s := m.sessionManager.Allocate(&m.strategy, link.Reader, link.Writer)
	if s == nil {
		return false
	}
	go fetchInput(ctx, s, m.link.Writer)
	_, pipeReader := link.Reader.(*pipe.Reader)
	if wait || !pipeReader {
		select {
		case <-ctx.Done():
			s.Close(false)
		case <-s.done.Wait():
		}
	}
	return true
}

func (m *ClientWorker) handleStatueKeepAlive(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusNew(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) handleStatusKeep(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if !meta.Option.Has(OptionData) {
		return nil
	}

	s, found := m.sessionManager.Get(meta.SessionID)
	if !found {
		// Notify remote peer to close this session.
		closingWriter := NewResponseWriter(meta.SessionID, m.link.Writer, protocol.TransferTypeStream)
		closingWriter.Close()

		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}

	rr := s.NewReader(reader, &meta.Target)
	err := buf.Copy(rr, s.output)
	if err != nil && buf.IsWriteError(err) {
		errors.LogInfoInner(context.Background(), err, "failed to write to downstream. closing session ", s.ID)
		s.Close(false)
		return buf.Copy(rr, buf.Discard)
	}

	return err
}

func (m *ClientWorker) handleStatusEnd(meta *FrameMetadata, reader *buf.BufferedReader) error {
	if s, found := m.sessionManager.Get(meta.SessionID); found {
		s.Close(false)
	}
	if meta.Option.Has(OptionData) {
		return buf.Copy(NewStreamReader(reader), buf.Discard)
	}
	return nil
}

func (m *ClientWorker) fetchOutput() {
	defer func() {
		common.Must(m.done.Close())
	}()

	reader := &buf.BufferedReader{Reader: m.link.Reader}

	var meta FrameMetadata
	for {
		err := meta.Unmarshal(reader, false)
		if err != nil {
			if errors.Cause(err) != io.EOF {
				errors.LogInfoInner(context.Background(), err, "failed to read metadata")
			}
			break
		}

		switch meta.SessionStatus {
		case SessionStatusKeepAlive:
			err = m.handleStatueKeepAlive(&meta, reader)
		case SessionStatusEnd:
			err = m.handleStatusEnd(&meta, reader)
		case SessionStatusNew:
			err = m.handleStatusNew(&meta, reader)
		case SessionStatusKeep:
			err = m.handleStatusKeep(&meta, reader)
		default:
			status := meta.SessionStatus
			errors.LogError(context.Background(), "unknown status: ", status)
			return
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to process data")
			return
		}
	}
}
