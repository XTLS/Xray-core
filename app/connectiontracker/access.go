package connectiontracker

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/transport"
)

type accessRecordKey struct{}

// AccessRecord captures accepted-request access-log state until the request
// finishes and a final log line can be emitted.
type AccessRecord struct {
	ID uint32

	Msg *clog.AccessMessage

	RequestBytes  int64
	ResponseBytes int64

	LastActivity int64

	cancel   context.CancelFunc
	finished atomic.Bool
}

// ContextWithAccessRecord stores r in ctx for deferred access-log handling.
func ContextWithAccessRecord(ctx context.Context, r *AccessRecord) context.Context {
	return context.WithValue(ctx, accessRecordKey{}, r)
}

// AccessRecordFromContext returns the access record stored in ctx, if any.
func AccessRecordFromContext(ctx context.Context) *AccessRecord {
	r, _ := ctx.Value(accessRecordKey{}).(*AccessRecord)
	return r
}

func (r *AccessRecord) touch() {
	atomic.StoreInt64(&r.LastActivity, time.Now().UnixNano())
}

func (r *AccessRecord) addRequestBytes(n int64) {
	if n <= 0 {
		return
	}
	atomic.AddInt64(&r.RequestBytes, n)
	r.touch()
}

func (r *AccessRecord) addResponseBytes(n int64) {
	if n <= 0 {
		return
	}
	atomic.AddInt64(&r.ResponseBytes, n)
	r.touch()
}

func cloneAccessMessage(msg *clog.AccessMessage) *clog.AccessMessage {
	if msg == nil {
		return nil
	}
	cloned := *msg
	return &cloned
}

func (m *Manager) completeAccessRecord(r *AccessRecord, reason error) {
	if r == nil || !r.finished.CompareAndSwap(false, true) {
		return
	}
	msg := cloneAccessMessage(r.Msg)
	if msg == nil {
		return
	}
	if reason != nil {
		msg.Reason = reason
	}
	msg.RequestBytes = atomic.LoadInt64(&r.RequestBytes)
	msg.ResponseBytes = atomic.LoadInt64(&r.ResponseBytes)
	clog.Record(msg)
}

// NewAccessRecord creates a new access record for an accepted request.
func (m *Manager) NewAccessRecord(msg *clog.AccessMessage, cancel context.CancelFunc) *AccessRecord {
	if msg == nil {
		return nil
	}
	record := &AccessRecord{
		ID:     atomic.AddUint32(&m.globalNext, 1),
		Msg:    msg,
		cancel: cancel,
	}
	record.touch()
	return record
}

// FinishAccessRecord emits the final access log for r, including payload
// totals accumulated during the request lifetime.
func (m *Manager) FinishAccessRecord(r *AccessRecord) {
	m.completeAccessRecord(r, nil)
}

// AbortAccessRecord emits the final access log for r with an abort reason and
// cancels the tracked context if one was supplied.
func (m *Manager) AbortAccessRecord(r *AccessRecord, reason error) {
	if r != nil && r.cancel != nil {
		r.cancel()
	}
	m.completeAccessRecord(r, reason)
}

// TrackAccessLink stores a deferred access record in ctx and wraps link so
// payload bytes can be accounted for at the body reader/writer boundary.
func (m *Manager) TrackAccessLink(ctx context.Context, msg *clog.AccessMessage, link *transport.Link, cancel context.CancelFunc) (context.Context, *transport.Link, *AccessRecord) {
	record := m.NewAccessRecord(msg, cancel)
	if record == nil || link == nil {
		return ctx, link, record
	}
	ctx = ContextWithAccessRecord(ctx, record)
	link = WrapAccessLink(link, record)
	return ctx, link, record
}

// WrapAccessLink wraps link so payload bytes are attributed to record.
func WrapAccessLink(link *transport.Link, record *AccessRecord) *transport.Link {
	if link == nil || record == nil {
		return link
	}
	if link.Reader != nil {
		link.Reader = &TrackedAccessReader{Reader: link.Reader, record: record}
	}
	if link.Writer != nil {
		link.Writer = &TrackedAccessWriter{Writer: link.Writer, record: record}
	}
	return link
}

// TrackedAccessReader counts request payload bytes read by an accepted request.
type TrackedAccessReader struct {
	buf.Reader
	record *AccessRecord
}

func (r *TrackedAccessReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if n := int64(mb.Len()); n > 0 && r.record != nil {
		r.record.addRequestBytes(n)
	}
	return mb, err
}

func (r *TrackedAccessReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	if reader, ok := r.Reader.(buf.TimeoutReader); ok {
		mb, err := reader.ReadMultiBufferTimeout(timeout)
		if n := int64(mb.Len()); n > 0 && r.record != nil {
			r.record.addRequestBytes(n)
		}
		return mb, err
	}
	return r.ReadMultiBuffer()
}

func (r *TrackedAccessReader) Interrupt() {
	common.Interrupt(r.Reader)
}

func (r *TrackedAccessReader) Close() error {
	return common.Close(r.Reader)
}

// TrackedAccessWriter counts response payload bytes written by an accepted
// request.
type TrackedAccessWriter struct {
	buf.Writer
	record *AccessRecord
}

func (w *TrackedAccessWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int64(mb.Len())
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil && n > 0 && w.record != nil {
		w.record.addResponseBytes(n)
	}
	return err
}

func (w *TrackedAccessWriter) Close() error {
	return common.Close(w.Writer)
}
