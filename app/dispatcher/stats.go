package dispatcher

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type multiCounter struct {
	counters []stats.Counter
}

func (m *multiCounter) Value() int64 {
	if len(m.counters) > 0 {
		return m.counters[0].Value()
	}
	return 0
}

func (m *multiCounter) Set(v int64) int64 {
	var prev int64
	for _, c := range m.counters {
		prev = c.Set(v)
	}
	return prev
}

func (m *multiCounter) Add(v int64) int64 {
	var r int64
	for _, c := range m.counters {
		r = c.Add(v)
	}
	return r
}

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
