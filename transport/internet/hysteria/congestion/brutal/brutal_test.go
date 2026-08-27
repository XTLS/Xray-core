package brutal

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// feedAckRate drives a single sampling slot with the given number of acked and
// lost packets and returns the resulting ackRate.
func feedAckRate(disableLossCompensation bool, ackCount, lossCount int) float64 {
	b := NewBrutalSender(1000000, disableLossCompensation)
	acked := make([]congestion.AckedPacketInfo, ackCount)
	lost := make([]congestion.LostPacketInfo, lossCount)
	// eventTime lands in a fixed slot; a single event carries enough samples.
	b.OnCongestionEventEx(0, monotime.Time(5*time.Second), acked, lost)
	return b.ackRate
}

func TestBrutalLossCompensation(t *testing.T) {
	tests := []struct {
		name      string
		ack, loss int
		want      float64 // expected ackRate when compensation is ENABLED
	}{
		{"no loss", 100, 0, 1.0},
		{"20% loss", 80, 20, 0.8},
		{"50% loss clamps to floor", 50, 50, minAckRate}, // 0.5 clamped up to 0.8
		{"few samples stays 1", 10, 5, 1.0},              // below minSampleCount
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compensation enabled (default behavior): ackRate reacts to loss.
			if got := feedAckRate(false, tt.ack, tt.loss); got != tt.want {
				t.Errorf("compensation on: ackRate = %v, want %v", got, tt.want)
			}
			// Compensation disabled: ackRate must stay pinned at 1 regardless.
			if got := feedAckRate(true, tt.ack, tt.loss); got != 1.0 {
				t.Errorf("compensation off: ackRate = %v, want 1.0", got)
			}
		})
	}
}
