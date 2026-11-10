package outbound

import "testing"

func TestMuxConcurrency(t *testing.T) {
	tests := []struct {
		name       string
		configured int32
		want       int32
	}{
		{name: "default", configured: 0, want: 128},
		{name: "disabled", configured: -1, want: -1},
		{name: "single session", configured: 1, want: 1},
		{name: "explicit small value", configured: 8, want: 8},
		{name: "default boundary", configured: 128, want: 128},
		{name: "above default", configured: 256, want: 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := muxConcurrency(tt.configured); got != tt.want {
				t.Errorf("muxConcurrency(%d) = %d, want %d", tt.configured, got, tt.want)
			}
		})
	}
}
