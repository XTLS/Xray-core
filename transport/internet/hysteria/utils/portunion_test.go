package utils

import (
	"reflect"
	"slices"
	"testing"
)

func TestParsePortUnion(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want PortUnion
	}{
		{
			name: "empty",
			s:    "",
			want: nil,
		},
		{
			name: "all 1",
			s:    "all",
			want: PortUnion{{0, 65535}},
		},
		{
			name: "all 2",
			s:    "*",
			want: PortUnion{{0, 65535}},
		},
		{
			name: "single port",
			s:    "1234",
			want: PortUnion{{1234, 1234}},
		},
		{
			name: "multiple ports (unsorted)",
			s:    "5678,1234,9012",
			want: PortUnion{{1234, 1234}, {5678, 5678}, {9012, 9012}},
		},
		{
			name: "one range",
			s:    "1234-1240",
			want: PortUnion{{1234, 1240}},
		},
		{
			name: "one range (reversed)",
			s:    "1240-1234",
			want: PortUnion{{1234, 1240}},
		},
		{
			name: "multiple ports and ranges (reversed, unsorted, overlapping)",
			s:    "5678,1200-1236,9100-9012,1234-1240",
			want: PortUnion{{1200, 1240}, {5678, 5678}, {9012, 9100}},
		},
		{
			name: "multiple ports and ranges with 65535 (reversed, unsorted, overlapping)",
			s:    "5678,1200-1236,65531-65535,65532-65534,9100-9012,1234-1240",
			want: PortUnion{{1200, 1240}, {5678, 5678}, {9012, 9100}, {65531, 65535}},
		},
		{
			name: "multiple ports and ranges with 65535 (reversed, unsorted, overlapping) 2",
			s:    "5678,1200-1236,65532-65535,65531-65534,9100-9012,1234-1240",
			want: PortUnion{{1200, 1240}, {5678, 5678}, {9012, 9100}, {65531, 65535}},
		},
		{
			name: "invalid 1",
			s:    "1234-",
			want: nil,
		},
		{
			name: "invalid 2",
			s:    "1234-ggez",
			want: nil,
		},
		{
			name: "invalid 3",
			s:    "233,",
			want: nil,
		},
		{
			name: "invalid 4",
			s:    "1234-1240-1250",
			want: nil,
		},
		{
			name: "invalid 5",
			s:    "-,,",
			want: nil,
		},
		{
			name: "invalid 6",
			s:    "http",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePortUnion(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePortUnion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortUnion_Ports(t *testing.T) {
	tests := []struct {
		name string
		pu   PortUnion
		want []uint16
	}{
		{
			name: "single port",
			pu:   PortUnion{{1234, 1234}},
			want: []uint16{1234},
		},
		{
			name: "multiple ports",
			pu:   PortUnion{{1234, 1236}},
			want: []uint16{1234, 1235, 1236},
		},
		{
			name: "multiple ports and ranges",
			pu:   PortUnion{{1234, 1236}, {5678, 5680}, {9000, 9002}},
			want: []uint16{1234, 1235, 1236, 5678, 5679, 5680, 9000, 9001, 9002},
		},
		{
			name: "single port 65535",
			pu:   PortUnion{{65535, 65535}},
			want: []uint16{65535},
		},
		{
			name: "port range with 65535",
			pu:   PortUnion{{65530, 65535}},
			want: []uint16{65530, 65531, 65532, 65533, 65534, 65535},
		},
		{
			name: "multiple ports and ranges with 65535",
			pu:   PortUnion{{65530, 65535}, {1234, 1236}},
			want: []uint16{65530, 65531, 65532, 65533, 65534, 65535, 1234, 1235, 1236},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pu.Ports(); !slices.Equal(got, tt.want) {
				t.Errorf("PortUnion.Ports() = %v, want %v", got, tt.want)
			}
		})
	}
}
