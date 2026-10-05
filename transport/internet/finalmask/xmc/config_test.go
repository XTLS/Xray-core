package xmc

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPaddingScheduleFromConfig(t *testing.T) {
	config := &Config{Padding: []*Padding{
		{LengthMin: 3, LengthMax: 3, Direction: 1},
		{LengthMin: 127, LengthMax: 129, Direction: 2},
		{LengthMin: 16384, LengthMax: 16384, Direction: 1},
	}}
	want := []paddingTurn{
		{direction: paddingClientToServer, minLength: 3, maxLength: 3},
		{direction: paddingServerToClient, minLength: 127, maxLength: 129},
		{direction: paddingClientToServer, minLength: 16384, maxLength: 16384},
	}
	for _, isClient := range []bool{true, false} {
		schedule, err := newPaddingSchedule(config.Padding, isClient)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(schedule, want) {
			t.Fatalf("schedule = %+v, want %+v", schedule, want)
		}
		for i, turn := range schedule {
			prefix := 0
			if i == 0 {
				prefix = 2
			}
			var wire bytes.Buffer
			if err := writePaddingTurn(&wire, turn, prefix); err != nil {
				t.Fatal(err)
			}
			if length := wire.Len() + prefix; length < turn.minLength || length > turn.maxLength {
				t.Fatalf("turn %d length = %d", i, length)
			}
			if err := readPaddingTurn(&wire, turn, prefix); err != nil {
				t.Fatal(err)
			}
			if wire.Len() != 0 {
				t.Fatalf("turn %d left unread bytes", i)
			}
		}
	}
}

func TestValidatePadding(t *testing.T) {
	for name, padding := range map[string][]*Padding{
		"nil turn":       {nil},
		"negative":       {{LengthMin: -1, LengthMax: 3, Direction: 1}},
		"prefix only":    {{LengthMin: 2, LengthMax: 3, Direction: 1}},
		"reversed range": {{LengthMin: 4, LengthMax: 3, Direction: 1}},
		"too long":       {{LengthMin: 3, LengthMax: maxPaddingTurnLength + 1, Direction: 1}},
		"int overflow":   {{LengthMin: 3, LengthMax: 1 << 32, Direction: 1}},
		"empty turn":     {{LengthMin: 3, LengthMax: 3, Direction: 1}, {}},
		"invalid direction": {{LengthMin: 3, LengthMax: 3, Direction: 0}},
	} {
		t.Run(name, func(t *testing.T) {
			config := &Config{Padding: padding}
			if err := config.ValidatePadding(); err == nil {
				t.Fatal("accepted invalid padding")
			}
			for _, isClient := range []bool{true, false} {
				if _, err := newPaddingSchedule(padding, isClient); err == nil {
					t.Fatal("accepted invalid padding at connection setup")
				}
			}
		})
	}
	if err := (&Config{Padding: []*Padding{{LengthMin: 3, LengthMax: maxPaddingTurnLength, Direction: 1}}}).ValidatePadding(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyPaddingUsesPreset(t *testing.T) {
	for _, padding := range [][]*Padding{nil, {}} {
		for _, isClient := range []bool{true, false} {
			schedule, err := newPaddingSchedule(padding, isClient)
			if err != nil {
				t.Fatal(err)
			}
			if len(schedule) != len(paddingSchedule2612) {
				t.Fatalf("schedule length = %d, want %d", len(schedule), len(paddingSchedule2612))
			}
			for i := range schedule {
				// The preset restricts send ranges per connection, but keeps its receive bounds.
				schedule[i].sendMinLength = 0
				schedule[i].sendMaxLength = 0
			}
			if !reflect.DeepEqual(schedule, paddingSchedule2612) {
				t.Fatal("empty padding changed the built-in preset")
			}
		}
	}
}
