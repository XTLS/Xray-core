package xmc

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientRejectsLongLegacyPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	profiles := []loginProfile{{Username: "TestUser"}}
	publicKey := []byte{0x01}

	if _, err := newClientConn(client, profiles, strings.Repeat("p", MaxLegacyPasswordLength), publicKey, "localhost", nil, nil); err != nil {
		t.Fatalf("password of %d bytes was rejected: %v", MaxLegacyPasswordLength, err)
	}
	if _, err := newClientConn(client, profiles, strings.Repeat("p", MaxLegacyPasswordLength+1), publicKey, "localhost", nil, nil); err == nil {
		t.Fatal("expected the long password to be rejected")
	}
}

func TestPaddingScheduleCaps(t *testing.T) {
	turn := func(length, delay int64) *Padding {
		return &Padding{LengthMin: length, LengthMax: length, Direction: 1, DelayMin: delay, DelayMax: delay}
	}

	t.Run("too many turns", func(t *testing.T) {
		paddings := make([]*Padding, maxPaddingTurns+1)
		for i := range paddings {
			paddings[i] = turn(3, 0)
		}
		if _, err := paddingScheduleFromConfig(paddings); err == nil {
			t.Fatal("expected a turn count error")
		}
	})

	t.Run("too many bytes", func(t *testing.T) {
		paddings := make([]*Padding, maxPaddingTotalLength/maxPaddingTurnLength+1)
		for i := range paddings {
			paddings[i] = turn(maxPaddingTurnLength, 0)
		}
		if _, err := paddingScheduleFromConfig(paddings); err == nil {
			t.Fatal("expected a total length error")
		}
	})

	t.Run("too much delay", func(t *testing.T) {
		tooLong := int64(maxPaddingScheduleDelay/time.Millisecond) + 1
		if _, err := paddingScheduleFromConfig([]*Padding{turn(3, tooLong)}); err == nil {
			t.Fatal("expected a total delay error")
		}
		if _, err := paddingScheduleFromConfig([]*Padding{turn(3, int64(maxPaddingScheduleDelay/time.Millisecond))}); err != nil {
			t.Fatalf("delay at the limit was rejected: %v", err)
		}
	})
}

func TestPaddingDisabled(t *testing.T) {
	config := &Config{NoPadding: true}
	if err := config.ValidatePadding(); err != nil {
		t.Fatalf("disabled padding failed validation: %v", err)
	}
	schedule, err := config.paddingSchedule(true)
	if err != nil {
		t.Fatal(err)
	}
	if schedule != nil {
		t.Fatalf("disabled padding returned %d turns", len(schedule))
	}
	config.Paddings = []*Padding{{LengthMin: 3, LengthMax: 3, Direction: 1}}
	if err := config.ValidatePadding(); err == nil {
		t.Fatal("expected a conflict between disabled and configured padding")
	}
	if _, err := config.paddingSchedule(false); err == nil {
		t.Fatal("expected a conflict between disabled and configured padding")
	}

	preset := &Config{}
	if schedule, err := preset.paddingSchedule(true); err != nil || len(schedule) == 0 {
		t.Fatalf("client preset = %d turns, err %v", len(schedule), err)
	}
	if schedule, err := preset.paddingSchedule(false); err != nil || len(schedule) == 0 {
		t.Fatalf("server preset = %d turns, err %v", len(schedule), err)
	}
}

// TestConfiguredPaddingsReplaceTheWholePreset pins the documented policy: a
// configured list is the complete schedule, so the preset's Play-state join tail
// does not run behind it on either end.
func TestConfiguredPaddingsReplaceTheWholePreset(t *testing.T) {
	config := &Config{Paddings: []*Padding{
		{LengthMin: 44, LengthMax: 44, Direction: 1},
		{LengthMin: 64, LengthMax: 64, Direction: 2},
	}}
	for _, isClient := range []bool{true, false} {
		schedule, err := config.paddingSchedule(isClient)
		if err != nil {
			t.Fatal(err)
		}
		if len(schedule) != len(config.Paddings) {
			t.Fatalf("isClient=%v: schedule has %d turns, want the %d configured turns", isClient, len(schedule), len(config.Paddings))
		}
		for i, turn := range schedule {
			want := paddingClientToServer
			if config.Paddings[i].Direction == 2 {
				want = paddingServerToClient
			}
			if turn.direction != want || turn.minLength != int(config.Paddings[i].LengthMin) {
				t.Fatalf("isClient=%v: turn %d = %+v, want the configured %+v", isClient, i, turn, config.Paddings[i])
			}
		}
	}

	// The preset, in contrast, carries the join tail behind the startup turns.
	preset, err := (&Config{}).paddingSchedule(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(preset) <= len(startupPaddingSchedule2612) {
		t.Fatalf("preset has %d turns, want the startup turns plus the join tail", len(preset))
	}
}

func TestCloseCancelsPaddingPause(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	conn, err := newClientConn(client, []loginProfile{{Username: "TestUser"}}, "password", []byte{0x01}, "localhost", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if err := conn.paddingPause(time.Hour); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("closing the connection did not cancel the pause")
	}
}
