package xmc

import (
	"fmt"
	"math"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// maxPaddingDelayMilliseconds keeps the millisecond value convertible to a
// time.Duration on every platform.
const maxPaddingDelayMilliseconds = int64(math.MaxInt64 / int64(time.Millisecond))

// MaxLegacyPasswordLength is the longest pre-shared password the login can
// carry. The verify token (4 random bytes) and the password travel together in
// one RSA-1024 PKCS#1 v1.5 block, which holds at most 128-11 bytes.
const MaxLegacyPasswordLength = 128 - 11 - 4

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	paddingSchedule, err := c.paddingSchedule(true)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.RsaPublicKey, c.Hostname, paddingSchedule)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	paddingSchedule, err := c.paddingSchedule(false)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := wrapConnServer(conn, profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey, paddingSchedule)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

// ValidatePadding checks the configured startup turns (including their bounds)
// without selecting a built-in preset.
func (c *Config) ValidatePadding() error {
	if c.NoPadding {
		if len(c.Paddings) != 0 {
			return fmt.Errorf("padding is disabled and configured at the same time")
		}
		return nil
	}
	_, err := paddingScheduleFromConfig(c.Paddings)
	return err
}

// paddingSchedule selects the padding turns for one connection. An explicit
// empty configuration disables padding; an absent one keeps the built-in
// preset.
//
// A configured list is the complete schedule, not a replacement for its startup
// part: the built-in preset also carries a Play-state join tail, and that tail
// runs only with the preset. A user who captured their own login decides the
// whole shape, including whether it has a tail.
func (c *Config) paddingSchedule(isClient bool) ([]paddingTurn, error) {
	if c.NoPadding {
		if len(c.Paddings) != 0 {
			return nil, fmt.Errorf("padding is disabled and configured at the same time")
		}
		return nil, nil
	}
	if len(c.Paddings) > 0 {
		return paddingScheduleFromConfig(c.Paddings)
	}
	if isClient {
		return newClientPaddingSchedule2612()
	}
	return newServerPaddingSchedule2612()
}

// paddingScheduleFromConfig builds the complete schedule from a configured list.
// The list replaces the preset entirely, including its Play-state join tail.
func paddingScheduleFromConfig(paddings []*Padding) ([]paddingTurn, error) {
	if len(paddings) == 0 {
		return nil, nil
	}
	if len(paddings) > maxPaddingTurns {
		return nil, fmt.Errorf("too many padding turns: %d (at most %d)", len(paddings), maxPaddingTurns)
	}
	var totalLength, totalDelayMilliseconds int64
	schedule := make([]paddingTurn, len(paddings))
	for i, turn := range paddings {
		if turn == nil || turn.LengthMin < 1 || turn.LengthMax < turn.LengthMin || turn.LengthMax > maxPaddingTurnLength {
			return nil, fmt.Errorf("invalid padding length range at turn %d", i)
		}
		if turn.DelayMin < 0 || turn.DelayMax < turn.DelayMin {
			return nil, fmt.Errorf("invalid padding delay range %d-%d at turn %d (must be non-negative and ordered)", turn.DelayMin, turn.DelayMax, i)
		}
		if turn.DelayMax > maxPaddingDelayMilliseconds {
			return nil, fmt.Errorf("padding delay range %d-%d at turn %d is too large", turn.DelayMin, turn.DelayMax, i)
		}
		totalLength += turn.LengthMax
		if totalLength > maxPaddingTotalLength {
			return nil, fmt.Errorf("padding turns are longer than %d bytes in total", maxPaddingTotalLength)
		}
		totalDelayMilliseconds += turn.DelayMax
		if totalDelayMilliseconds > int64(maxPaddingScheduleDelay/time.Millisecond) {
			return nil, fmt.Errorf("padding pauses are longer than %s in total", maxPaddingScheduleDelay)
		}
		var direction paddingDirection
		switch turn.Direction {
		case 1:
			direction = paddingClientToServer
		case 2:
			direction = paddingServerToClient
		default:
			return nil, fmt.Errorf("invalid padding direction %d at turn %d (1=client-to-server, 2=server-to-client)", turn.Direction, i)
		}
		schedule[i] = paddingTurn{
			direction: direction,
			minLength: int(turn.LengthMin),
			maxLength: int(turn.LengthMax),
			delay: paddingDelayRange{
				min: time.Duration(turn.DelayMin) * time.Millisecond,
				max: time.Duration(turn.DelayMax) * time.Millisecond,
			},
		}
	}
	// The first turn includes the two-byte Login Acknowledged packet.
	if err := validatePaddingSchedule(schedule, 2); err != nil {
		return nil, err
	}
	return schedule, nil
}
