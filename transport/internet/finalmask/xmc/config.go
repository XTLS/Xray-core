package xmc

import (
	"fmt"
	"net"
)

func (c *Config) WrapConnClient(conn net.Conn) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.RsaPublicKey, c.Hostname, c.Paddings)
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
	cc, err := wrapConnServer(conn, profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey, c.Paddings)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

// ValidatePadding checks custom startup turns without selecting a built-in preset.
func (c *Config) ValidatePadding() error {
	_, err := paddingScheduleFromConfig(c.Paddings)
	return err
}

func paddingScheduleFromConfig(paddings []*Padding) ([]paddingTurn, error) {
	if len(paddings) == 0 {
		return nil, nil
	}
	schedule := make([]paddingTurn, len(paddings))
	for i, turn := range paddings {
		if turn == nil || turn.LengthMin < 1 || turn.LengthMax < turn.LengthMin || turn.LengthMax > maxPaddingTurnLength {
			return nil, fmt.Errorf("invalid padding length range at turn %d", i)
		}
		if turn.Delay < 0 {
			return nil, fmt.Errorf("invalid padding delay %d at turn %d (must be non-negative)", turn.Delay, i)
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
			delay:     int(turn.Delay),
		}
	}
	// The first turn includes the two-byte Login Acknowledged packet.
	if err := validatePaddingSchedule(schedule, 2); err != nil {
		return nil, err
	}
	return schedule, nil
}

func newPaddingSchedule(paddings []*Padding, isClient bool) ([]paddingTurn, error) {
	schedule, err := paddingScheduleFromConfig(paddings)
	if err != nil || schedule != nil {
		return schedule, err
	}
	if isClient {
		return newClientPaddingSchedule2612()
	}
	return newServerPaddingSchedule2612()
}
