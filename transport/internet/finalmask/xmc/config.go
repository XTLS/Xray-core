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
	cc, err := newClientConn(conn, profiles, c.Password, c.RsaPublicKey, c.Hostname, c.Padding)
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
	cc, err := wrapConnServer(conn, profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey, c.Padding)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

// ValidatePadding checks custom startup turns without selecting a built-in preset.
func (c *Config) ValidatePadding() error {
	_, err := paddingScheduleFromConfig(c.Padding)
	return err
}

func paddingScheduleFromConfig(padding []*Padding) ([]paddingTurn, error) {
	if len(padding) == 0 {
		return nil, nil
	}
	schedule := make([]paddingTurn, len(padding))
	for i, turn := range padding {
		if turn == nil || turn.LengthMin < 1 || turn.LengthMax < turn.LengthMin || turn.LengthMax > maxPaddingTurnLength {
			return nil, fmt.Errorf("invalid padding length range at turn %d", i)
		}
		direction := paddingClientToServer
		if i%2 != 0 {
			direction = paddingServerToClient
		}
		schedule[i] = paddingTurn{
			direction: direction,
			minLength: int(turn.LengthMin),
			maxLength: int(turn.LengthMax),
		}
	}
	// The first turn includes the two-byte Login Acknowledged packet.
	if err := validatePaddingSchedule(schedule, 2); err != nil {
		return nil, err
	}
	return schedule, nil
}

func newPaddingSchedule(padding []*Padding, isClient bool) ([]paddingTurn, error) {
	schedule, err := paddingScheduleFromConfig(padding)
	if err != nil || schedule != nil {
		return schedule, err
	}
	if isClient {
		return newClientPaddingSchedule2612()
	}
	return newServerPaddingSchedule2612()
}
