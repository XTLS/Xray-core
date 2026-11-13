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

func (c *Config) wrapClientAuth() (*yggdrasilAuth, error) {
	if c.Yggdrasil == nil {
		return nil, nil
	}
	return yggdrasilAuthFor(
		c.Yggdrasil.Api,
		c.Yggdrasil.Username,
		c.Yggdrasil.Password,
		c.Yggdrasil.Player,
	)
}

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	auth, err := c.wrapClientAuth()
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	if auth == nil && len(profiles) == 0 {
		return nil, fmt.Errorf("minecraft finalmask: empty profiles")
	}

	// In Yggdrasil mode the server key is authenticated by the session hash
	// handshake, so the client accepts the key sent in Encryption Request
	// instead of pinning a configured one.
	var rsaPublicKey []byte
	if auth == nil {
		rsaPublicKey = c.RsaPublicKey
	}

	cc, err := newClientConn(conn, profiles, c.Password, rsaPublicKey, c.Hostname, c.Paddings, auth)
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

	var verifier *yggdrasilVerifier
	if c.Yggdrasil != nil {
		verifier, err = newYggdrasilVerifier(c.Yggdrasil.Api)
		if err != nil {
			return nil, fmt.Errorf("minecraft finalmask: %w", err)
		}
	}
	if verifier == nil && len(profiles) == 0 {
		return nil, fmt.Errorf("minecraft finalmask: empty profiles")
	}

	cc, err := wrapConnServer(conn, profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey, c.Paddings, verifier)
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
		if turn.DelayMin < 0 || turn.DelayMax < turn.DelayMin {
			return nil, fmt.Errorf("invalid padding delay range %d-%d at turn %d (must be non-negative and ordered)", turn.DelayMin, turn.DelayMax, i)
		}
		if turn.DelayMax > maxPaddingDelayMilliseconds {
			return nil, fmt.Errorf("padding delay range %d-%d at turn %d is too large", turn.DelayMin, turn.DelayMax, i)
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
