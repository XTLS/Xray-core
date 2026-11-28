package xmc

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// DefaultDataChannel carries the tunnel byte stream and DefaultPaddingChannel
	// carries the startup padding. Both ends must agree on the pair, and the
	// defaults are public constants, so a deployment that wants a different
	// fingerprint renames them on both sides.
	DefaultDataChannel    = "xmc:data"
	DefaultPaddingChannel = "xmc:pad"

	// MaxChannelIDLength bounds a channel id. The id travels in every custom
	// payload header, so a long one is pure overhead; vanilla itself has no
	// limit beyond the string encoding.
	MaxChannelIDLength = 128
)

var (
	channelNamespacePattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)
	channelPathPattern      = regexp.MustCompile(`^[a-z0-9/._-]+$`)
)

// ChannelIDs returns the two configured custom payload channels, filling in the
// defaults for empty fields. Both are validated because both ends have to
// register them as Minecraft resource locations.
func (c *Config) ChannelIDs() (dataChannel, paddingChannel string, err error) {
	dataChannel = c.DataChannel
	if dataChannel == "" {
		dataChannel = DefaultDataChannel
	}
	paddingChannel = c.PaddingChannel
	if paddingChannel == "" {
		paddingChannel = DefaultPaddingChannel
	}
	if err = ValidateChannelID(dataChannel); err != nil {
		return "", "", fmt.Errorf("data channel: %w", err)
	}
	if err = ValidateChannelID(paddingChannel); err != nil {
		return "", "", fmt.Errorf("padding channel: %w", err)
	}
	if dataChannel == paddingChannel {
		return "", "", fmt.Errorf("data and padding channels must differ: %q", dataChannel)
	}
	return dataChannel, paddingChannel, nil
}

// ValidateChannelID checks one custom payload id as a Minecraft resource
// location: namespace:path with vanilla's character rules. The "minecraft"
// namespace is reserved, because every vanilla custom payload id lives there and
// reusing one would make the tunnel collide with the game.
func ValidateChannelID(id string) error {
	if id == "" {
		return fmt.Errorf("empty channel id")
	}
	if len(id) > MaxChannelIDLength {
		return fmt.Errorf("channel id %q is longer than %d bytes", id, MaxChannelIDLength)
	}
	namespace, path, found := strings.Cut(id, ":")
	if !found || strings.Contains(path, ":") {
		return fmt.Errorf("channel id %q is not namespace:path", id)
	}
	if namespace == "" || namespace == ".." || !channelNamespacePattern.MatchString(namespace) {
		return fmt.Errorf("channel id %q has an invalid namespace: only a-z, 0-9, '_', '.' and '-' are allowed, and it cannot be \"..\"", id)
	}
	if namespace == "minecraft" {
		return fmt.Errorf("channel id %q uses the vanilla \"minecraft\" namespace; vanilla custom payload ids belong to the game", id)
	}
	if path == "" || !channelPathPattern.MatchString(path) {
		return fmt.Errorf("channel id %q has an invalid path: only a-z, 0-9, '_', '-', '.' and '/' are allowed", id)
	}
	return nil
}
