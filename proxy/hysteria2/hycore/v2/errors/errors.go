package errors

import (
	"fmt"
	"strconv"
)

// ConfigError is returned when a configuration field is invalid.
type ConfigError struct {
	Field  string
	Reason string
}

func (c ConfigError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", c.Field, c.Reason)
}

// ConnectError is returned when the client fails to connect to the server.
type ConnectError struct {
	Err error
}

func (c ConnectError) Error() string {
	return "connect error: " + c.Err.Error()
}

func (c ConnectError) Unwrap() error {
	return c.Err
}

// AuthError is returned when the client fails to authenticate with the server.
type AuthError struct {
	StatusCode int
}

func (a AuthError) Error() string {
	return "authentication error, HTTP status code: " + strconv.Itoa(a.StatusCode)
}

// DialError is returned when the server rejects the client's dial request.
// This applies to both TCP and UDP.
type DialError struct {
	Message string
}

func (c DialError) Error() string {
	return "dial error: " + c.Message
}

// ClosedError is returned when the client attempts to use a closed connection.
type ClosedError struct {
	Err error // Can be nil
}

func (c ClosedError) Error() string {
	if c.Err == nil {
		return "connection closed"
	} else {
		return "connection closed: " + c.Err.Error()
	}
}

func (c ClosedError) Unwrap() error {
	return c.Err
}

// ProtocolError is returned when the server/client runs into an unexpected
// or malformed request/response/message.
type ProtocolError struct {
	Message string
}

func (p ProtocolError) Error() string {
	return "protocol error: " + p.Message
}
