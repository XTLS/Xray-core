package utils

import (
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// ResolveSocketPath applies platform-specific transformations to a Unix
// socket path, matching the listen-side behaviour in
// transport/internet/system_listener.go.
//
// For abstract sockets (prefix @) on Linux/Android:
//   - single @ — used as-is (lock-free abstract socket)
//   - double @@ — stripped to single @ and padded to
//     syscall.RawSockaddrUnix{}.Path length (HAProxy compat)
//
// Filesystem paths and abstract sockets on other platforms are returned
// unchanged.
func ResolveSocketPath(path string) string {
	if len(path) == 0 || path[0] != '@' {
		return path
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		return path
	}
	if len(path) > 1 && path[1] == '@' {
		fullAddr := make([]byte, len(syscall.RawSockaddrUnix{}.Path))
		copy(fullAddr, path[1:])
		return string(fullAddr)
	}
	return path
}

// SplitHTTPUnixURL splits a target into an HTTP URL and an optional Unix
// socket path. For regular http(s) URLs the input is returned unchanged
// with an empty socketPath. For Unix sockets the format is:
//
//	/path/to/socket.sock[:/http/path]
//	@abstract[:/http/path]
//	@@padded[:/http/path]
//
// The :/ separator delimits the socket path from the HTTP request path.
// If omitted, "/" is used.
func SplitHTTPUnixURL(raw string) (httpURL, socketPath string) {
	if len(raw) == 0 || (!filepath.IsAbs(raw) && raw[0] != '@') {
		return raw, ""
	}
	if idx := strings.Index(raw, ":/"); idx >= 0 {
		return "http://localhost" + raw[idx+1:], raw[:idx]
	}
	return "http://localhost/", raw
}
