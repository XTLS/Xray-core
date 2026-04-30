package socks

import "io"

// WriteSocks5AuthFailureForTest exposes writeSocks5AuthFailure to external
// test packages. It is only compiled into test binaries.
func WriteSocks5AuthFailureForTest(w io.Writer, behavior AuthFailureBehavior, version, auth byte) error {
	return writeSocks5AuthFailure(w, behavior, version, auth)
}
