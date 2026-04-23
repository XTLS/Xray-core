// Package champa implements a transport that tunnels TCP-like streams
// through an AMP (Accelerated Mobile Pages) cache via domain fronting.
// The protocol stack is HTTP-via-AMP-cache → Noise NK → KCP → smux,
// based on David Fifield's Champa <https://www.bamsoftware.com/software/champa/>.
package champa

const protocolName = "champa"
