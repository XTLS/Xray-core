# TLS sniffing deadline

To wait for application data before routing an IP TCP/443 connection, set this
inbound's `sniffing` configuration:

```json
{
  "enabled": true,
  "destOverride": ["http", "tls"],
  "routeOnly": true,
  "tlsSniffingTimeout": 3000
}
```

`tlsSniffingTimeout` accepts 1-60000 milliseconds and requires content sniffing
with `tls` in `destOverride`. Zero retains the ordinary timeout/fallback policy.
One deadline covers the first byte and classification; fragments do not reset it.
SOCKS success still precedes waiting for data.

Timeout, cancellation, incomplete EOF, an incomplete 64 KiB prefix, or exhaustion
of 1024 pending slots per dispatcher closes the connection without outbound
dispatch. A read retains its slot until its inbound owner closes it and it exits.
Complete unknown/no-SNI input keeps existing routing rules and exclusions.
Usable FakeDNS mappings, domain destinations, other ports, and UDP use the
ordinary sniffing policy. Server-first protocols on enabled IP TCP/443, oversized
ClientHellos, and data arriving after the deadline will fail. ECH and QUIC are
outside this option's scope.

The TLS parser fix also applies with the option off: fragmented ClientHellos can
continue within the existing 200 ms budget instead of hitting the two-read exit.
