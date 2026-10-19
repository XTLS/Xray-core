# Waiting for TLS before routing

An IP-based TCP connection can arrive before its application data. With ordinary
sniffing, an expired sniffing timeout falls back to routing the original IP. A
ClientHello sent later cannot change that route.

For an inbound whose IP TCP/443 connections must wait for content classification,
enable `tlsSniffingTimeout` in its `sniffing` settings:

```json
{
  "enabled": true,
  "destOverride": ["http", "tls"],
  "routeOnly": true,
  "tlsSniffingTimeout": 3000
}
```

The value is milliseconds, from 1 to 60000. Zero (the default) retains the ordinary
sniffing timeout policy. Nonzero values require `enabled: true`, `metadataOnly:
false`, and `tls` in `destOverride` (`https` and `ssl` are JSON aliases).

For IP TCP/443 destinations, Xray waits before dispatching to any outbound. The
single deadline covers both waiting for the first byte and completing sniffing;
receiving another fragment does not restart it. ClientHello fragmentation across
reads and TLS records is supported. Classification finishes as soon as possible,
without adding a fixed delay to a complete ClientHello.

An expired deadline, cancellation, EOF before classification, an incomplete
64 KiB prefix, or exhaustion of the 1024 pending-sniff slots closes the connection
without dispatching it. The slot limit is per dispatcher, shared by enabled
inbounds. A pending read retains its slot until the inbound owner closes it and
the read returns. SOCKS success still precedes waiting for application data.

A recognized domain uses existing routing rules and sniffing exclusions. Complete
unrecognized input (including TLS without SNI) retains existing routing behavior;
this setting does not send unknown domains to a different outbound. A FakeDNS
mapping that the sniffing configuration allows to override the destination uses
the ordinary policy, since its domain is already known. Other ports, UDP, and
destinations already supplied as domain names also use the ordinary policy.

The TLS parser improvements apply with or without this option: fragmented TLS can
continue within the existing 200 ms budget instead of giving up after two reads.
The default timeout and its IP routing fallback remain unchanged.

Enable this only where waiting for client data is appropriate: a server-first
protocol on TCP/443 will time out. A ClientHello exceeding the prefix budget or
arriving after the deadline will also fail. This is not a guarantee of routing
encrypted/hidden SNI (ECH), QUIC, or all traffic for a particular service.
