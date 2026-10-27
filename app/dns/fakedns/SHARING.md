# Sharing FakeDNS mappings

When DNS is answered by one core and traffic is handled by another, independent
allocators for the same synthetic range are unsafe: the receiving core may not
know a domain, or may have allocated that address to another domain. Sharing only
the CIDRs or forwarding DNS requests does not provide reverse mapping ownership.

This feature offers one authoritative bounded allocator and a `FakeDNSService`
using Xray's existing API transport. It supports desktop clients with isolated
DNS/TUN/data processes, a long-lived DNS process with replaceable traffic cores,
and other controllers that need both allocation and reverse lookup. Ordinary
single-core configurations remain unchanged; Go applications that already share
one engine in-process do not need the RPC.

## Configuration

The authority uses ordinary local pools and enables the service:

```json
{
  "api": {
    "tag": "api",
    "listen": "127.0.0.1:8080",
    "services": ["FakeDNSService"]
  },
  "fakedns": [
    { "ipPool": "198.18.0.0/15", "poolSize": 65535 },
    { "ipPool": "2001:2::/48", "poolSize": 65535 }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
```

Consumers select the remote engine instead of local pools:

```json
{
  "fakedns": {
    "remote": { "address": "127.0.0.1:8080", "timeout": 2000 }
  },
  "dns": { "servers": ["fakedns"] }
}
```

Their traffic inbounds still need the usual FakeDNS sniffing/destination override
configuration. The remote engine implements the same FakeDNS feature interfaces,
so DNS and sniffing need no private protocols or alternate DNS-server scheme.
Pool settings and `remote` are mutually exclusive. `timeout` is a per-call deadline
in milliseconds; omitted/zero means 2000. The address must be a loopback IP literal
with a nonzero port (IPv4 or IPv6), or an absolute Unix socket path prefixed with
`unix:`, such as `unix:///run/xray/fakedns.sock`. On Windows versions supporting
Unix sockets, `unix:C:/path/to/fakedns.sock` is also accepted. Hostnames and custom
gRPC resolvers are not accepted. Connections bypass system proxy discovery.

## API and behavior

- `GetPools` reports initialized CIDRs, not the contents of the mapping table.
- `Allocate` selects IPv4 and/or IPv6 and uses the authority's existing LRU.
- `ReverseLookup` takes a binary IP and returns an empty domain for unknown/evicted
  addresses. It never allocates a replacement mapping.

The remote engine opens one reusable gRPC connection, fetches and validates pool
ranges at Start, and performs membership checks locally. Allocation and reverse
lookup always consult the authority. There is no replicated reverse cache, local
fallback allocator, import/export of arbitrary mappings or unbounded journal.
Closing a consumer cancels its calls and closes its connection without closing
the authority. IPv4/IPv6 selection and LRU eviction keep their native semantics.
An ended parent context prevents new mapping calls, including calls with their
own uncancelled request context.
Construction opens no connection; failed startup closes its candidate connection,
and closing during startup cancels pool discovery. If a consumer also exposes the
mapping service, forwarded calls preserve the caller's deadline/cancellation and
the authority's RPC errors. Reverse-domain replies are validated before use.
Native DNS queries and FakeDNS metadata sniffing use the optional context-aware
engine capability too: their request budgets reach the authority, and mapping
errors remain distinguishable from unknown or evicted mappings. Context-free
local engines and existing feature callers remain supported.
Use the same domain spelling/canonicalization as the local engine: the API does
not introduce a separate domain-key normalization rule.

The authority must be ready before consumers start: `GetPools` must succeed,
not merely the API listener opening. An unavailable authority
makes consumer startup fail or mapping calls return no result, rather than silently
creating a competing allocator. The existing engine interface has no error return
for mapping queries. Authority loss does not itself create a general traffic
firewall: the controller must decide how traffic to unknown synthetic addresses is
handled. Pool geometry changes require consumer restart. Mappings survive consumer
replacement, not authority restart or ordinary LRU eviction; this is not persistent
storage or a distributed consensus protocol.

## Local access

All three RPCs require a direct API connection over loopback TCP (IPv4 or IPv6)
or a local Unix socket. Configure `api.listen`, for example `127.0.0.1:8080` or
`/run/xray/fakedns.sock`. Nonlocal connections return `PermissionDenied` before
reading or allocating mappings. The routed API path exposes synthetic connection
addresses and is also denied, even when its inbound listens on loopback.
Forwarding headers do not establish local access.

This is a transport reachability check, not local-user authentication. The client
uses plaintext gRPC; keep it local and protect the API and Unix socket permissions
as other administrative interfaces. Existing API services retain their current
access behavior.
