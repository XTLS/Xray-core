# XDNS encrypted DNS

XDNS uses `domains[].names` for tunnel domains and `resolvers[].addrs` for
recursive DNS endpoints. Record types belong to `domains[].types`, independently
of the resolver protocol. An omitted client `types` list defaults to TXT (16);
the server continues to accept A, CNAME, TXT and AAAA by default.

```json
{
  "type": "xdns",
  "settings": {
    "domains": [
      {
        "names": ["tunnel.example.com"],
        "types": [16],
        "edns0": 1232
      }
    ],
    "resolvers": [
      {
        "addrs": [
          "dot://resolver.example:853",
          "doh://resolver.example/dns-query"
        ]
      }
    ],
    "extraPoll": 0
  }
}
```

Replace the example tunnel domain and resolver hostnames with real endpoints.
Configure the authoritative XDNS server with the same tunnel domain and record
types; its DNS listener does not change.

| Endpoint | Default port | Notes |
| --- | --- | --- |
| `192.0.2.1`, `udp://192.0.2.1` | 53 | Existing UDP transport |
| `tcp://resolver.example` | 53 | Existing plaintext TCP transport |
| `dot://resolver.example` | 853 | DNS over TLS; no path or query |
| `doh://resolver.example` | 443 | HTTPS POST; default path `/dns-query` |

IPv6 literals use brackets, e.g. `dot://[2001:db8::1]:853`. DoH preserves a
custom path and query, e.g. `doh://resolver.example/custom?key=value`.

TLS verifies the endpoint hostname or IP using system trust roots. Resolver
connections use Xray's injected TCP dialer and inherit its socket settings.
Bootstrap name resolution and any proxy used by that dialer must be available
independently of the same XDNS outbound to avoid a circular dependency.

Put XDNS last in the configured UDP mask list when it contains DoT or DoH.
Combining it with another mask that owns dialing (such as xicmp or udphop) is
rejected before dialing. Existing plaintext-only mask behavior is retained.

Each encrypted endpoint permits at most 16 concurrent requests with a 10-second
timeout. Saturated endpoints drop new requests instead of blocking other
resolvers. DoT reuses its TLS connection, matches transaction IDs and questions,
and reconnects on a subsequent request after a disconnect. DoH reuses HTTPS
connections and negotiates HTTP/2 when available. Redirects and invalid DNS
responses are rejected. Queries are not automatically replayed after an
uncertain result.

Clients with encrypted resolvers support logical read/write deadlines and a
stable logical local address. Close cancels requests and waits for resolver and
client workers to finish.

Explicitly listing UDP/TCP together with DoT/DoH is supported and sends some
queries in plaintext. No plaintext resolver is added implicitly. This extension
adds DoT and DoH; `doh3`, `doq`, `fallback` and `auto` are not implemented.

Tests are intended for GitHub Actions, including the package tests in the
existing workflow. A focused race run can use:

```sh
go test -race -timeout 5m ./transport/internet/finalmask/xdns ./transport/internet/finalmask ./infra/conf
```
