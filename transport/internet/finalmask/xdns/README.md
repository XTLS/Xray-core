# XDNS resolver configuration

Client resolvers use this form:

```text
<tunnel-domain>[:txt|a|aaaa]+<protocol>://<resolver-endpoint>
```

For example:

```json
{
  "type": "xdns",
  "settings": {
    "resolvers": [
      "example.xdns+udp://192.0.2.1:53",
      "example.xdns:txt+dot://resolver.example:853",
      "example.xdns:aaaa+doh://resolver.example/dns-query"
    ]
  }
}
```

The record type defaults to `txt` for clients. UDP resolvers require an IP
address and an explicit port. DoT accepts a DNS name or an IP address and
defaults to port `853`. DoH accepts a DNS name or an IP address, defaults to
port `443`, and uses `/dns-query` when the URL has no path. DoH query
parameters are preserved.

Resolvers may be mixed explicitly. UDP entries remain plaintext DNS; XDNS does
not fall back from DoT or DoH to UDP. DoT and DoH authenticate the resolver
with the system trust store using the configured host name or IP address.

The connection used to resolve a DoT or DoH resolver must not itself depend on
the same XDNS outbound, otherwise startup resolution can recurse.
