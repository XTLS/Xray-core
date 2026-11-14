# VMess rule-scoped UUID routes

Ordinary VMess clients can select an explicitly declared `userRoute` by changing UUID bytes 7 and 8. Only the server needs this implementation. The original UUID remains a valid exact credential. `vlessRoute` retains its previous meaning; it does not enable VMess aliases.

## Authentication and identity

The router publishes immutable route declarations together with its active rules. Inbound tags and user/email matchers, including the router's regular-expression semantics, select the eligible values. Destination-dependent conditions remain routing conditions. A script-only router declares no aliases.

The validator derives ordinary VMess AuthID keys for those values. It keeps exact configured credentials on their existing path. If multiple configured ordinary accounts share the same 14 non-route bytes, generated aliases for that identity are disabled; their exact credentials keep their existing owners. Generated keys never become separate API users.

An inbound retains a small identity-history record for each distinct 14-byte identity registered during its lifetime. If that identity is registered with different original route bytes or in both ordinary and legacy opt-in modes, its ordinary aliases stay disabled even after API removal/re-addition. Re-registering the same exact credential and mode remains supported. This history is administrative metadata, not prepared keys, and is cleared when the inbound is destroyed. It is not persisted across restarts: independently revocable users and credential rotations must use fresh non-route UUID bytes. Changing only the route bytes intentionally preserves access to the same routing identity.

Matching returns the original account and the selected UUID's command key separately. The normal header AEAD, syntax, checksum and replay checks still run. Session replay identity uses the original account, including across aliases. Only after complete validation does a generation check admit a connection and acquire its cache lease. Account deletion, identity replacement and route removal fence stale admissions. Existing connections retain their original policy and route until closed.

Admission also checks the registration ID, including for exact credentials, and rejects alias candidates while a concurrent account change is pending. Closed validators cannot rebuild catalogs. API removal uses the same lowercase email identity as registration, including Unicode. AuthID replay records cover the entire inclusive timestamp window: each rotating bucket lasts 241 seconds rather than 120. This retains more replay records under sustained traffic; it does not change wire encoding, accepted timestamp skew or the separate existing three-minute body-session history.

The earlier opt-in account extension remains readable for compatibility with this fork's earlier configurations. Ordinary aliases do not use its key derivation, reserved byte or padding format; no account flag is needed.

Without a route provider, ordinary authentication creates no route catalog or online-cache state. Existing routing contexts and protobuf field numbers remain unchanged by the server-only implementation.

## Online/recent cache

The cache has no address, IP, source-port or fingerprint input. A successful connection increments the original account's lease count; every exit releases it exactly once. A Mux carrier has one lease. Prepared keys expire two minutes after the final connection closes, with cleanup on access and a 30-second periodic sweep.

Entries use a prepared-key byte budget. Idle entries are evicted before active entries, with authentication recency breaking ties. Eviction never revokes a credential. Rule-only updates preserve lease counts and idle deadlines, do not promote evicted accounts, and do not count as fresh authentication. Leases survive a temporarily empty route set. Slow headers retain only the account and a numeric generation, not an obsolete key table; long-lived leases likewise do not pin obsolete tables.

Hot lookup walks the same recency list used for eviction. A failed attempt to cache a larger route set leaves other eligible entries intact. Immutable provider-owned declaration slices are copied before filtering out the original route.

Search holds a read lock while using immutable tables. Catalog/cache publication waits for readers, so scans cannot retain a retired prepared table. Cache preparation is serialized under the cache lock, and catalog rebuilding under the validator lock. This bounds concurrent preparation but can delay handshakes during a large update. Unchanged account key groups are reused. A stale in-flight alias handshake may be rejected during reload and must reconnect.

## Resources and platforms

Per inbound:

- Prepared-key payload: at most 64 MiB.
- Raw alias-key catalog: at most 128 MiB; the full count is checked before new key derivation.
- At most two concurrent alias scans. Excess alias handshakes fail promptly; exact configured credentials do not consume these slots.

Exceeding the catalog limit fails initial setup. After a live rule or user update, an oversized catalog disables alias admission with an explicit authentication error until it fits; exact configured credentials remain valid. Catalog replacement can temporarily hold both old and new raw tables. Metadata, allocator/GC overhead and ordinary connection buffers are additional memory; these limits do not claim to cap total RSS.

On amd64 with AES-NI and SSE4.1, the candidate search uses a 68-byte AES-128 decryption schedule and four interleaved candidates. All ten AES rounds remain present. A candidate is rechecked with the standard-library decoder before the ordinary authenticated header is opened. CPU feature checks, `purego` builds and Go FIPS mode select the standard-library fallback. The fallback is functionally compatible but has higher search/allocation costs; the measurements below do not predict ARM performance or certify a cryptographic module.

At 10,000 users and 300 declared aliases each, the raw payload is 48,000,000 bytes. With 1,000 cached accounts, native prepared payload is 20,400,000 bytes. A local Windows amd64 / Go 1.27.3 check after the admission/cache fixes measured a 3.279-second catalog build, a 173.882-ms cold miss, a 2.573-ms cached match and 85,756,528 bytes of live Go heap in that test process. These are individual local observations, not latency percentiles, total server RSS or a production throughput claim. If most users are cold, the cache cannot remove the full catalog scan. VMess does not expose the plaintext UUID lookup available to VLESS.

A second lifecycle check admitted all 10,000 accounts simultaneously. The cache retained 3,289 accounts (67,095,600 prepared-key bytes), kept 10,000 active lease records, and released all prepared entries after the final closes and expiry. The remaining online accounts stayed eligible through cold search.

## Verification

Coverage includes catalog scoping and immutable publication, malformed range rejection, account collisions and exact ownership, API user counts, stale candidates, original credentials, cache expiry/eviction, route changes concurrent with connection closes, and a 4,000-operation deterministic lifecycle model. Native AES tests compare a known-answer vector and 4,096 decryptions against the standard library; search tests cover tails, unknown users and expired AuthIDs.

The real encoder/decoder fixture covers UUID-only aliases, header tampering, AuthID replay, cross-alias session replay and rule removal. The network scenario covers TCP, UDP, AES-GCM, ChaCha20-Poly1305 and Mux with no account flag. The separate verification workspace records published-client interoperability and the 10,000-by-300 resource check.

Unmodified published clients 1.8.24, 25.12.8 and 26.11.9 passed UUID-only selection on TCP/UDP, both body ciphers and Mux, plus route values 0 and 65535. A further 120 ordinary VMess/VLESS compatibility cases in both directions and seven byte-for-byte legacy configuration compilation cases passed. The legacy `vlessRoute` zero fixture uses its pre-existing string form `"0"`; changing the old parser's handling of numeric zero is outside this change.

Independent cryptographic review, race instrumentation and production load testing remain release requirements. Local functional tests do not establish those outcomes.

Selected authentication/cache regressions passed 30 repetitions at each of 1, 2, and 4 CPUs with shuffled order. Go pointer checks and the runtime fallback with AES/SSE4.1 disabled also passed. These do not replace race instrumentation or independent assembly review. Windows executable builds and Linux amd64/arm64 VMess cross-compilation passed; Linux runtime testing was not performed.

The broader local test run was not wholly green. With a larger time budget, the full scenario package passed in 337.398 seconds, resolving the earlier timeout. The remaining failures were the external AdGuard QUIC IPv4-override DNS test and Cloudflare ECH dialing (`malformed ECHConfigList`). The affected packages passed with those external test families excluded; excluded tests are not counted as passing. Final scoped and published-client checks were rerun after the last authentication fixes. Full `go vet` also reports pre-existing unreachable code in VMess commands/config parsing and a discarded timeout cancellation in the routing command service; all other analyzers passed when those two existing analyzer classes were excluded. DNS/TLS production code and the pre-existing vet findings were not changed.
