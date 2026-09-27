# sing-box and Mihomo execution boundaries

## Status and method

SOURCE COMPARISON — 2026-09-27. This is evidence for the new
[Xray proposal](README.md), not a selected implementation or peer benchmark.
The inspected development refs and their actual dependencies were pinned
and their source paths inspected for this comparison. This document preserves
that dated source review; it is not a new runtime or performance execution.

No peer implementation, source patch or dependency was copied into Xray.
Descriptions below distinguish observed source behavior from design inference.
No peer runtime, performance, Android or interoperability test was run.

## How these examples may be used

The architecture of sing-box or Mihomo is not the target. These are examples
of concrete mechanisms, including
their costs and limitations. They are not reference implementations of correct
Xray behavior, and this comparison claims no RPRX or upstream endorsement.

For any proposed use, identify the Xray problem first; inspect the example;
compare it with native reuse and a direct Xray-specific solution; then verify
the resulting ownership, behavior and cost in Xray. A mechanism is not selected
because both peers use it. Their registries, dependency graph, buffer framework,
callback semantics and product policy are not inherited requirements.

Maintainer criticisms are relevant when they identify a concrete mechanism,
tradeoff or failure. Keep the exact statement and its context, verify whether
the inspected revision has the same property, and record the consequence for
our proposal. Neither broad praise nor broad criticism settles this design.

## Exact sources

- **sing-box testing:**
  [`af60b5e60525ff003940a7816a5302d58ad550fa`](https://github.com/SagerNet/sing-box/tree/af60b5e60525ff003940a7816a5302d58ad550fa),
  committed 2026-09-27 10:40:50 UTC. The separately resolved release v1.14.2 is
  `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`; development findings are not claims
  about that release.
- Its [go.mod](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/go.mod#L46)
  pins `SagerNet/sing v0.9.6-0.20260927091435-fcc22e2b9f96`, resolved to
  [`fcc22e2b9f96f06534a4269e47e2a354f2c64446`](https://github.com/SagerNet/sing/tree/fcc22e2b9f96f06534a4269e47e2a354f2c64446).
  Its sing-mux dependency resolves to `baf887b90a625f89b5daef70c193e8859d17cf53`;
  this review covers the integration boundary, not a complete mux-library audit.
- **Mihomo Alpha proxy core:**
  [`63bd52ec794b7051569b76ede2f6cdbf4c091fda`](https://github.com/MetaCubeX/mihomo/tree/63bd52ec794b7051569b76ede2f6cdbf4c091fda),
  committed 2026-09-27 01:11:59 UTC. Alpha is the inspected development branch;
  the unrelated/stale main tree was not silently substituted.
- Its [go.mod](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/go.mod#L37)
  pins `metacubex/sing v0.5.8`, resolved to
  [`1dd5bcee2b112766b8f030eb51f3db2f245996ed`](https://github.com/metacubex/sing/tree/1dd5bcee2b112766b8f030eb51f3db2f245996ed),
  and sing-mux v0.3.10. The latter's internal child/carrier implementation was
  not verified in this pass after its tag lookup timed out.

License provenance comes from repository text, not GitHub's inferred badge:
[sing-box](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/LICENSE)
and [SagerNet/sing](https://github.com/SagerNet/sing/blob/fcc22e2b9f96f06534a4269e47e2a354f2c64446/LICENSE)
state GPL-3.0-or-later; sing-box also states a naming restriction.
[Mihomo](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/LICENSE)
contains GPL v3 text; [metacubex/sing](https://github.com/metacubex/sing/blob/1dd5bcee2b112766b8f030eb51f3db2f245996ed/LICENSE)
states GPL v3-or-later. These are comparison sources, not implementation donors.

## sing-box: connection handoff with capability-aware execution

The [SOCKS inbound](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/protocol/socks/inbound.go#L74)
hands a connection and metadata to `RouteConnectionEx`.
The [router](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/route/route.go#L71)
sniffs/matches, retains consumed data through cached-connection wrappers and
selects the outbound. It can call an outbound-specific connection handler or
the central connection manager. Thus a common path exists, but not every handler
is compelled to be a two-socket relay.

The [connection manager](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/route/conn.go#L101)
dials the selected endpoint, reports handshake success, attempts the available
splice path, applies configured connection transforms, handles pending
first-write handshakes and starts the two directional copies. A
[Trojan outbound](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/protocol/trojan/outbound.go#L159)
returns a protocol-wrapped connection to this machinery rather than containing
its own general ordinary-TCP duplex pump.

The actual copy machinery is in the pinned sing dependency. Its
[copy entry](https://github.com/SagerNet/sing/blob/fcc22e2b9f96f06534a4269e47e2a354f2c64446/common/bufio/copy.go#L27)
drains cached input, discovers capabilities, can unwrap counting endpoints and
refreshes the usable operation after handshake. Its
[direct path](https://github.com/SagerNet/sing/blob/fcc22e2b9f96f06534a4269e47e2a354f2c64446/common/bufio/copy_direct.go#L12)
includes splice and optimized buffer/read-wait/vector alternatives. The main
connection boundary is not evidence of scalar-only copying or zero buffering.

The [ordinary directional completion code](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/route/conn.go#L292)
attempts half-close when supported, or closes an endpoint. A shared zero-value
atomic flag means the **second** direction to reach `done.Swap(true)` invokes
`onClose`, then calls the final endpoint close. The callback is before that
final close and remaining logging; `NewConnection` itself returns after starting
goroutines. Therefore it is directional coordination, not a synchronous
post-resource-release return contract. Failure/startup and splice paths must be
read separately before making a broader callback guarantee.

There are also separately tracked socket owners in the same manager. Their
existence does not mean the relay, live-connection directory and every lower
resource have one lifetime. The Xray proposal does not inherit that tracking
structure merely because it exists beside copying.

For packets the [router](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/route/route.go#L247)
and [manager](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/route/conn.go#L175)
use packet-specific operations, destination remapping and UDP timeout behavior.
The [packet contract](https://github.com/SagerNet/sing/blob/fcc22e2b9f96f06534a4269e47e2a354f2c64446/common/network/conn.go#L24)
itself uses the peer library's buffer plus destination; it is not plain
`net.Conn`. The similarly named peer buffer package is not Xray's MultiBuffer
ABI, and it is not evidence that useful custom buffer contracts never exist.

[MUX client integration](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/common/mux/client.go#L17)
and [carrier routing](https://github.com/SagerNet/sing-box/blob/af60b5e60525ff003940a7816a5302d58ad550fa/common/mux/router.go#L70)
delegate multiplexing to sing-mux. Decoded children are separate routed
connections or packet connections. This integration is evidence for distinct
child/carrier boundaries, not proof of Xray MUX/XUDP behavior.

## Mihomo: routed connections and a shared relay

The [TCP tunnel path](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/tunnel/tunnel.go#L502)
validates/fixes metadata, sniffs or peeks retained data, selects a proxy and
dials it with timeout/retry handling. It can write an early payload for a
handshake-aware connection, discards exactly the consumed peeked prefix,
installs a tracker and enters socket handling. The tunnel keeps final endpoint
close responsibility around that operation.

[Socket handling](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/tunnel/connection.go#L220)
calls the active [shared Relay](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/common/net/sing.go#L67).
One direction runs in a goroutine and the other in the caller. Successful copy
attempts CloseWrite, otherwise closes; Relay waits for the other worker and
defers closing both endpoints before returning. The commented historical
`common/net/relay.go` is not the active implementation.

The effective outbound [connection type](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/adapter/outbound/base.go#L225)
includes an extended connection and chain metadata. Construction can add a
deadline adapter and exposes replacement/unwrapping information. This is a
connection-oriented boundary with additional capabilities and real wrapper
cost, not a promise that every adapter is transparently interchangeable.

The [buffered input](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/common/net/bufconn.go#L74)
drains sniffed bytes before allowing replacement of the reader. Pinned sing's
[copy selection](https://github.com/metacubex/sing/blob/1dd5bcee2b112766b8f030eb51f3db2f245996ed/common/bufio/copy.go#L20)
handles cached input and counters, attempts direct syscall copying, then uses
extended readers/writers, read waiters, headroom and pooled buffers as applicable.
It is not a mandatory standard `io.CopyBuffer` path.

UDP follows a [different tunnel path](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/tunnel/tunnel.go#L420):
a NAT-keyed sender owns bounded packet admission; outbound packet connection
creation and a reply worker are separate from TCP relay. The
[packet operations](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/tunnel/connection.go#L65)
preserve destination mapping and WriteBack behavior, serialize sends and drop
when their admission bounds require it. The
[reply worker](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/tunnel/connection.go#L168)
restores source addressing, writes back, releases storage and closes association
resources. TCP relay success cannot validate this separate lifecycle.

The [multiplexing outbound](https://github.com/MetaCubeX/mihomo/blob/63bd52ec794b7051569b76ede2f6cdbf4c091fda/adapter/outbound/singmux.go#L41)
presents a child stream as a connection and handles packets separately. This
review does not establish its dependency's internal serialization, close
isolation or retained-session behavior.

## Implications for the new Xray solution

**Observed mechanism examples:** decoded connection handoff to common routing;
selected outbound preparation returning a usable protocol endpoint; shared
ordinary transfer mechanics; capability-aware optimized I/O; retained input
drained before lower-reader replacement; packet-specific addressing/lifetime;
logical children separated from shared resources.

**Not established:** one universal Conn type is sufficient; all buffers or
queues disappear; every handler uses one relay function; wrapper Close or a
callback proves all work and resources ended; peer throughput predicts Xray
performance; peer packet/MUX code solves Xray-specific retained XUDP.

The proposed Xray separation of protocol preparation and execution must stand
on the Xray owner graph and experiments. These examples show ways to implement
such a separation and pitfalls to test; they do not select it. Xray's own
scalar-D result already rejects that shortcut without any peer comparison.
There is no basis here to import a peer manager or optional-interface catalog.
Each proposed capability must remove concrete conversion/copy work or preserve
an observed semantic property on the Xray path.

## Consequences for E1

The direct and framed stream cells must enter one owner through the actual
dispatcher/proxyman boundary, preserve cached first data and prove real old-body
retirement. A reader/writer facade over old execution is a failing result.

The two completion implementations differ, so Xray must specify its own
directional and final completion contract rather than copy a callback name.
The packet and native-child cells are required early discriminators because
neither peer's ordinary stream path proves those shapes fit Xray's replacement.

E1's six cells, negative findings and result boundaries are recorded in
[E1_RESULTS.md](E1_RESULTS.md); reproduction commands are in
[VALIDATION.md](VALIDATION.md). This comparison does not select another plan.
