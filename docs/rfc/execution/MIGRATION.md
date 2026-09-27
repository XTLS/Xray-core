# Migration and related upstream work

## Status

Proposed direction only. The experimental diff is not the first production PR.
An accepted migration should retire a complete responsibility on a cohort of
paths, rather than merely convert one interface at a time.

## Logical stages

1. Ordinary streams: decoded input/sniffing, route, startup, transfer, policy
   and completion together. Keep contrasting direct and framed examples so
   the design is not determined by the first inbound/outbound pair.
2. Other stream admissions/outcomes: HTTP request reuse, core.Dial and tagged
   APIs, local answer/reject, fallback and reinjection. Preserve logical versus
   physical lifetime and immediate virtual-return semantics.
3. Packet associations: admission, replaceable routing legs, native packet IO
   and replies together, including virtual/shared device owners when supported.
4. Multiplexed/shared resources: children, carrier serialization, END ordering,
   Reverse and retained XUDP with explicit isolation/reuse contracts.
5. Remove obsolete compatibility and old execution bodies after the last
   production callers move. Recount queues, loops, timers and adapters, then LOC.

These stages are owner groups, not a commitment to their exact PR sizes. The
first production slice is a maintainer question. Trojan's removed relay is a
useful concrete example, but ordinary framed paths must constrain the common
boundary before it is generalized. Old Process callers, including direct library
usage, need an explicit replacement rather than disappearance by assumption.

## Related PRs, checked 2026-09-27

- [#5143](https://github.com/XTLS/Xray-core/pull/5143) is open: decoded VMess
  readers/writers passed through DispatchLink, with added MUX/reverse pipes.
  [RPRX asks to avoid restoring those pipes](https://github.com/XTLS/Xray-core/pull/5143#issuecomment-3403697498);
  [Yuhan explains concurrent response writes](https://github.com/XTLS/Xray-core/pull/5143#issuecomment-3568788872).
  This is the closest ownership/serialization comparison, not an incompatible
  philosophy merely because its entry is named DispatchLink.
- [#5844](https://github.com/XTLS/Xray-core/pull/5844) is open: connection
  tracking/API over existing execution. [RPRX describes the API need](https://github.com/XTLS/Xray-core/pull/5844#issuecomment-4150019479);
  [Fangliding questions the initial complexity](https://github.com/XTLS/Xray-core/pull/5844#issuecomment-4150055342).
  Its observer is outside this RFC; overlapping files still need reconciliation.
- [#6814](https://github.com/XTLS/Xray-core/pull/6814) and
  [#6822](https://github.com/XTLS/Xray-core/pull/6822) are open: exact-instance
  UDP retirement and packet-local destination values. These support narrow
  ownership invariants, not a universal association/leg architecture.
- [#6425](https://github.com/XTLS/Xray-core/pull/6425) is open and currently
  changes one DNS timeout-only context. [The discussion](https://github.com/XTLS/Xray-core/pull/6425#issuecomment-4915458047)
  distinguishes dial cancellation from copy lifetime. Broader context changes
  were withdrawn; this is not a reason to add a DNS rewrite here.
- [#6834](https://github.com/XTLS/Xray-core/pull/6834) is open: suppress the
  outer TLS CloseNotify after Vision switches to raw copy. It is a future
  protocol-transition gate, not a generic instruction to suppress TLS closure.
- [#6831](https://github.com/XTLS/Xray-core/pull/6831) is open: native SS2022
  rewrite/removal of singbridge. It is a future overlap and dependency example;
  E1's Shadowsocks cell is ordinary AEAD, not SS2022.
- [#6298](https://github.com/XTLS/Xray-core/pull/6298) is an open plugin
  outbound proposal with a Link interface. It is not an accepted external ABI.
  [#6833](https://github.com/XTLS/Xray-core/pull/6833#issuecomment-5849039988)
  is closed; its maintainer response suggests a direct outbound Process call
  for the discussed embedding use, highlighting callers beyond ordinary inbound.
- [#6843](https://github.com/XTLS/Xray-core/pull/6843#issuecomment-5857644467)
  is closed without merge: objections to added counters and end-only access
  logging. Its pipe-close diagnostic snapshot is not shared execution completion.
  [#6837](https://github.com/XTLS/Xray-core/pull/6837#issuecomment-5855079308)
  is also closed: loopback performance did not justify complicated counter
  unwrapping. E1 makes no uniform performance claim.

These links document questions and constraints, not endorsement. sing-box and
Mihomo are implementation references only; no peer code or architecture is
required to accept this proposal.
