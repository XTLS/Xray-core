# Full historical experiment matrix

## Status, provenance and relation to E1

The saved register contains **64 rows**, revision **267**, recorded on
2026-09-20. Its state is **OPEN**, with no production implementation selected.
These rows are research questions, not 64 completed experiments or 64 E1 tests.
Six E1 integration cells cannot replace this history.

[The machine-readable register](historical-matrix.json) preserves every row ID,
compared variants, full recorded status, historical next step, unknowns and run
identifiers. Questions are translated into English. Local paths, private Git
references, product requirements and unavailable file links are not exported.
Receipt counts count identifiers attached to the saved register, not passed
tests. Some scoped reports (including historical CONN-R2) were recorded
separately and have no run ID in that row. Run IDs identify saved receipts;
they are not fabricated public links. The
original source-register digest identifies the snapshot behind this translation.

The matrix's official reference was
[`c412e77`](https://github.com/XTLS/Xray-core/commit/c412e77a9b712082ac9ebf27fa793951cb5a7d85).
Individual experiments also used their own experimental controls. Their costs
must not be subtracted from E1's official `3519dfec` control, or added together
as cumulative savings. Historical complete source bundles are not all published.
The descriptions below are recorded findings, not fresh executions.

Status meanings:

- `CLOSED_WITH_SCOPED_EVIDENCE`: the bounded question has a recorded result,
  including negative results; it does not mean the candidate was accepted.
- `SCOPED_RESULT_COMPLETE`: the named specimen was evaluated, not all Xray.
- `MERGED*`: the research question moved to another row, not a GitHub merge.
- `DEFERRED*`: unexecuted or incomplete at this register snapshot; never PASS.
- `*_INVARIANT`: an evidence/validation rule, not a runtime experiment.

The original broad register also investigated observation, control and DNS
replacement. Those rows remain visible for completeness but are explicitly
outside this execution RFC. They do not become migration requirements or
justify adding a tracker, policy system or DNS replacement subsystem to E1.

## Variant glossary and causal sequence

S denotes the relevant official control; A a historical experimental control.
O compacted observation state without changing IO; B consolidated native input,
timeout and cache work; L added exact local close/join; D changed the copy
boundary while preserving those other dimensions. DNS-P explored resolver-state
preparation separately. These were controlled contrasts, not a chain of approved
production releases. G/T compared opaque owner identity with configured tags;
the resolver lifecycle question is outside this RFC.

1. **Input consolidation (B)** removed repeated reader/timeout/cache work in
   bounded paths. It suggested a single custodian for retained decoded bytes.
2. **Scalar copy (D)** exposed the cost of an unconditional 32 KiB buffer and
   loss of the prior uplink vector path. A standard connection interface alone
   did not justify forcing scalar transfer everywhere.
3. **Prepared framing (BUF-1B/1C)** removed one gather operation in a measured
   AEAD primitive, but allocation depended on the producer and returned backing.
   This was not a whole-flow or generic zero-copy result.
4. **CONN-1** introduced a connection-facing facade while retaining old owners,
   wrappers and sniff replay. It proved zero removed byte-copy operations. Forty
   fresh-process receipts recorded +1 to +3 allocations in every paired contrast;
   byte deltas changed sign. Functional success did not demonstrate retirement.
5. **CONN-R1** moved actual input/endpoints and two-worker completion into a
   coherent stream owner. Its direct and framed allocation results differed;
   substantial legacy callers and per-protocol execution still remained.
6. **CONN-R2 (historical shared-executor experiment)** replaced scoped Freedom
   and Shadowsocks relay loops with shared execution. Native MUX-child fit was
   still source-blocked at Link admission/child ownership; a carrier-compatible
   test was insufficient. This motivated a real decoded-child discriminator.
7. **Trojan experiment** proved selected relay retirement and EOF/final-write
   cases, but its mandatory buf boundary, two queues and old child execution
   were not the terminal architecture. The first client's topology could not
   define every stream.
8. **E1** tested contrasting direct/framed producers and native packet/child
   shapes together. Its first revision still failed association/leg lifetime
   and read-ahead allocation requirements. **E1 R2** corrected those two choices;
   [the detailed results](E1_RESULTS.md) preserve the failure and correction.

Historical CONN-R1/CONN-R2 and E1 R1/R2 are **different experiment series**.
A shared suffix is not source identity or transferable evidence.

## Execution-design history (19 rows)

| ID | Question | Compared forms | Recorded result/status | Receipt count |
| --- | --- | --- | --- | ---: |
| CONTROL-1 | Exact control and candidate parity | S exact official; A current snapshot; O/B/L/D frozen | PROCEDURE_INVARIANT: exact baseline, clean control, source hashes and failure preservation required for every run | 1 |
| BUF-1 | Framing headroom, copy and returned storage | S/temp control; CopyReturn old framing; CopyReturn native StackNew temp; CopyReturn reserved frame; RETIRED: RejectDetached generic replacement | CLOSED_WITH_SCOPED_EVIDENCE: framing, returned storage and allocation controls preserved | 9 |
| BUF-2 | Connection-oriented Shadowsocks batch/vector/headroom | S native MultiBuffer/connection control; applicable CopyReturn old/StackNew/reserved controls; one R-SS2 producer-reserved batch candidate; D byte-copy historical control only | MERGED_INTO_CONN-1: conn-oriented SS correctness, native UDP/MUX fallback and copy/allocation receipts preserved | 15 |
| PKT-1 | Packet destinations, sizes and partial acceptance | native packet owner/control; R-SS2 applicable packet-aware batch or explicit native fallback | CLOSED_WITH_SCOPED_EVIDENCE: one real SS UDP association preserved native packet fallback and A/B/A/B destinations | 3 |
| COPY-1 | Copy primitive memory, CPU and latency | 32K direct buffer; 8K buffer; bounded pool; native batch | CLOSED_WITH_SCOPED_EVIDENCE: cap-shaped Windows/Linux primitive allocations recorded | 14 |
| COPY-2 | Native progress versus final/deferred byte reporting | stock final n/deferred; owned chunked splice progress; native readv progress | DEFERRED_UNTIL_CONCRETE_CANDIDATE: native progress and byte-boundary acceptance suite | 0 |
| FIN-1 | Natural EOF, half-close and explicit abort | native behavior; directional FIN propagation; explicit full stop | CLOSED_WITH_SCOPED_EVIDENCE: A shared timeout and B SS-local alternatives pass the real property with distinct limitations; no selection | 19 |
| MUX-1 | Blocked DATA, child close and sibling survival | stock blocked-admission control; native pipe cancellation-aware DATA admission; one bounded shared frame serializer; per-child scheduler only if fairness gap remains | CLOSED_WITH_SCOPED_EVIDENCE: merged MUX gate records v2 blocker closure and full-uplink late-missing B delay | 15 |
| MUX-2 | END ordering and bounded close capacity | stock ignored END error/control wait; per-admitted-session END reserve with retained ID; bounded serializer/control scheduler | MERGED_INTO_MUX-1: exact local END/error evidence and arbitrary missing-session admission bound preserved | 3 |
| MUX-3 | Child batching, pressure and metadata | native pipe/gather control; R-SS2 applicable batch path or explicit native fallback; D byte-only historical seam | CLOSED_WITH_SCOPED_EVIDENCE: same-carrier neighbor exchange and native prepared-path fallback preserved | 3 |
| XUDP-1 | Local reuse, stale identity and retained remote state | native XUDP owners; local exact-handle candidates | DEFERRED_UNTIL_CONCRETE_CANDIDATE | 0 |
| TUN-1 | Full-cone identity, destinations and stale retirement | native gVisor owners; owner-local admission; packet seam | DEFERRED_UNTIL_CONCRETE_CANDIDATE | 0 |
| BUF-1B | Producer-reserved AEAD payload without a gather copy | CopyReturn gathers into output frame; one R-SS2 reuses explicitly prepared producer buffer; unreserved cached/unsupported input falls back honestly | CLOSED_WITH_SCOPED_EVIDENCE: prepared writer removes one gather at its measured boundary | 16 |
| BUF-1C | Authoritative Seal backing and error cleanup | v1 ignores returned backing; copy authoritative returned ciphertext; explicit reject non-inplace result | CLOSED_WITH_SCOPED_EVIDENCE: authoritative returned storage covered for built-in scope | 7 |
| BUF-1D | Returned size-prefix storage and panic cleanup | native Encode return ignored; consume returned prefix; explicit error or panic cleanup | DEFERRED_UNTIL_CONCRETE_CANDIDATE | 0 |
| BUF-1E | Native StackNew temporary-buffer cost | CopyReturn stock temp buf.New; CopyReturn stock temp buf.StackNew; CopyReturn reserved frame | CLOSED_WITH_SCOPED_EVIDENCE: StackNew primitive allocation result preserved | 2 |
| CONN-1 | Connection facade over retained execution owners | stock DispatchLink; current fork UserStream -> userStreamReader/BufferToBytesWriter -> transport.Link; bounded DispatchConn/ProcessConn-style candidate with at most one explicit temporary legacy Link adapter for named unmigrated outbound callers | CLOSED_WITH_SCOPED_EVIDENCE: one bounded conn-native SOCKS-to-Freedom branch passes lifecycle/routing/ReadV/splice gates, but retains ownership/accounting layers, removes zero proven byte copies and increases full-flow allocation count | 57 |
| CONN-R1 | Coherent direct/Shadowsocks stream ownership replacement | functionally comparable existing USER path; bounded stream replacement with one justified temporary legacy boundary | SCOPED_RESULT_COMPLETE: structural replacement and bounded direct/AES128 SS evidence; no foundation selected | 20 |
| CONN-R2 | Shared stream executor and native MUX-child fit | frozen CONN-R1 current-control; R1 v14 plus one shared direct/SS executor and owned preparation; native logical MUX-child applicability gate | SCOPED_RESULT_COMPLETE: structural PASS; Windows direct/SS correctness and bounded cost PASS with limitations; MUX-child runtime SOURCE_BLOCKED_WITH_EXACT_SCOPE; no foundation selected | 0 |

## Acceptance boundary, not e1 completion (7 rows)

| ID | Question | Compared forms | Recorded result/status | Receipt count |
| --- | --- | --- | --- | ---: |
| IDENT-1 | Distinguishing user, internal and measurement admission | explicit admission methods; typed owner-local origin | MERGED_INTO_CONN-1: explicit USER/internal admission is per migrated path, not a generic origin framework | 0 |
| IDENT-2 | Selected outbound and exact logical reference | dispatcher projection/index; owner-local handle/projection | MERGED: MUX collision evidence is closed in MUX-1; remaining logical-reference/ABA questions move to CONN-1 | 0 |
| SCALE-1 | Retained heap, GC and tails under concurrency | S/A/O/B/L/D and new forms | DEFERRED_READINESS_PLANE | 0 |
| COMPOSE-1 | Composition of compatible experimental candidates | explicit combined source bundles | DEFERRED_READINESS_PLANE | 0 |
| PLATFORM-1 | Host and Android cross-build boundaries | Windows; Linux; Android cross-build | DEFERRED_READINESS_PLANE | 0 |
| PLATFORM-2 | Physical device and external-network evidence | connected Android core harness; controlled network impairment/remote peer | DEFERRED_READINESS_PLANE: physical device prerequisite remains absent | 0 |
| DNS-M19 | Unchanged upstream regression controls | G/P; G/D; T/P; T/D where applicable | VALIDATION_INVARIANT: original upstream tests and fixtures remain unchanged | 0 |

## Outside execution rfc (38 rows)

| ID | Question | Compared forms | Recorded result/status | Receipt count |
| --- | --- | --- | --- | ---: |
| OBS-1 | Independent live, tag and history reads | combined snapshot control; separate native views | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| OBS-2 | Start/end results and bounded retention | bounded sequence log; snapshot+sequence; bounded event stream | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| OBS-3 | Slow consumer, loss and resynchronization | pull ring/cursor; bounded push+gap | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| OBS-4 | Totals/rates with partial writes, raw paths and reuse | current delta sampler; independent views/progress candidates | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| CTL-1 | Rule/balancer application and readback | native updates; thin serialized operation | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| CTL-2 | Runtime destination redirection | native prepared handlers; composed route+handler operation | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| CTL-3 | Handler replacement and existing-flow lifetime | native manager; validated prepare/publish adapter | DEFERRED_CANDIDATE_ACCEPTANCE | 0 |
| CTL-4 | Captured-set close after a switch | caller composition; snapshot-aware operation adapter | DEFERRED_MERGED_WITH_CTL-5: future per-path exact-close acceptance suite | 0 |
| DNS-1 | Runtime dependencies and provisional rollback | P negative control; explicit ready dependencies; prepared resolver graph | MERGED_INTO_DNS-A1 | 0 |
| DNS-2 | Identity of old DNS-owned work | G: private owner token + same per-state activity; T: active/draining configured tags + same activity | MERGED_INTO_DNS-A1 | 0 |
| DNS-3 | Retirement of DNS queries, caches and transports | G/P; G/D; T/P; T/D | MERGED_INTO_DNS-A1 | 0 |
| DNS-4 | Cache policy and mixed A/AAAA expiry | fresh cache; validated compatible migration | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-5 | Built-in DNS and routed/local path parity | TCP/UDP local+routed; DoH/QUIC prepared clients; prepared instances+routing | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| API-1 | Direct Go versus wire-adapter parity | direct Go; experimental thin native API adapter | DEFERRED_READINESS_PLANE | 0 |
| DNS-M1 | Missing dispatcher/FakeDNS dependency readiness | G/P; G/D; T/P; T/D where applicable | CLOSED_WITH_SCOPED_EVIDENCE: direct TCP readiness component | 3 |
| DNS-M2 | Provisional rollback across client kinds | G/P; G/D; T/P; T/D where applicable | CLOSED_WITH_SCOPED_EVIDENCE: lazy routed/local construction and failure preservation | 4 |
| DNS-M3 | Local/remote TCP DNS cutover | G/P; G/D; T/P; T/D where applicable | CLOSED_WITH_SCOPED_EVIDENCE: one paused old-A/fresh-B snapshot component | 3 |
| DNS-M4 | Stale refresh retirement | G/P; G/D; T/P; T/D where applicable | MERGED_INTO_DNS-A1: asynchronous worker lifetime first; stale/periodic work deferred | 0 |
| DNS-M5 | Singleflight across generations | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M6 | Mixed A/AAAA expiry and results | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M7 | Parallel winner/loser ownership | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M8 | UDP pending link and EDNS retry | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M9 | DNS outbound identity and recursion | G/P; G/D; T/P; T/D where applicable | MERGED_INTO_DNS-A1: G/T identity comparison after shared TCP-worker ownership | 0 |
| DNS-M10 | h2c transport pool ownership | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M11 | HTTPS handshake failure ownership | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M12 | QUIC stream, idle and dial lifetime | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M13 | Local resolver lifetime | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M14 | Borrowed FakeDNS engine ownership | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M15 | Cache/pubsub periodic work and migration | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M16 | Concurrent applies and retired backlog | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M17 | Instance close across DNS owner types | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M18 | Repeated apply/close and races | G/P; G/D; T/P; T/D where applicable | DEFERRED_UNTIL_DNS_OWNER_CANDIDATE | 0 |
| DNS-M20 | Bootstrap feature construction order | S dispatcher-before-DNS; S DNS-before-dispatcher; S isolated DNS-first process; DNS-M21 dependency-ready alternatives | CLOSED_WITH_SCOPED_EVIDENCE: stock bootstrap order counterexample preserved | 2 |
| CTL-5 | Exact references and per-target close outcome | current exact owner references; owner-local handles; selected snapshot composition | DEFERRED_MERGED_WITH_CTL-4: future per-path exact-close acceptance suite | 0 |
| DNS-M21 | Matcher construction after client readiness | S order-dependent control; A: trailing matcher finalizer (error masking hypothesis); B: whole builder with ready dispatcher/FakeDNS; later if warranted: explicit per-client completion/error receipts | CLOSED_WITH_SCOPED_EVIDENCE: B/J1 bootstrap construction component | 7 |
| DNS-M22 | Dependency callback error folding | S last-callback control; F first-error exact identity; J aggregate all with singleton wrapper; J1 singleton-direct, aggregate only multiple errors | CLOSED_WITH_SCOPED_EVIDENCE: J1 callback error-fold component; F remains comparison evidence | 8 |
| DNS-A1 | Async TCP-worker ownership and opaque-token versus tag identity | top-level lookup lease negative control; G private owner token plus TCP-worker child lease; T configured tags plus the same TCP-worker child lease | CLOSED_WITH_SCOPED_EVIDENCE: serial routed TCP worker ownership and publish/drain ordering pass; G/T differ only in identity precision; no model selected | 8 |
| APP-ROUTE-1 | Native process routing and actual-flow attribution | stock TUN process finder plus native process matcher and runtime rule/handler mutation; later candidate/device acceptance for actual rule/outbound receipt, app correlation sufficiency and captured-set exact close | DEFERRED_STOCK_INTEGRATION: native process/app routing and runtime rule mutation exist; later candidate/device acceptance covers route receipt, app correlation and captured-set close | 0 |

## A quantitative historical counterexample: shared execution was not free

The older CONN-R2 report used one unchanged measurement source in one Windows
Go 1.27 control process and one candidate process. Each short cell contained
32 fresh 1 KiB flows; each sustained cell contained eight fresh 8 MiB flows.
These figures compare that experiment's own control and shared-executor
candidate, **not official E1 control versus E1 R2**. `on/off` refers to that
historical experiment's observation mode, not the public E1 stats switch.
The complete historical source/control bundle is not published here.

| Historical CONN-R2 cell | Control B/flow | Candidate B/flow | Control allocations/flow | Candidate allocations/flow |
| --- | ---: | ---: | ---: | ---: |
| Direct off, 1 KiB | 58,891.75 | 59,013.50 | 329.00 | 300.97 |
| Direct off, 8 MiB | 407,624 | 434,344 | 11,091.00 | 11,824.38 |
| Direct on, 1 KiB | 60,851.25 | 55,935.50 | 343.13 | 313.75 |
| Direct on, 8 MiB | 404,060 | 437,740 | 11,103.63 | 11,829.63 |
| SS off, 1 KiB | 93,542.25 | 95,671.25 | 753.66 | 734.50 |
| SS off, 8 MiB | 1,840,575 | 1,477,903 | 46,553.13 | 36,382.00 |
| SS on, 1 KiB | 98,013.00 | 95,340.25 | 772.16 | 745.94 |
| SS on, 8 MiB | 1,840,190 | 1,456,477 | 47,012.13 | 36,383.00 |

The shared candidate really replaced two selected relay loops, but sustained
Direct cost increased while sustained SS cost fell. The record was one-process
allocation evidence, not stable timing, retained memory or a universal win.
The shared-executor delta added 119 production lines over its preceding R1
variant; the native MUX-child boundary remained source-blocked. This is why
E1 required contrasting paths, actual child admission and separate structural
versus cost conclusions rather than another successful two-socket copy test.

## What carries forward, and what does not

The historical sequence supplies counterexamples: facades can retain all old
work, framing primitives can conceal whole-path cost, scalar copy can hide native
capabilities, carrier compatibility can conceal old child execution, and a
high-level return can precede worker retirement. E1 addresses selected instances
of those counterexamples; it does not retroactively close every deferred row.

Full runtime DNS replacement, event retention, exact application routing,
Android/device behavior and whole-system scale remain outside E1. A historical
DNS readiness result says nothing by itself about cancellation of a context-free
lookup in a new preparation path. A historical child-close result says nothing
by itself about retained XUDP across carrier replacement.

Use [the atlas](CORE_ATLAS.md) for the broad source owner map,
[the E1 overlay](OWNERSHIP_MAP.md) for actual changed responsibilities,
[the E1 result ledger](E1_RESULTS.md) for quantitative and negative evidence,
and [the migration proposal](MIGRATION.md) for current open decisions. None of
this register's historical next-step text overrides the present RFC scope.
