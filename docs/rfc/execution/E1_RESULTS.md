# E1: detailed results, rejected choices and measured costs

## Status and evidence levels

This is the full result ledger behind the shorter [validation guide](VALIDATION.md).
It restores saved positive, negative and quantitative results; no experiment
was rerun merely to expand the documentation. E1 R2 supports further staged
work within S1-S4/P1/M1. That is an experiment verdict, not upstream approval,
full migration, a release verdict or a general performance result.

The official control is
[`3519dfec`](https://github.com/XTLS/Xray-core/commit/3519dfecbd65022ba71d9bc73e94063d0cbc8636).
The exact original R2 source is public in
[`29119405`](https://github.com/svlavr/Xray-core/commit/29119405bcc03a77afa5bf9fca439c3a154bcaf9);
its hashes and the formatting-only public changes are in
[the manifest](source-manifest.json). E1 R1 used the same official base but a
different experimental source snapshot. It is not the older CONN-R1 series.

There are three distinct levels of evidence:

1. **Publicly reproducible current checks:** the in-tree tests and portable
   guarded stream runner, with exact commands in VALIDATION.
2. **Saved host measurement receipts:** aggregate samples published below,
   with workload, source identity and measurement boundary. They are not new
   CI results or fresh executions of this documentation revision.
3. **Historical rejected implementations:** reasons and scoped observations
   retained from earlier reports. The complete E1 R1 and older prototype source
   bundles are not all in this public branch; their exact independent rerun is
   not promised by the existence of a table.

## Why six cells were necessary

| Cell | Architectural question | Actual discriminator | Limit |
| --- | --- | --- | --- |
| S1 SOCKS/Freedom | Can a direct stream use common execution without gratuitous buffering? | Real TCP, native guard, stats on/off and native IO regression cases | Baseline SOCKS already avoided the crossed dispatcher pair; no such pair can be counted as deleted here |
| S2 Trojan/Freedom | Can retained handshake input, sniffing and independent EOF observation coexist with shared completion? | Coalesced header/payload, zero-buffer policy, EOF during preparation and blocked writes | Independent read-ahead remains for its demonstrated purpose |
| S3 SOCKS/SS AEAD | Does the boundary handle framed startup and silent clients? | Real AEAD peer, server-first response before late payload, preparation interruption and terminal-buffer tests | Framing remains protocol-local; this is not SS2022 |
| S4 SOCKS/ordinary VLESS | Does a second startup behavior fit without a protocol option in the executor? | Real peer, timed startup and blocked-header cancellation | No Vision/raw transition, reverse or special command proof |
| P1 SOCKS UDP/Freedom | Can an association outlive a routed leg and retain packet addressing? | Two destinations, empty/large datagrams, failed leg then route reselection, blocked reply retirement | Selected source has exclusively owned real write deadlines; not arbitrary shared devices |
| M1 VMess MUX TCP children | Can a logical child use common execution without owning the carrier? | Two native children; close one while sibling progresses; pressure/duplicate IDs/stalled physical writer | Carrier Link and packet/XUDP branches remain; eight-child cap is experimental |

The extra server used as a framed peer is not counted as migrated merely
because the front path is native. The native guard checks the selected front
handler. M1 has its own decoded-child guard; a test that only used a MUX carrier
with old dispatched children would not satisfy this cell.

## Failure and correction sequence

| Finding | Why the first result was insufficient | Correction or disposition |
| --- | --- | --- |
| Removing independent reading delayed EOF behind a blocked write | Direction-only policy could start at a different time | Keep producer EOF observable independently; join the final accepted write separately |
| First E1 packet leg ended the association on failure | Payload/address success hid changed reopen/routing semantics | Association owns one replaceable leg; retire, cancel, interrupt and join it before reselection |
| Source reply write could stay blocked during leg retirement | Reusing a deadline before old callbacks/writer joined could affect the next leg | One exclusive write/deadline owner; generation-scoped callbacks; join before reset |
| First read-ahead allocated payload arrays per read | The allocation cost grew with transferred payload | Pool fixed-size blocks with explicit producer/queue/consumer/release custody |
| Mutex-only carrier serialization did not interrupt a blocked physical write | Child cancellation could stall END and join | Carrier writer expiry and carrier-owned physical interruption precede join |
| Stream startup or raw transfer hid required progress/idle behavior | Successful payload copying alone did not preserve policy | Focused preparation/progress/EOF regression corrections; no blanket raw-path claim |
| A prior splice trace belonged to an earlier stream snapshot | Source changes invalidated using that trace as final-source proof | Keep the trace historical; do not attribute it to the corrected candidate |
| Fixed 50 ms allocation settlement did not join all payload work | Control/candidate could be measured at unequal teardown points | Use equivalent test-only admission/completion hooks and join payload workers; count native timers separately |
| Original TestTagsCache race reproduced on pristine control | A wider race run was not all green | Preserve original test and report separately; do not weaken it to accept E1 |

Context-aware retry, the temporary UDP recursive-close repair, real packet
socket capability, address mapping and noise-delay cancellation are neighboring
correctness work. Their usefulness does not itself prove the need for a new
execution architecture. Arbitrary context-free DNS cancellation remains open.

## R2 alternatives and why the simpler mechanisms won

| Candidate | Ownership/lifecycle | Memory/state and complexity | Decision in the selected scope |
| --- | --- | --- | --- |
| Association-owned deadline and one leg generation | Interrupt old reply; join old callbacks/writer before deadline reset | One current leg and reply worker, no destination map or packet queue | Selected for the real SOCKS source |
| Context on every packet write | Still requires a real interruption primitive | Per-operation callbacks or broader endpoint changes | Not needed to solve this source's demonstrated problem |
| Queued/dropped replies | Separates source writer from leg | Another queue/worker, overflow rules and changed pressure behavior | Rejected for this slice |
| New source socket per leg | Replaces the association's own identity | New resource rather than leg retirement | Incorrect boundary |
| Pooled fixed-size read-ahead chunks | Explicit exclusive custody and release after join | Storage follows occupancy; reuse without new public buffer ABI | Selected |
| Per-source ring | Must handle wrap, partial reads, terminal errors and unlimited growth | Reserved capacity and additional state transitions | No demonstrated advantage over the smaller pooled correction |
| Mandatory MultiBuffer storage | Retains native storage reuse but couples generic input to codec operations | Does not itself eliminate consumer copying | Not selected as the common ABI |

No LOC target selected these choices. The two rejected R1 mechanisms were
corrected in the existing experiment, without a scheduler, destination registry
or mass protocol migration.

## Regression families behind the PASS labels

| Property | Public test anchors | What the anchor does not prove |
| --- | --- | --- |
| Pending bytes/error replay | exchange: TestInputReplaysDataAndPendingError; TestAheadPartialReadsKeepPooledDataAndTerminal | Every codec implementation |
| Early EOF versus blocked write | exchange: TestAheadObservesEOFWhileConsumerBlocked; TestIngressEOFPolicyRunsDuringPreparation; TestPeerEOFDoesNotPrecedeFinalWrite | Remote application delivery |
| Directional timeout and join | exchange: TestRunAbortJoinsBothDirectionsAndPreservesFailure; TestResponseEOFPolicyAbortsAndJoinsBlockedFinalUplink | Universal whole-instance shutdown |
| Pool release and isolation | exchange: TestAheadAbortJoinReleasesPartiallyConsumedQueue; TestAheadConcurrentConsumersOfPoolNeverShareLiveStorage | Immediate OS memory reclamation |
| Preparation interruption | Shadowsocks/VLESS: TestPreparationIdleClosesBlockedHeader; retry: TestContextCancelsBackoffWait | Cancellation of context-free DNS |
| Leg replacement | exchange: TestE1PacketLegRetiresAndAssociationRoutesAgain; scenarios: TestE1PacketSocksReroutesAfterFailedLeg | All UDP association policies |
| Stale callbacks/deadlines | exchange: TestPacketRetireJoinsBlockedReplyBeforeDeadlineReset; TestPacketDeadlineResetFailureAbortsAssociation | Deadlines shared with unrelated writers |
| Distinct policy clocks | exchange: TestPacketResponseTimerIgnoresRequestsAndIdleCanBeShorter; TestPacketZeroIdleIsImmediateNotDisabled | One universal idle policy |
| Late/failed preparation | exchange: TestPacketPreparationTimeoutClosesLateLegAndKeepsSource; TestPacketFailedPreparationDoesNotCountTransfer | Arbitrary custom handlers |
| No ambiguous replay | exchange: TestPacketFailedLegWriteIsNotReplayed | Exactly-once network delivery |
| Endpoint validity | proxyman: TestPacketRejectsMalformedEndpointBeforeAddressWrapping; TestPacketPrepareErrorAbortsReturnedResource | All external endpoint contracts |
| Native packet path | scenarios: TestE1PacketNativeSocksFreedomAssociation | TUN/WireGuard/MASQUE/XUDP migration |
| Child isolation and serialization | scenarios: TestE1VMessNativeMuxChildren; mux: TestE1CarrierSerializesOwnedFramesAfterChildCancel; TestE1ChildInputPressureIsLocal | Arbitrary production MUX concurrency settings |
| Identity and carrier abort | mux: TestE1DuplicateChildIDCannotOverwrite; TestE1StalledCarrierCancellationClosesAndJoins | Reverse or retained-XUDP correctness |

Sources: [exchange tests](../../../transport/exchange),
[proxyman tests](../../../app/proxyman/outbound), [MUX tests](../../../common/mux),
[scenarios](../../../testing/scenarios), [SOCKS](../../../proxy/socks),
[Shadowsocks](../../../proxy/shadowsocks), [VLESS](../../../proxy/vless/outbound).
The exact selected commands, source checks and independently reviewed
publication boundaries are recorded in VALIDATION rather than inferred from
the number of test names.

## Isolated read-ahead allocation measurements

Saved Windows amd64, Go 1.27.0 measurements: identical
BenchmarkAheadOwnedTransfer workload, two runs of 200 iterations, including
consumption, Stop and Join. R1 uses the earlier Ahead implementation via a
test-only overlay. [Numeric receipts](evidence/buffer-results.json).

| Payload | R1 B/op | R2 B/op | R1 allocations/op | R2 allocations/op |
| --- | ---: | ---: | ---: | ---: |
| 1 KiB | 34,026-34,029 | 1,229-1,319 | 15 | 13 |
| 1 MiB | 1,091,413-1,091,519 | 4,035-4,094 | 310 | 46-48 |

This establishes removal of the per-read payload allocation in this owner,
not a whole-core speedup. Pool cold allocation and retention remain. The old
R1 implementation is not distributed in this RFC, so the table is a saved
comparison, not a claim that the public candidate alone reproduces both sides.

## Occupancy and retained memory

The saved pressure probe holds 32 Ahead producers, a 64 KiB queue threshold,
16 KiB reads and paused consumers. Automatic GC is disabled only during the
probe; explicit GC phases reveal retention while owners remain reachable.
Both revisions reach **160 queued chunks**, **2,621,440 queued bytes**, plus
**524,288 producer-held bytes**: **3,145,728 active payload bytes**, or 96 KiB
per owner. R2 did not secretly increase or eliminate the existing threshold
overshoot. Zero/unlimited policies keep their stated behavior.

| Snapshot, 32 owners | R1 | R2 |
| --- | ---: | ---: |
| Owner-held payload after abort + Join | 2,621,440 B | 0 B |
| Active Go HeapAlloc delta | 3,241,760 B | 3,234,832 B |
| After first forced GC, owners retained | 2,691,856 B | 3,226,800 B |
| After second forced GC, owners retained | 2,691,856 B | 73,464 B |
| After releasing owners and another GC | 43,312 B | 48,376 B |

These are HeapAlloc deltas including metadata, not RSS. R2 returns storage to
a pool, so its first-GC retention can exceed R1. The observed second-GC pool
eviction is not a wall-clock reclamation guarantee. R1's queued payload remains
reachable through the retained canceled owner; R2's owner no longer owns it.

P1 separately holds one 65,535-byte request scratch and one lazily allocated
reply scratch of the same size. The reply storage is reused only after leg
join. Framing/socket/kernel/legacy adapter buffers are additional, not included
in a claim of zero packet memory.

## Matched complete payload-flow costs

The saved R2/control series contains **32 interleaved process invocations**:
four paths, 1 KiB/1 MiB payloads, two variants and two samples. Each invocation
uses three measured flows after one joined warmup. Thus each table entry has
six measured flows. Statistics were off. Values are medians of sample averages;
they are not p90/p99 distributions. Sources:
[all 32 aggregate samples](evidence/r2-flow-samples.json) and
[16 variant/cell summaries](evidence/r2-flow-summary.json).

Equivalent test-only overlays reserve work before goroutine creation and join
TCP setup/callbacks, asynchronous dispatch, task.Run children, the candidate
executor, local echo handlers and socket close. Native ActivityTimers are
counted separately. The historical cost build did not install the native guard;
functional guarded checks are separate evidence. The public guarded race probe
must not be used as if it were this unguarded, non-race allocation workload.

| Path | Payload | Control B/flow | R2 B/flow | Interpretation |
| --- | --- | ---: | ---: | --- |
| SOCKS/Freedom | 1 KiB | 54,872 | 58,324 | Higher candidate bytes |
| Trojan/Freedom | 1 KiB | 82,108 | 106,924 | Higher candidate bytes |
| SOCKS/SS AEAD | 1 KiB | 90,407 | 121,369 | Higher candidate bytes |
| SOCKS/VLESS | 1 KiB | 75,539 | 113,336 | Higher candidate bytes |
| SOCKS/Freedom | 1 MiB | 1,132,308 | 1,134,121 | Similar, slightly higher candidate bytes |
| Trojan/Freedom | 1 MiB | 1,287,584 | 1,208,665 | Lower candidate bytes |
| SOCKS/SS AEAD | 1 MiB | 1,312,396 | 1,385,935 | Higher candidate bytes |
| SOCKS/VLESS | 1 MiB | 1,181,515 | 1,205,249 | Higher candidate bytes |

All per-cell allocation counts, instrumentation counts, remaining timer counts
and raw completion-time aggregates remain in the JSON; unfavorable cells are
not discarded. Instrumentation cost was included in both variants, with isolated
calibration of one allocation/24 bytes per payload event and one allocation/16
bytes per timer event. No estimated correction was subtracted to create a gain.

Control teardown often reaches payload completion only after native directional
policy expiry, about 2-3 seconds in this workload. A shorter completion time is
therefore **not a throughput improvement**. Some candidate samples still had
timers at payload completion. This boundary is not finalization of every runtime
resource. Earlier R1 whole-flow values used a 50 ms settlement sleep and cannot
be placed beside this table as an equal-lifecycle comparison.

The published overlay generator and probe can be used to construct a fresh
same-base control/candidate cost run without the guard; the commands below are
a reproduction recipe, not a new measurement result from this docs update:

```sh
git worktree add --detach ../xray-control 3519dfecbd65022ba71d9bc73e94063d0cbc8636
python testing/executionprobe/overlay.py . ../execution-cost --label candidate
python testing/executionprobe/overlay.py ../xray-control ../execution-cost --label control
go build -overlay ../execution-cost/candidate-overlay.json -o ../execution-cost/candidate ./testing/executionprobe/probe.go
# Run from ../xray-control, referencing the RFC's probe.go by its absolute path:
# go build -overlay /absolute/execution-cost/control-overlay.json -o /absolute/execution-cost/control /absolute/rfc/testing/executionprobe/probe.go
# Alternate candidate/control, then reverse the order for sample 2:
../execution-cost/candidate -scenario socks -size 1024 -n 3 -warmup 1
../execution-cost/control -scenario socks -size 1024 -n 3 -warmup 1
```

Repeat the same two-sample recipe for socks/trojan/ss/vless and 1024/1048576
bytes, without `-race`, `-stats`, native_guard.go or additional greeting/sniff
flags. Preserve the raw outputs and actual Go/OS/CPU/source identity. Changes
in runtime, machine or instrumentation require a new comparison, not a promise
to reproduce the identical numeric values above. The historical E1 R1 Ahead
comparison requires its separate unavailable-in-this-branch control source.

## Complexity after identifying owners

The original R2 specimen added 3,326 and removed 546 production lines against
official source: net +2,780, across 55 source/test files overall. R2 versus
rejected E1 R1 added 437 and removed 251 production lines: net +186 across eight
production paths. These include code movement and compatibility; they are not
net retired runtime responsibility. Public formatting/docs/probes are separate.

The actual deletion/bypass ledger is in [OWNERSHIP_MAP](OWNERSHIP_MAP.md).
Trojan's relay body is deleted, while shared old Process bodies and getLink
remain for other callers. MUX adds carrier/child queues. Native buf leaf helpers
remain. Only after those distinctions can LOC describe maintenance cost.

## What this result selects and leaves open

The selected direction can represent direct/framed streams, one replaceable
SOCKS packet leg and a native logical child without making the protocol own a
second general executor. That is the positive feasibility result. The result
does not prove optimal memory cost, universal packet cancellation capability,
full MUX/Reverse/XUDP coverage, Vision close transitions, context-free DNS
cancellation or a complete way to remove all legacy callers. Those are explicit
future design and implementation gates, not missing rows silently marked PASS.
