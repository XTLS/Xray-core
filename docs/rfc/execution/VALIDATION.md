# Validation matrix and reproduction

## Status

Bounded host evidence, not a full-core or release verdict. The R2 source/test
files are identified by [source-manifest.json](source-manifest.json), with
CRLF normalized to LF before SHA-256. It retains both the exact original R2
source commit/hashes and the public hashes after upstream formatting. The
formatting-only commit changes import grouping and whitespace, not runtime
behavior. Original upstream tests/fixtures and
go.mod/go.sum are unchanged from official `3519dfec`.

The original R2 local runs used Go 1.27.0 on Windows amd64 and WSL Linux amd64.
Their saved package outputs are evidence for that source, but do not retain
every exact command. Commands below define the public reproduction selection;
they must not be presented as recovered historical invocations.

## Six discriminating cells

| Cell | Actual path | Checks and limits |
| --- | --- | --- |
| S1 | SOCKS TCP -> Freedom | Real socket peer, native admission guard, stats off/on; native progress/vector/splice-related unit checks are separate |
| S2 | Trojan TCP -> Freedom | Coalesced header/payload, sniffing enabled, zero-buffer policy; EOF versus blocked final write tested separately |
| S3 | SOCKS -> Shadowsocks AEAD | Real framed peer, server-first response then payload; preparation failure/cancellation tested separately |
| S4 | SOCKS -> ordinary VLESS | Real peer and timed startup; no Vision, encryption extensions or special commands |
| P1 | SOCKS UDP -> Freedom legs | Multiple destinations/empty/large datagrams; failed leg followed by new routing on the same association; retirement/deadline failures |
| M1 | VMess MUX -> two native TCP children | Sibling-safe close, native guard; pressure, duplicate ID, frame ownership and stalled-carrier abort/join |

P1/M1 native guards are in [packet scenarios](../../../testing/scenarios/packet_e1_test.go)
and [MUX scenarios](../../../testing/scenarios/mux_e1_test.go). S1-S4 use
[the standalone probe](../../../testing/executionprobe/probe.go) and
[native guard](../../../testing/executionprobe/native_guard.go), with a test-only
Go overlay. An unexpected old Dispatch call fails. The selected handler must
admit and return both flows (one warmup plus one test); enabled counters must
be positive. This is not a claim that the extra remote framed peer is migrated.

## Reproduce from the repository root

Requires Python 3, Git, Go 1.27 and the normal Go race-detector toolchain for
the host (including its C compiler). Tests use local loopback only. Run serially.

```sh
python testing/executionprobe/validate.py audit
python testing/executionprobe/validate.py focused
python testing/executionprobe/validate.py streams
python testing/executionprobe/validate.py compile
```

`all` runs these four checks. The focused selection executes all tests in the
exchange, packet adapter, SOCKS, MUX, retry and prepared protocol packages;
proxyman selects the added Packet/Stream cases and scenarios select TestE1.
It is not a whole-tree race pass. Compile uses `go test ./... -run '^$'`, which
compiles tests but does not execute them. Original tests are neither edited nor
disabled; the original proxyman TestTagsCache race was observed on the pristine
control too, and is outside this focused result.

The public stream runner generates overlays and builds in a temporary directory;
it does not edit repository source. Its lifetime hooks are reserved before
goroutine launch. It joins payload setup/inbound/dispatcher/task/echo workers
and local sockets; native activity timers are counted separately. Handler return
alone is not the join proof. Probe Go files use the `ignore` build tag and are
compiled explicitly, so instrumentation never enters normal Xray builds.

The stream command combines the previously separate joined probe and native
guard under race detection. It is a functional check. Allocation/timing fields
from this instrumented run are deliberately not reported as a benchmark.

## Memory and cost boundary

Read-ahead block custody/partial reads/error order/abort cleanup and concurrent
pool users have in-tree regression tests. The candidate-only storage probe and
benchmark are available without historical source:

```sh
go test ./transport/exchange -run '^TestAheadRetainedStorageProbe$' -v -count=1
go test ./transport/exchange -run '^$' -bench '^BenchmarkAheadOwnedTransfer$' -benchmem
```

They do not establish a whole-core speedup. [E1_RESULTS.md](E1_RESULTS.md)
preserves the saved numeric comparisons, including higher short/framed-flow
cost, workload and lifetime boundaries, sample counts, pool retention and
negative findings. Aggregate JSON samples are published with the report.
Historical R1 source bundles are not all part of this package; those tables
are saved host evidence, not a promise of independent reproduction from the
current candidate alone. No benchmark was rerun just to restore this evidence.

The earlier [64-row research matrix](EXPERIMENT_MATRIX.md) is distinct from
the six E1 cells. Its deferred and rejected results remain visible; they are
not counted as E1 PASS or evidence that all of Xray has been migrated.

## Reuse of existing public evidence

The public fork was inspected before selecting these checks. Existing branches
did not contain this E1 R2 source. Successful platform builds at
[`addee59`](https://github.com/svlavr/Xray-core/actions/runs/35532608709),
[`be922ec`](https://github.com/svlavr/Xray-core/actions/runs/36090159345) and
[`ce5ae09`](https://github.com/svlavr/Xray-core/actions/runs/36329068671)
are results for different sources. Their test runs were not wholly green:
[first](https://github.com/svlavr/Xray-core/actions/runs/35532608688),
[second](https://github.com/svlavr/Xray-core/actions/runs/36090159284),
[third](https://github.com/svlavr/Xray-core/actions/runs/36329068690).
These supply workflow/scenario context only, not a passing E1 receipt. The local
R2 manifest permits reuse of its unchanged source evidence; the newly portable
probe still needs its own execution check.

## Unproven boundaries

All-protocol behavior, full upstream test execution, Android/device execution,
external-network interoperability, production MUX limits, Vision/raw phase
changes, Reverse/retained XUDP, arbitrary custom handlers and context-free DNS
cancellation are not established. Queue/Link acceptance is not physical remote
delivery. Native timers can remain at payload completion. Compatibility adapters
require cooperation with cancellation/interruption.

## Public-package checks performed on 2026-09-27

- Windows amd64, Go 1.27.0: `audit`, `focused` and `streams` passed; `compile`
  passed after the formatting-only correction.
- WSL Linux amd64, Go 1.27.0: the new portable `streams` check passed.
- All eight guarded stream invocations passed on each host: four paths with
  stats off/on, one warmup and one measured functional exchange per invocation.
  Every guard reported two admissions, two returns and zero legacy Dispatch.
- Linux focused race and Linux whole-tree compilation are reused from the unchanged
  local R2 source evidence, not presented as new public-package executions.
  Original tests/dependencies, the original R2 source commit and the public
  formatted files are checked by `audit`.
- Independent publication review found no blocker; its request to enforce an
  exact export allowlist is incorporated into `audit`. This is not a new full
  runtime review or an upstream approval.
- Upstream vformat passed on an LF-normalized export. The Windows worktree's
  CRLF-only reports were separated from the actual import-group/whitespace
  corrections. Original upstream files were not reformatted. Functional checks
  above preceded the formatting-only correction; no behavioral change was made.

No full platform build matrix, whole-tree race suite or comparative benchmark
was rerun for packaging. The exact public revision is recorded in the Draft PR;
any automatically scheduled upstream/fork CI has its own status and scope.

The subsequent documentation expansion restores the historical register, atlas,
peer comparison and numeric receipts. It does not change the 55 R2 source/test
files or their manifest hashes. The audit's publication allowlist is extended
only for those documents and aggregate data; Go tests are not rerun for prose.
