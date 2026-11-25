# XDRIVE

xDrive carries an ordered byte stream in each direction. Use matching releases on
both peers. Drive uses slots; local, URL-template and S3 stores keep their WAL.
This repository is a review candidate based on the maintainer's fork, not a merge
of the current upstream branch.

## Drive protocol

The announcement names a table of file IDs and one reader-owned watermark for
**each direction**. IDs are allocated in batches. The first lap creates files
on first publication. Established sessions do not list files to find data:
sequence `n` maps directly to `slots[n % depth]`. If present, the announcement's
first payload is sequence zero, not an additional record.

Mode 1 carries up to 14 KiB in metadata, mode 5 a media body, modes 3 and 4
mean end and error. See "Transport model" below.

- **Write:** one goroutine batches caller input and assigns sequence numbers.
  Input is gathered for 25 ms; after idle, a small write has a 2 ms window.
  The planner uses up to 24 available inline positions; larger bursts can use
  media. There are at most 32 upload workers per direction and never more than
  the ring depth. For the eager window after a media upload starts (default 2 s),
  later bursts do not split into inline waves even if few uploads remain.
  Reuse requires previous local completion and cumulative remote credit.
- **Read:** idle polling focuses on the head. After a minute without a head,
  one bounded background probe at a time rotates through other slot descriptions
  to distinguish a gap from a genuinely idle peer. During activity, up to
  24 known descriptions are prefetched, with one metadata GET per worker at a
  time. Empty-slot polling reaches only four positions beyond the observed
  frontier (or head); new observations advance that frontier immediately.
  All media sizes may be prefetched; byte admission follows sequence
  order, bounded to 4 MiB per media connection and held until head promotion.
  Ordinary media has four HTTP permits per connection (capped at 64); head
  media has separate permits (up to four), including queued requests promoted
  to head. Both use the same connections; the head has its own frame allowance.
  A prefetched frame returns its local byte reservation when promoted, even if
  its body is still downloading. Completed successors retain theirs until promoted.
  Workers can finish out of order; one coordinator alone delivers bytes.
  Ordered delivery refreshes the eager timer; speculative body downloads do not.
- **Media:** frames through 1 MiB use one progressive GET; larger frames
  use up to four block ranges at once, capped by the media connection count
  and targeting at least 512 KiB of payload per range.
  If the first range returns a full HTTP 200 body, keep it and cancel the other
  ranges instead of downloading the full body four times. Validate every
  block's sequence tag, HTTP range/length and EOF. One retry can resume an
  incomplete span without delivering the same bytes twice. No media GET runs
  before discovering its frame description.
- **Close:** Close discards unread input, drains its writer and publishes END.
  It keeps verifying input and returning credit until it reads the peer's END,
  then flushes any remaining verified watermark. The peer may still have a full
  ring to drain after our writer finishes. Interrupt cancels instead.

Unlike v6, a unilateral graceful Close can time out if the peer never publishes
END. The one-minute watchdog tracks outbound progress until the local writer
finishes, then also counts successful inbound watermark writes during Close.
Receiving END alone does not close the outbound half.

## Transport model (Drive)

Each direction is a ring of `depth` Drive files plus one watermark file owned
by the reader. Sequence `n` always lives in `slots[n % depth]`.

1. **Gather.** The writer collects caller input for up to 25 ms (2 ms after
   idle for a single small write) or until the current frame size is reached.
   With 4 or more uploads in flight the writer is streaming: it keeps
   gathering while input keeps arriving, up to 200 ms or a full frame, and
   sends once input pauses for 25 ms, so a reply burst goes out as one frame.
2. **Frame size grows every round.** It starts at `segmentBytes` (512 KiB)
   and doubles after each round that filled a whole frame, up to 4 MiB (below
   Drive's 5 MB multipart limit). It halves (not below the start) when an
   upload waited more than 5 s for ring credit outside Drive cooldown.
   Cooldown freezes frame size instead of shrinking it: smaller frames spend
   more requests per byte. Routine credit takes 1-3 s; shorter waits only mean
   the writer is a ring ahead. Larger frames carry more bytes per position.
3. **Publish.** Up to 14 KiB goes inline in the file description (one PATCH;
   an idle writer may split a burst into up to 24 inline frames, a streaming
   writer never does, because the reader finds only about 24 frames per round
   trip and 14 KiB frames would cap throughput near 1 MB/s). Larger frames
   are one multipart PATCH: the description holds `XDRVSL03`, sequence, mode
   and length; the body is blocks of an 8-byte sequence tag followed by up to
   256 KiB of data. At most 32 uploads and
   4 MiB of unfinished uploads per media connection run per direction (one
   frame may exceed it alone). Media requests rotate per request over
   the media connections (XMUX `maxConnections`, default 4): one Google
   connection carries only a fraction of a link (a measured single-connection
   client download averaged ~0.22 MB/s). The byte bound,
   about one 4 MiB frame per connection, bounds payload bytes, not request count
   or duplicated network traffic. Head reads have separate HTTP permits, not
   extra connections. Bounded look-ahead overlaps service latency between frames
   instead of forcing one large frame to finish before starting the next.
4. **Discover.** The reader polls the head slot's description (25 ms while
   active; no duplicate hedged GET) and prefetches up to 24 descriptions. Slots
   beyond the observed frontier plus four wait without polling; the head always
   polls, and the existing gap probe still covers otherwise unobserved gaps.
   Bodies of all sizes download ahead within the byte budget, admitted in sequence
   order so distant successors cannot reserve it before nearer frames. The head
   bypasses that budget, and a queued media request switches to the reserved
   HTTP permits when promoted. Admission waits for the previous frame's ready
   signal, not its completed download.
   Promotion releases any existing look-ahead reservation, not remote ring credit.
   Thus a head discovered in advance no longer consumes both its own allowance
   and the successors' budget. Cancellation also releases each reservation once.
5. **Fetch.** Media up to 1 MiB uses one streaming GET; larger frames use
   two to four block-aligned ranges with the default four connections,
   targeting at least 512 KiB per range and reaching four ranges at 2 MiB.
   They start together for each admitted frame: every block carries
   the sequence tag, so each range rejects an older lap by itself (before,
   later ranges waited for the first one, costing a second time-to-first-byte,
   ~1 s, per large frame).
   A full HTTP 200 response to the first range replaces all ranges; the others
   are canceled before any of their bytes are delivered. Bytes are delivered
   in 32 KiB pieces as they arrive. One retry resumes
   after the delivered bytes; the declared length and exact EOF are checked.
6. **Credit.** The reader writes its cumulative watermark every `depth/6`
   frames or 1.5 s. A slot is rewritten only after that credit. Frame size
   changes are logged at debug level (`xdrive frame size A -> B`), as is
   each media frame: `xdrive upload seq` (credit wait, PUT time) and
   `xdrive read seq` (time to find, admission/byte-budget wait, body time).
   `xdrive watermark seq N put P` records successful ACK publications, and
   `xdrive credit seq N ack A` records the writer observing newer credit.
   `xdrive span seq` records range status, wire bytes, time waiting for headers
   (including permit wait, retries and service latency), and time after headers.
   `xdrive span retry seq` records emitted payload bytes and the error that
   triggered the one stream resume; successful final reads can hide this error.
   `xdrive request retry seq` exposes retries before headers or buffered success.
   `xdrive cooldown D` records the shared delay after quota/service rejections.

There are no CRCs: integrity relies on TLS, the length checks and the
per-block sequence tags, and VLESS encryption authenticates the payload. Both
peers must run this release (`XDRVSL03` is not readable by older peers).

## Implementation and trade-offs

`slots.go` contains the frame codec, ring announcement and
publication, outbound writer, and inbound reader, in that order. One reader
ACK loop owns both periodic and final watermark writes. `drive.go` owns OAuth,
Drive requests, quotas, object CRUD, ID allocation, and media verification.
`client.go` is shared with the URL-template and S3 transports. It retains the
configured TLS/QUIC dial path, socket and mask settings, stall timeout, HTTP/2
keepalive and XMUX leases. Drive uses distinct metadata, priority and media
pools. Metadata and priority select a lease once per session; media rotates
per request across one-connection XMUX lanes instead of random selection
(the upper `maxConnections` bound, default 4). Request/reuse/lifetime limits
still apply within each lane; the media byte budget follows the same count.
Peer-supplied IDs are checked for valid syntax and uniqueness. An existing
object must match its announced session name and configured parent on first
use. Keep the folder private to the two peers; these checks do not authenticate
a writer who already has access to the session folder.

Removed from the larger implementation: custom spare-connection probes,
background connection/token/ID keepers, eager spare rings, duplicated media
rescue and latency controllers, and detailed per-burst telemetry. A Drive ID
allocation failure now fails the dial explicitly instead of switching to WAL.
Announcements are also created with reserved IDs. After a lost reply, read back
the exact slot, watermark or inline announcement description; for a media
announcement also compare the complete body. Never replay an ambiguous write.
If an announcement was already deleted, a 404 is not proof of delivery. If confirmation fails,
the original write error is preserved. Graceful close reports final ACK errors. These are
behavior differences, not just source rearrangement. Historical throughput
and tail-latency measurements from the larger version are **not** measurements
of this one. Empty Drive announcements are rejected rather than opened as WAL
sessions. Uploads and OAuth refresh requests do not follow redirects.

## Failure handling and verification

A fatal upload, media-read or watermark error cancels both halves of a Drive
connection with the first error as the cause. A normal END only closes its
own direction. Readers reject an overwritten sequence; a writer verifies that
a cumulative ACK cannot cover its own unpublished sequence before reusing a slot.
Buffered GETs can retry an interrupted response body. Streamed media resumes
by delivered offset, and an ambiguous mutation is not replayed. Listing and ID allocation
use the app-data space when `remoteFolder` is `appDataFolder`. Drive announcement
age is seeded from `createdTime` and the listing response’s `Date`, so an expired
announcement does not become fresh when a listener restarts. This is not a
persistent exactly-once claim within the TTL. An unprovable gap (no subsequent
frame) still looks like an idle connection; use a read deadline when one is required.

Transient OAuth transport and service failures can retry before any file operation
is sent. All Drive file attempts, including retries, reserve spaced starts at
80 requests/s per shared storage instance, across sessions and lanes. Two peers
at this ceiling use about 9,600 attempts/minute against the observed 12,000
quota, leaving headroom, not a guarantee for other processes or profiles sharing
the project. Queued requests recheck cooldown before proceeding. Cancellation
may leave unused pacing turns, but releases the request permit.
Drive rate-limit responses and 503 responses with `Retry-After` apply a shared
exponential cooldown (jittered 2–30 s base), reset after a minute without a new
cooldown. Concurrent rejections in one cooldown do not escalate independently;
a longer `Retry-After` still extends it. A 503 never permits mutation replay.
Quota retry logs omit the repetitive JSON error body. Cleanup excludes
folders and Google-native objects. Conflicting regular files with the exact same
announcement name are not selected or deleted as a group; resolve them manually.
The admission deadline also applies while loading or binding the announcement,
not to the resulting connection. Use a dedicated folder for one listener and its clients.

### Verification of this candidate

This version descends from the v7 candidate, which began as a literal merge
of v6's four slot files. The per-block CRCs, the checksum table and the
checksummed media reader are gone here. Retry safety rules remain, but media
reading, request pacing and shared cooldown now differ from v6.

The quota refinement passes `gofmt -l`, `go build ./...` and xdrive `go vet`.
A Python virtual-clock model checks pacing, cancellation, cooldown extension,
Retry-After, frontier progression and frame-size freezing; it is not a Go
HTTP/race workload or a live-Drive throughput benchmark. No test files are added.

The receive-credit refinement releases local look-ahead bytes on head promotion;
watermarks still advance only after verified ordered delivery and exact EOF.
No budgets, request limits or wire-format fields changed. Validate with slow
heads, completed successors, cancellation and unequal Close workloads under race
detection before attributing a sustained-speed improvement to this change.

The following are **Python model checks against the v7 candidate, not runs of
this Go package**:

- At ring depth two, the v6 and candidate models each delivered 1,096,163
  bytes in each direction, with separate deterministic payloads. All received
  bytes matched. The fixture crossed the inline, prefix and multi-range
  thresholds. It cut 16 model responses after a complete block plus 17 bytes;
  eight resumes simulated a server ignoring Range. No duplicated bytes.
- Seven scripted quota/status cases per version checked the retry decision for
  429, rate-limited and ordinary 403, and 500/503, including a 503 with
  Retry-After on a mutation. Delays used a virtual clock, not HTTP or Drive.
- A small exhaustive close model let the empty writer publish END before the
  opposite writer finished four data frames. Three v6 terminal states could
  not progress; none of the candidate's 45 reachable states was stuck. This
  is a bounded ordering check, not a goroutine race test.

**Release gates:** the candidate workspace had no Go 1.27 or `gofmt`, so the
model checks above did not build it. This snapshot was formatted with `gofmt`
(and the repository's `vformat`/`vprotogen` checks), vetted and built with the
`go.mod` toolchain; it has not been run against an HTTP mock in Go, with a
`-race` workload, or against live Drive. The inventory below is the physical
post-`gofmt` count. No XDrive test file is shipped.

For deeper assurance, in a disposable checkout, run the same depth-two
transfers against v6 and the candidate with a fault-injecting Drive HTTP mock
under `go test -race`: compare both byte streams, truncate media responses,
return 429/403/503, and close both peers with unequal outstanding writes.
Also check one-sided Close, final ACK failure and Interrupt. A plain
`go test -race` without a workload is not a concurrency test. Repeat the
bidirectional transfer with a dedicated live Drive folder.

## Drive source budget (physical lines, including comments and blanks)

Count all three implementation files in full, including the shared HTTP client.
For mixed files, the following inventory charges whole integration functions
where practical, including generic code within them. The remaining WAL/backend,
protocol-wide listener, configuration and generated protobuf code is shared or
unrelated, not a hidden second Drive implementation. Ranges below are inclusive
for this snapshot, relative to `transport/internet/xdrive` unless marked `infra/`.

| Source | Inclusive lines counted | Count |
|---|---|---:|
| `drive.go` | whole file | 1056 |
| `slots.go` | whole file | 879 |
| `client.go` | whole file | 537 |
| `conn.go` | 65–79, 185–217, 219–244 | 74 |
| `xdrive.go` | 9, 139–223, 276, 323–413, 479–490, 492–512, 538–572, 588–670 | 329 |
| `params.go` | 75–91 | 17 |
| `storage.go` | 9, 20–24, 36–63, 65–75 | 45 |
| `storage_lease.go` | 26–32, 42–45, 47–63, 69–70, 89, 157–162 | 37 |
| `infra/conf/transport_method.go` | 1020–1027, 1037, 1045–1050 | 15 |
| `infra/conf/transport_internet.go` | 266–275 | 10 |
| **Total** | | **2999** |
