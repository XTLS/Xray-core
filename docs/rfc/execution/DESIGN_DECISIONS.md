# Decisions tested by E1

## Status

These choices explain the executable specimen. They are not requirements for
upstream to adopt its exact interfaces. Alternatives remain open where the
experiment does not discriminate between them.

## Independent read-ahead and completion

Removing independent reads changes when EOF becomes visible if the peer write
is blocked. That can delay directional policy transitions. The specimen keeps
read-ahead where needed and separates producer EOF from delivery of accepted
queued input and completion of the final local write. It does not impose the
same queued topology on every endpoint.

R1 allocated a fresh payload array for each read. R2 uses pooled 16 KiB blocks
with explicit custody: producer -> accepted queue -> consumer -> pool. Abort
joins the producer before releasing remaining storage. A chunk cannot be reused
while either party can access it. This avoids a new mandatory buffer ABI.

A per-source ring would add wrap/growth/terminal state and reserve unused
capacity. A mandatory MultiBuffer representation would couple the boundary to
codec buffer operations without removing the final consumer copy. Neither was
needed to correct the demonstrated allocation problem.

Existing capacity semantics remain: a 64 KiB threshold can hold five 16 KiB
queued chunks plus one producer block, or 96 KiB of active payload per owner.
Zero allows the native one-chunk handoff behavior; negative means explicitly
unlimited buffering. Pool retention is additional to live queue occupancy and
does not promise immediate return of memory to the OS.

## UDP association versus routed leg

The rejected first form ended the source association when the outbound leg
ended. The corrected form keeps one replaceable leg, routes its first datagram
afresh and joins its retirement before another generation uses source writes.
No per-destination map or native packet queue is needed for the selected case.

Using the source socket's real write deadline permits interruption of a blocked
reply. This requires exclusive ownership of its writes/deadlines. A context
parameter on every WritePacket would still need an actual interruption primitive;
a reply queue would add a worker and change pressure/drop semantics; replacing
the source socket would break association identity. Missing/failed deadline
capability is not silently treated as success.

The reply scratch is reused only after join. The executor owns one request
array and at most one lazily allocated reply array of 65,535 bytes each. Socket,
framing and compatibility buffers are separate. Ambiguous datagrams are not
automatically replayed. Response-only expiry is distinct from Freedom idle.

## MUX child versus carrier

Concurrent logical writers need frame serialization. E1 places it at the
carrier, with child-local input queues and a reserved control budget. It does
not claim queues can be eliminated or that changing pipe to channel is progress
by itself. Duplicate live/closing IDs are rejected; reuse waits for the old
END acknowledgement at the retained Link boundary.

The specimen permits eight native children, eight input frames per child,
32 carrier jobs and 16 data permits. These are explicit experimental bounds,
not proposed universal production settings. Child admission/pressure and
carrier failure have distinct error/close behavior. Reverse, retained XUDP and
arbitrary concurrency settings need further evidence before production adoption.

## Compatibility and neighboring fixes

Legacy projection remains a named edge. The packet adapter owns private pipes,
cancellation and join; it cannot make an uncooperative custom handler cancellable.
Stream compatibility similarly must not be described as native completion proof.

Context-aware retry, cancellation of Freedom's noise delay, retained packet
addresses and endpoint validation support the tested preparation/retirement
paths. They should be reviewed as individual behavior changes within the diff,
not counted as proof of the overall architecture. E1 does not rewrite the DNS
subsystem; cancellation of context-free DNS remains outside its evidence.

## Open decisions

Exact public interfaces, raw/Vision transition capabilities, virtual/shared
packet interruption, Reverse/XUDP contracts and removal of direct Process
callers remain open. A future capability should have a concrete consumer and
counterexample; it must not be added merely because another protocol exists.
