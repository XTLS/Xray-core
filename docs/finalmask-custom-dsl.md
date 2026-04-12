# Finalmask Custom DSL

## Purpose

`finalmask/header-custom` supports a bounded declarative DSL for building and matching custom header bytes.

The DSL is intended for controlled request/response linkage and derived field construction without introducing a general scripting engine.

## Compatibility

Legacy static item forms remain valid:

- `packet`
- `rand`

DSL fields extend the same item model and coexist with the legacy fields.

## Item Fields

Supported item fields:

- `packet`
- `rand`
- `save`
- `var`
- `expr`
- `delay` for TCP items
- `randRange`
- `type` for byte literal decoding

Each item must define exactly one emitted value kind:

- `packet`
- `rand`
- `var`
- `expr`

`save` is optional and stores the emitted or matched bytes under a variable name.

## Expressions

Supported expression operators:

- `concat`
- `slice`
- `xor16`
- `xor32`
- `be16`
- `be32`

Expression arguments may contain:

- literal bytes
- unsigned integers
- variable references
- metadata references
- nested expressions

## Variables

Variable names use identifier syntax:

- first character: letter or `_`
- remaining characters: letter, digit, or `_`

Variables may be introduced by `save` and consumed later by `var` or expressions.

## Metadata

Supported metadata names:

- `local_port`
- `remote_port`
- `local_ip4_u32`
- `remote_ip4_u32`

`local_port` and `remote_port` are numeric values.

`local_ip4_u32` and `remote_ip4_u32` are IPv4 numeric values encoded as unsigned 32-bit integers in network byte order before higher-level operators such as `be32`.

Metadata lookup fails when the requested value is unavailable.

## State

The runtime maintains short-lived state for saved variables.

Current state model:

- UDP state is keyed by peer address
- TCP state is keyed by the local/remote endpoint tuple
- state entries expire automatically
- saved variables are copied on read and write boundaries

State is isolated by key and not shared globally across unrelated peers.

## Transport Semantics

UDP semantics:

- item lists are evaluated in packet order
- inbound matching may capture values for later reuse
- outbound building may reuse previously saved values for the same state key

TCP semantics:

- sequence items are processed in order
- saved values remain available across later sequence steps in the same handshake
- connection endpoint metadata is available during sequence evaluation

## Validation Rules

The config builder rejects:

- mixed item kinds in a single item
- invalid variable names
- malformed expressions
- unsupported metadata names at evaluation time
- range values outside byte bounds for `randRange`

## Out of Scope

This DSL does not provide:

- arbitrary user code
- loops
- branching
- user-defined functions
- protocol-specific helper operations
- checksum generation
- cryptographic signing

## Design Boundary

The DSL is intentionally limited to deterministic byte construction, matching, metadata access, and bounded saved-state reuse.
