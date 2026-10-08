# XMC startup padding

The optional `padding` array in an XMC TCP finalmask replaces the built-in
Minecraft 26.1.2 startup padding schedule. Omit the field entirely to keep the
preset, including its write boundaries and timing.

For example, add this field alongside `password`, `profiles`, and `hostname`
in the XMC mask's `settings` on **both endpoints**:

```json
"padding": [
  {"length": "44", "direction": "c2s"},
  {"length": "64-128", "direction": "s2c"},
  {"length": "25", "direction": "c2s"},
  {"length": "32768-49152", "direction": "s2c"}
]
```

- Each entry is an object with:
  - `length`: a fixed byte length or an inclusive `min-max` range string.
    Each sender samples uniformly within its range.
  - `direction`: either `"c2s"` (client-to-server) or `"s2c"` (server-to-client).
    You can use `"client-to-server"` and `"server-to-client"` as well.
- Each side finishes reading the peer's turn before sending its own. The array
  runs once during startup, not once per application write.
- Turns can be in any order and direction. Consecutive same-direction turns are
  allowed.
- A length includes the padding record's VarInt header. The first turn also
  includes the two-byte Login Acknowledged packet, so its minimum is 3 bytes.
  Later turns may be as short as 1 byte. The maximum per turn is 8,388,608 bytes.
- Custom turns add no intentional delays. Writes use the existing bounded
  padding buffer; configured lengths are turn totals, not TCP segment sizes.
- After startup, data framing and the 15-second keep-alive remain unchanged.
  This setting does not pad application data, fragment it, or reorder other
  finalmasks.

Both endpoints must use the same array. Selected record lengths are carried
inside the existing encrypted padding stream and checked against the receiver's
configured range. There is no profile negotiation or configuration fingerprint:
some mismatches fail a length check, while others may stall until the handshake
deadline or leave the stream out of sync. Do not mix custom and default schedules
or rely on length checks to detect every mismatch.
