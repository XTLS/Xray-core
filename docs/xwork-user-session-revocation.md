# XWork VLESS session revocation v1

Baseline: upstream Xray v26.3.27, commit d2758a023cd7f4174a5a5fa4ff66e487d4342ba0.

The maintained branch adds an explicit AlterInbound operation
`xwork.vless.RevokeUserSessions.v1`, whose payload is the nonempty user email used by
the inbound validator. `xray api rmus --server=127.0.0.1:10085 -tag=vless-inbound email`
calls that operation. An unpatched core rejects it; the caller must not interpret a
stock RemoveUser response as evidence that sessions closed. The API must remain local.

The VLESS handler serializes AddUser, user revocation, and authenticated-session
registration. It checks the authenticated user object is still current before
registering a session, rejecting stale authentication after removal/re-addition.
Revocation deletes the validator entry, detaches the user's registered sessions,
cancels their contexts, and closes their logical connections. Other user sessions
and shared HTTP transports remain owned by their existing handlers. No business
account, subscription, payment, refund, UUID, or usage ledger is deleted.

Stock rmu remains authentication-only. Restoring access uses stock adu. Agent enables
rmus only with dynamicUsers.terminateSessions=true and retains failed reconciliations
for retry. Binary/config upgrades may restart once; quota events must not restart
Xray or Caddy.

Run `go test -race ./proxy/vless/inbound ./app/proxyman/command` and build `./main`.
In xconnect-edge-agent run `XRAY_SESSION_TEST_BINARY=<absolute binary> go test
-tags xrayintegration ./internal/xrayconfig -run TestExtended -count=1 -v`.
The stock-core negative control must fail the extended integration test.

UAT must additionally prove Accounts quota decision and SSE propagation using a
dedicated test account, process PID stability, denied new authentication, unrelated
user session continuity, and restoration through adu. Local tests alone are not UAT
acceptance. Production deployment is a separate promotion.
