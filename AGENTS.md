# Maintained XWork Xray extension

The extension baseline is upstream v26.3.27 at d2758a023cd7f4174a5a5fa4ff66e487d4342ba0.
Keep upstream history and license intact. Maintain extension commits on release/xwork-v26.3.27.
Host deployment belongs to Playbooks Roles; resource declarations belong to GitOps;
release orchestration and authorization belong to Toolkit/Pipeline.

Preserve stock rmu behavior. The explicit rmus operation must revoke only authenticated
VLESS sessions belonging to the requested user, including logical XHTTP/Mux streams.
Validate races between authentication, removal, and re-addition. Do not identify accounts
by source IP or close a shared HTTP transport to disconnect a single account.
Release gates: race tests, real TCP/XHTTP/Mux isolation and recovery tests, fixed upstream
and extension SHA, binary checksum, UAT only before production promotion.
