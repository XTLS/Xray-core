# Fork patches

`reality-*.patch` are applied to the REALITY version pinned in `go.mod`, vendored into `third_party/reality`
(wired in via a `replace` directive). Re-run `./patches/apply.sh` after every upstream merge.

- `reality-allow-x25519.patch`: reverts [XTLS/REALITY@8cdf7bf](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8),
  so the server again accepts Client Hellos that offer plain X25519 without X25519MLKEM768 (older clients/apps).

`.github/workflows/sync-upstream.yml` does this automatically for every new upstream release and publishes
`<tag>-compat` with raw `xray-linux-amd64` / `xray-linux-arm64` binaries. It needs a `SYNC_TOKEN` secret
(PAT with Contents + Workflows write on this repo).

Remnanode: set `CUSTOM_CORE_URL=https://github.com/TripleA150/Xray-core/releases/latest/download/xray-linux-amd64`.
