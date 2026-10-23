#!/bin/sh
# Re-vendors the REALITY version pinned in go.mod into third_party/reality with our patches applied.
# Run after every upstream merge; fails loudly if a patch no longer applies.
set -eu
cd "$(dirname "$0")/.."
ver=$(go list -m -f '{{.Version}}' github.com/xtls/reality)
go mod download "github.com/xtls/reality@$ver"
rm -rf third_party/reality
mkdir -p third_party
cp -r "$(go env GOMODCACHE)/github.com/xtls/reality@$ver" third_party/reality
chmod -R u+w third_party/reality
for p in patches/reality-*.patch; do patch -p1 --no-backup-if-mismatch -d third_party/reality < "$p"; done
go run ./infra/vformat/main.go -pwd ./third_party/reality # keep upstream format check green
echo "$ver" > third_party/reality/VERSION
go mod edit -replace github.com/xtls/reality=./third_party/reality
