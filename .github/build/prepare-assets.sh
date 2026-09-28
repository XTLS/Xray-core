#!/usr/bin/env bash
set -euo pipefail

mkdir -p resources

prepare_geodat() {
  local name file expected actual tmp
  for name in geoip geosite; do
    file="resources/${name}.dat"
    expected="$(curl --fail --silent --show-error --location --retry 3 \
      "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/${name}.dat.sha256sum" | awk 'NR == 1 { print $1 }')"
    if [[ ! "${expected}" =~ ^[[:xdigit:]]{64}$ ]]; then
      echo "Invalid SHA256 for ${name}.dat" >&2
      exit 1
    fi
    if [[ -s "${file}" ]]; then
      actual="$(sha256sum "${file}" | awk '{ print $1 }')"
      if [[ "${actual}" == "${expected}" ]]; then
        continue
      fi
    fi
    tmp="${file}.download"
    curl --fail --silent --show-error --location --retry 3 \
      "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/${name}.dat" -o "${tmp}"
    printf '%s  %s\n' "${expected}" "${tmp}" | sha256sum --check --status
    mv -f "${tmp}" "${file}"
  done
}

prepare_wintun() {
  local arch zip missing=false
  for arch in amd64 x86 arm64; do
    if [[ ! -s "resources/wintun/bin/${arch}/wintun.dll" ]]; then
      missing=true
    fi
  done
  if [[ "${missing}" == false && -s resources/wintun/LICENSE.txt ]]; then
    return
  fi

  zip="$(mktemp)"
  trap 'rm -f "${zip}"' RETURN
  curl --fail --silent --show-error --location --retry 3 \
    'https://www.wintun.net/builds/wintun-0.14.1.zip' -o "${zip}"
  printf '%s  %s\n' \
    '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51' "${zip}" | sha256sum --check --status
  unzip -oq "${zip}" -d resources/
  for arch in amd64 x86 arm64; do
    test -s "resources/wintun/bin/${arch}/wintun.dll"
  done
  test -s resources/wintun/LICENSE.txt
}

case "${1:-}" in
  geodat) prepare_geodat ;;
  all) prepare_geodat; prepare_wintun ;;
  *) echo 'Usage: prepare-assets.sh geodat|all' >&2; exit 2 ;;
esac
