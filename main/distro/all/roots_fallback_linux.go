//go:build linux && (arm || arm64)

// For Linux ARM build running on Android which dosen't have CA certs in standard path

package all

import _ "golang.org/x/crypto/x509roots/fallback"
