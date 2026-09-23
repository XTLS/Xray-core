/* SPDX-License-Identifier: MIT
 *
 * Copyright 2024 Marten Seemann
 * Adapted from github.com/quic-go/connect-ip-go (commit a0c35fa).
 */

package connectip

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPRanges(t *testing.T) {
	tests := []struct {
		start, end netip.Addr
		want       []netip.Prefix
	}{
		{
			start: netip.MustParseAddr("192.168.1.1"),
			end:   netip.MustParseAddr("192.168.1.1"),
			want:  []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")},
		},
		{
			start: netip.MustParseAddr("192.168.1.0"),
			end:   netip.MustParseAddr("192.168.1.1"),
			want:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/31")},
		},
		{
			start: netip.MustParseAddr("192.168.1.1"),
			end:   netip.MustParseAddr("192.168.1.2"),
			want:  []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32"), netip.MustParsePrefix("192.168.1.2/32")},
		},
		{
			start: netip.MustParseAddr("192.168.1.0"),
			end:   netip.MustParseAddr("192.168.1.255"),
			want:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		},
		{
			start: netip.MustParseAddr("10.0.0.0"),
			end:   netip.MustParseAddr("10.1.0.255"),
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.1.0.0/24")},
		},
		{
			start: netip.MustParseAddr("2001:0db8:85a3::8a2e:0370:7334"),
			end:   netip.MustParseAddr("2001:0db8:85a3::8a2e:0370:7334"),
			want:  []netip.Prefix{netip.MustParsePrefix("2001:0db8:85a3::8a2e:0370:7334/128")},
		},
		{
			start: netip.MustParseAddr("2001:db8::0"),
			end:   netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff"),
			want:  []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")},
		},
		{
			start: netip.MustParseAddr("2001:db8::1"),
			end:   netip.MustParseAddr("2001:db8::2"),
			want:  []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("2001:db8::2/128")},
		},
		{
			start: netip.MustParseAddr("2001:db8:1234:5678::"),
			end:   netip.MustParseAddr("2001:db8:1234:5679::"),
			want: []netip.Prefix{
				netip.MustParsePrefix("2001:db8:1234:5678::/64"),
				netip.MustParsePrefix("2001:db8:1234:5679::/128"),
			},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%s", test.start, test.end), func(t *testing.T) {
			prefixes := rangeToPrefixes(test.start, test.end)
			require.Equal(t, test.want, prefixes)
		})
	}
}
