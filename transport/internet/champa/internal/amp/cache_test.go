package amp

import (
	"bytes"
	"net/url"
	"testing"

	"golang.org/x/net/idna"
)

func TestDomainPrefixBasic(t *testing.T) {
	// Tests expecting no error.
	for _, test := range []struct {
		domain, expected string
	}{
		{"", ""},
		{"xn--", ""},
		{"...", "---"},

		// Should not apply mappings such as case folding and
		// normalization.
		{"b\u00fccher.de", "xn--bcher-de-65a"},
		{"B\u00fccher.de", "xn--Bcher-de-65a"},
		{"bu\u0308cher.de", "xn--bucher-de-hkf"},

		// Check some that differ between IDNA 2003 and IDNA 2008.
		// https://unicode.org/reports/tr46/#Deviations
		// https://util.unicode.org/UnicodeJsps/idna.jsp
		{"faß.de", "xn--fa-de-mqa"},
		{"βόλοσ.com", "xn---com-4ld8c2a6a8e"},

		// Lengths of 63 and 64. 64 is too long for a DNS label, but
		// domainPrefixBasic is not expected to check for that.
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},

		// https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/#basic-algorithm
		{"example.com", "example-com"},
		{"foo.example.com", "foo-example-com"},
		{"foo-example.com", "foo--example-com"},
		{"xn--57hw060o.com", "xn---com-p33b41770a"},
		{"\u26a1\U0001f60a.com", "xn---com-p33b41770a"},
		{"en-us.example.com", "0-en--us-example-com-0"},
	} {
		output, err := domainPrefixBasic(test.domain)
		if err != nil || output != test.expected {
			t.Errorf("%+q → (%+q, %v), expected (%+q, %v)",
				test.domain, output, err, test.expected, nil)
		}
	}

	// Tests expecting an error.
	for _, domain := range []string{
		"xn---",
	} {
		output, err := domainPrefixBasic(domain)
		if err == nil || output != "" {
			t.Errorf("%+q → (%+q, %v), expected (%+q, non-nil)",
				domain, output, err, "")
		}
	}
}

func TestDomainPrefixFallback(t *testing.T) {
	for _, test := range []struct {
		domain, expected string
	}{
		{
			"",
			"4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq",
		},
		{
			"example.com",
			"un42n5xov642kxrxrqiyanhcoupgql5lt4wtbkyt2ijflbwodfdq",
		},

		// These checked against the output of
		// https://github.com/ampproject/amp-toolbox/tree/84cb3057e5f6c54d64369ddd285db1cb36237ee8/packages/cache-url,
		// using the widget at
		// https://amp.dev/documentation/guides-and-tutorials/learn/amp-caches-and-cors/amp-cache-urls/#url-format.
		{
			"000000000000000000000000000000000000000000000000000000000000.com",
			"stejanx4hsijaoj4secyecy4nvqodk56kw72whwcmvdbtucibf5a",
		},
		{
			"00000000000000000000000000000000000000000000000000000000000a.com",
			"jdcvbsorpnc3hcjrhst56nfm6ymdpovlawdbm2efyxpvlt4cpbya",
		},
		{
			"00000000000000000000000000000000000000000000000000000000000\u03bb.com",
			"qhzqeumjkfpcpuic3vqruyjswcr7y7gcm3crqyhhywvn3xrhchfa",
		},
	} {
		output := domainPrefixFallback(test.domain)
		if output != test.expected {
			t.Errorf("%+q → %+q, expected %+q",
				test.domain, output, test.expected)
		}
	}
}

// Checks that domainPrefix chooses domainPrefixBasic or domainPrefixFallback as
// appropriate; i.e., always returns string that is a valid DNS label and is
// IDNA-decodable.
func TestDomainPrefix(t *testing.T) {
	// A validating IDNA profile, which checks label length and that the
	// label contains only certain ASCII characters. It does not do the
	// ValidateLabels check, because that depends on the input having
	// certain properties.
	profile := idna.New(
		idna.VerifyDNSLength(true),
		idna.StrictDomainName(true),
	)
	for _, domain := range []string{
		"example.com",
		"\u0314example.com",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // 63 bytes
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 bytes
		"xn--57hw060o.com",
		"a b c",
	} {
		output := domainPrefix(domain)
		if bytes.IndexByte([]byte(output), '.') != -1 {
			t.Errorf("%+q → %+q contains a dot", domain, output)
		}
		_, err := profile.ToUnicode(output)
		if err != nil {
			t.Errorf("%+q → error %v", domain, err)
		}
	}
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}

func TestCacheURL(t *testing.T) {
	// Tests expecting no error.
	for _, test := range []struct {
		pub         string
		cache       string
		contentType string
		expected    string
	}{
		// With or without trailing slash on pubURL.
		{
			"http://example.com/",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/example.com",
		},
		{
			"http://example.com",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/example.com",
		},
		// https pubURL.
		{
			"https://example.com/",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/s/example.com",
		},
		// The content type should be escaped if necessary.
		{
			"http://example.com/",
			"https://amp.cache/",
			"/",
			"https://example-com.amp.cache/%2F/example.com",
		},
		// Retain pubURL path, query, and fragment, including escaping.
		{
			"http://example.com/my%2Fpath/index.html?a=1#fragment",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/example.com/my%2Fpath/index.html?a=1#fragment",
		},
		// Retain scheme, userinfo, port, and path of cacheURL, escaping
		// whatever is necessary.
		{
			"http://example.com",
			"http://cache%2Fuser:cache%40pass@amp.cache:123/with/../../path/..%2f../",
			"c",
			"http://cache%2Fuser:cache%40pass@example-com.amp.cache:123/path/..%2f../c/example.com",
		},
		// Port numbers in pubURL are allowed, if they're the default
		// for scheme.
		{
			"http://example.com:80/",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/example.com",
		},
		{
			"https://example.com:443/",
			"https://amp.cache/",
			"c",
			"https://example-com.amp.cache/c/s/example.com",
		},
		// "?" at the end of cacheURL is okay, as long as the query is
		// empty.
		{
			"http://example.com/",
			"https://amp.cache/?",
			"c",
			"https://example-com.amp.cache/c/example.com",
		},

		// https://developers.google.com/amp/cache/overview#example-requesting-document-using-tls
		{
			"https://example.com/amp_document.html",
			"https://cdn.ampproject.org/",
			"c",
			"https://example-com.cdn.ampproject.org/c/s/example.com/amp_document.html",
		},
		// https://developers.google.com/amp/cache/overview#example-requesting-image-using-plain-http
		{
			"http://example.com/logo.png",
			"https://cdn.ampproject.org/",
			"i",
			"https://example-com.cdn.ampproject.org/i/example.com/logo.png",
		},
		// https://developers.google.com/amp/cache/overview#query-parameter-example
		{
			"https://example.com/g?value=Hello%20World",
			"https://cdn.ampproject.org/",
			"c",
			"https://example-com.cdn.ampproject.org/c/s/example.com/g?value=Hello%20World",
		},
	} {
		pubURL := mustParseURL(test.pub)
		cacheURL := mustParseURL(test.cache)
		outputURL, err := CacheURL(pubURL, cacheURL, test.contentType)
		if err != nil {
			t.Errorf("%+q %+q %+q → error %v",
				test.pub, test.cache, test.contentType, err)
			continue
		}
		if outputURL.String() != test.expected {
			t.Errorf("%+q %+q %+q → %+q, expected %+q",
				test.pub, test.cache, test.contentType, outputURL, test.expected)
			continue
		}
	}

	// Tests expecting an error.
	for _, test := range []struct {
		pub         string
		cache       string
		contentType string
	}{
		// Empty content type.
		{
			"http://example.com/",
			"https://amp.cache/",
			"",
		},
		// Empty host.
		{
			"http:///index.html",
			"https://amp.cache/",
			"c",
		},
		// Empty scheme.
		{
			"//example.com/",
			"https://amp.cache/",
			"c",
		},
		// Unrecognized scheme.
		{
			"ftp://example.com/",
			"https://amp.cache/",
			"c",
		},
		// Wrong port number for scheme.
		{
			"http://example.com:443/",
			"https://amp.cache/",
			"c",
		},
		// userinfo in pubURL.
		{
			"http://user@example.com/",
			"https://amp.cache/",
			"c",
		},
		{
			"http://user:pass@example.com/",
			"https://amp.cache/",
			"c",
		},
		// cacheURL may not contain a query.
		{
			"http://example.com/",
			"https://amp.cache/?a=1",
			"c",
		},
		// cacheURL may not contain a fragment.
		{
			"http://example.com/",
			"https://amp.cache/#fragment",
			"c",
		},
	} {
		pubURL := mustParseURL(test.pub)
		cacheURL := mustParseURL(test.cache)
		outputURL, err := CacheURL(pubURL, cacheURL, test.contentType)
		if err == nil {
			t.Errorf("%+q %+q %+q → %+q, expected error",
				test.pub, test.cache, test.contentType, outputURL)
			continue
		}
	}
}
