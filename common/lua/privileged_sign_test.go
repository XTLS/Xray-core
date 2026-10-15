package lua

// TODO: Re-enable these tests and their helper when Compile supports privileged signature authorization again.
/*
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func privilegedSeed(t *testing.T) string {
	t.Helper()
	seed, err := hex.DecodeString(privilegedTestSeed)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(seed)
}

func TestSignPrivilegedScriptPreservesSource(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	seed := privilegedSeed(t)
	for _, tc := range []struct {
		name, prefix, header, body, newline string
	}{
		{name: "unsigned", body: privilegedFixtureBody, newline: "\n"},
		{name: "unsigned boundary whitespace", body: " \t\n\n" + privilegedFixtureBody + " \t\n", newline: "\n"},
		{name: "unsigned CRLF", body: strings.ReplaceAll(privilegedFixtureBody, "\n", "\r\n"), newline: "\r\n"},
		{name: "replace invalid header", header: privilegedSignatureHeader + "%", body: "\n" + privilegedFixtureBody, newline: "\n"},
		{name: "replace indented header", prefix: " \t\r\n\n", header: " \t--\t @xray:privileged-signature=% \t", body: "\r\n \t\r\n" + privilegedFixtureBody + "\r\n", newline: "\r\n"},
		{name: "replace valid header", header: privilegedSignatureHeader + privilegedFixtureSignature, body: "\n" + privilegedFixtureBody, newline: "\n"},
		{name: "empty script", newline: "\n"},
		{name: "header without newline", header: privilegedSignatureHeader + "%"},
		{name: "ordinary comment before marker", body: "-- ordinary comment\n" + privilegedSignatureHeader + "%\nvalue = 1", newline: "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := []byte(tc.prefix + tc.header + tc.body)
			original := bytes.Clone(code)
			signed, err := SignPrivilegedScript(code, seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(code, original) {
				t.Fatal("signing modified the input buffer")
			}
			body := tc.body
			if tc.header != "" {
				body = strings.TrimPrefix(body, tc.newline)
			}
			header := privilegedSignatureHeader + testSignature(t, body)
			want := header + tc.newline + tc.body
			if tc.header != "" {
				want = tc.prefix + header + tc.body
			}
			if string(signed) != want {
				t.Fatalf("signed source = %q, want %q", signed, want)
			}
			program, err := Compile(writeTestScript(t, string(signed)))
			if err != nil || program == nil || !program.privileged {
				t.Fatalf("signed source Compile = %v, %v; want privileged program", program, err)
			}
			again, err := SignPrivilegedScript(signed, seed)
			if err != nil || !bytes.Equal(again, signed) {
				t.Fatalf("resigning changed the source: %q, %v", again, err)
			}
		})
	}
}

func TestSignPrivilegedScriptRejectsInvalidSeed(t *testing.T) {
	seed := privilegedSeed(t)
	for _, value := range []string{
		"", "%", seed + "=",
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SeedSize-1)),
		base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
	} {
		if signed, err := SignPrivilegedScript([]byte(privilegedFixtureBody), value); signed != nil || err == nil {
			t.Fatalf("SignPrivilegedScript with invalid seed = %q, %v; want rejection", signed, err)
		}
	}
}
*/
