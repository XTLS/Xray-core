package armor

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

func decodeToString(src string) (string, error) {
	dec, err := NewDecoder(strings.NewReader(src))
	if err != nil {
		return "", err
	}
	p, err := ioutil.ReadAll(dec)
	return string(p), err
}

func TestDecoder(t *testing.T) {
	for _, test := range []struct {
		input          string
		expectedOutput string
		expectedErr    bool
	}{
		{`
<pre>
0
</pre>
`,
			"",
			false,
		},
		{`
<pre>
0aGVsbG8gd29ybGQK
</pre>
`,
			"hello world\n",
			false,
		},
		// bad version indicator
		{`
<pre>
1aGVsbG8gd29ybGQK
</pre>
`,
			"",
			true,
		},
		// text outside <pre> elements
		{`
0aGVsbG8gd29ybGQK
blah blah blah
<pre>
0aGVsbG8gd29ybGQK
</pre>
0aGVsbG8gd29ybGQK
blah blah blah
`,
			"hello world\n",
			false,
		},
		{`
<pre>
0QUJDREV
GR0hJSkt
MTU5PUFF
SU1RVVld
</pre>
junk
<pre>
YWVowMTI
zNDU2Nzg
5Cg
=
</pre>
<pre>
=
</pre>
`,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n",
			false,
		},
		// no <pre> elements, hence no version indicator
		{`
aGVsbG8gd29ybGQK
blah blah blah
aGVsbG8gd29ybGQK
aGVsbG8gd29ybGQK
blah blah blah
`,
			"",
			true,
		},
		// empty <pre> elements, hence no version indicator
		{`
aGVsbG8gd29ybGQK
blah blah blah
<pre>   </pre>
aGVsbG8gd29ybGQK
aGVsbG8gd29ybGQK<pre></pre>
blah blah blah
`,
			"",
			true,
		},
		// other elements inside <pre>
		{
			"blah <pre>0aGVsb<p>G8gd29</p>ybGQK</pre>",
			"hello world\n",
			false,
		},
		// HTML comment
		{
			"blah <!-- <pre>aGVsbG8gd29ybGQK</pre> -->",
			"",
			true,
		},
		// all kinds of ASCII whitespace
		{
			"blah <pre>\x200\x09aG\x0aV\x0csb\x0dG8\x20gd29ybGQK</pre>",
			"hello world\n",
			false,
		},

		// bad padding
		{`
<pre>
0QUJDREV
GR0hJSkt
MTU5PUFF
SU1RVVld
</pre>
junk
<pre>
YWVowMTI
zNDU2Nzg
5Cg
=
</pre>
`,
			"",
			true,
		},
		/*
			// per-chunk base64
			// test disabled because Go stdlib handles this incorrectly:
			// https://github.com/golang/go/issues/31626
			{
				"<pre>QQ==</pre><pre>Qg==</pre>",
				"",
				true,
			},
		*/
		// missing </pre>
		{
			"blah <pre></pre><pre>0aGVsbG8gd29ybGQK",
			"",
			true,
		},
		// nested <pre>
		{
			"blah <pre>0aGVsb<pre>G8gd29</pre>ybGQK</pre>",
			"",
			true,
		},
	} {
		output, err := decodeToString(test.input)
		if test.expectedErr && err == nil {
			t.Errorf("%+q → (%+q, %v), expected error", test.input, output, err)
			continue
		}
		if !test.expectedErr && err != nil {
			t.Errorf("%+q → (%+q, %v), expected no error", test.input, output, err)
			continue
		}
		if !test.expectedErr && output != test.expectedOutput {
			t.Errorf("%+q → (%+q, %v), expected (%+q, %v)",
				test.input, output, err, test.expectedOutput, nil)
			continue
		}
	}
}

func roundTrip(s string) (string, error) {
	var encoded strings.Builder
	enc, err := NewEncoder(&encoded)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(enc, strings.NewReader(s))
	if err != nil {
		return "", err
	}
	err = enc.Close()
	if err != nil {
		return "", err
	}
	return decodeToString(encoded.String())
}

func TestRoundTrip(t *testing.T) {
	lengths := make([]int, 0)
	// Test short strings and lengths around elementSizeLimit thresholds.
	for i := 0; i < bytesPerChunk*2; i++ {
		lengths = append(lengths, i)
	}
	for i := -10; i < +10; i++ {
		lengths = append(lengths, elementSizeLimit+i)
		lengths = append(lengths, 2*elementSizeLimit+i)
	}
	for _, n := range lengths {
		buf := make([]byte, n)
		rand.Read(buf)
		input := string(buf)
		output, err := roundTrip(input)
		if err != nil {
			t.Errorf("length %d → error %v", n, err)
			continue
		}
		if output != input {
			t.Errorf("length %d → %+q", n, output)
			continue
		}
	}
}
