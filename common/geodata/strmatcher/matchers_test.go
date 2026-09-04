package strmatcher_test

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/geodata/strmatcher"
)

func TestMatcher(t *testing.T) {
	cases := []struct {
		pattern string
		mType   Type
		input   string
		output  bool
	}{
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "www.example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "www.e3ample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "xample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Domain,
			input:   "xexample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Full,
			input:   "example.com",
			output:  true,
		},
		{
			pattern: "example.com",
			mType:   Full,
			input:   "xexample.com",
			output:  false,
		},
		{
			pattern: "example.com",
			mType:   Regex,
			input:   "examplexcom",
			output:  true,
		},
	}
	for _, test := range cases {
		matcher, err := test.mType.New(test.pattern)
		common.Must(err)
		if m := matcher.Match(test.input); m != test.output {
			t.Error("unexpected output: ", m, " for test case ", test)
		}
	}
}

func TestToDomain(t *testing.T) {
	{ // Test normal ASCII domain, which should not trigger new string data allocation
		input := "example.com"
		domain, err := ToDomain(input)
		if err != nil {
			t.Error("unexpected error: ", err)
		}
		if domain != input {
			t.Error("unexpected output: ", domain, " for test case ", input)
		}
		if (*reflect.StringHeader)(unsafe.Pointer(&input)).Data != (*reflect.StringHeader)(unsafe.Pointer(&domain)).Data {
			t.Error("different string data of output: ", domain, " and test case ", input)
		}
	}
	{ // Test ASCII domain containing upper case letter, which should be converted to lower case
		input := "eXAMPLE.cOm"
		domain, err := ToDomain(input)
		if err != nil {
			t.Error("unexpected error: ", err)
		}
		if domain != "example.com" {
			t.Error("unexpected output: ", domain, " for test case ", input)
		}
	}
	{ // Test internationalized domain, which should be translated to ASCII punycode
		input := "example.公益"
		domain, err := ToDomain(input)
		if err != nil {
			t.Error("unexpected error: ", err)
		}
		if domain != "example.xn--55qw42g" {
			t.Error("unexpected output: ", domain, " for test case ", input)
		}
	}
	{ // Test internationalized domain containing upper case letter
		input := "eXAMPLE.公益"
		domain, err := ToDomain(input)
		if err != nil {
			t.Error("unexpected error: ", err)
		}
		if domain != "example.xn--55qw42g" {
			t.Error("unexpected output: ", domain, " for test case ", input)
		}
	}
	{ // Test domain name of invalid character, which should return with error
		input := "{"
		_, err := ToDomain(input)
		if err == nil {
			t.Error("unexpected non error for test case ", input)
		}
	}
	{ // Test domain name containing a space, which should return with error
		input := "Mijia Cloud"
		_, err := ToDomain(input)
		if err == nil {
			t.Error("unexpected non error for test case ", input)
		}
	}
	{ // Test domain name containing an underscore, which should return with error
		input := "Mijia_Cloud.com"
		_, err := ToDomain(input)
		if err == nil {
			t.Error("unexpected non error for test case ", input)
		}
	}
	{ // Test internationalized domain containing invalid character
		input := "Mijia Cloud.公司"
		_, err := ToDomain(input)
		if err == nil {
			t.Error("unexpected non error for test case ", input)
		}
	}
}
