package splithttp_test

import (
	"testing"

	. "github.com/GFW-knocker/Xray-core/transport/internet/splithttp"
)

func Test_GetNormalizedPath(t *testing.T) {
	c := Config{
		Path: "/?world",
	}

	path := c.GetNormalizedPath("hello", true)
	if path != "/hello?world" {
		t.Error("Unexpected: ", path)
	}
}

func Test_GetNormalizedPath2(t *testing.T) {
	c := Config{
		Path: "?world",
	}

	path := c.GetNormalizedPath("hello", true)
	if path != "/hello?world" {
		t.Error("Unexpected: ", path)
	}
}

func Test_GetNormalizedPath3(t *testing.T) {
	c := Config{
		Path: "hello?world",
	}

	path := c.GetNormalizedPath("", true)
	if path != "/hello/?world" {
		t.Error("Unexpected: ", path)
	}
}

func Test_GetNormalizedPath4(t *testing.T) {
	c := Config{
		Path: "hello?world",
	}

	path := c.GetNormalizedPath("", false)
	if path != "/hello/" {
		t.Error("Unexpected: ", path)
	}
}
