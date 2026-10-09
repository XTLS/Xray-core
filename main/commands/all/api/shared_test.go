package api

import (
	"slices"
	"testing"

	"github.com/xtls/xray-core/main/commands/base"
)

func TestParseFlags(t *testing.T) {
	cases := []struct {
		args        []string
		server      string
		timeout     int
		json        bool
		unnamedArgs []string
	}{
		{nil, "127.0.0.1:8080", 3, false, nil},
		{[]string{"-s", "127.0.0.1:10085", "a", "b"}, "127.0.0.1:10085", 3, false, []string{"a", "b"}},
		{[]string{"a", "--server=127.0.0.1:10085", "b", "-t", "5", "-json"}, "127.0.0.1:10085", 5, true, []string{"a", "b"}},
		{[]string{"a", "--", "-s", "b"}, "127.0.0.1:8080", 3, false, []string{"a", "-s", "b"}},
		{[]string{"-t", "5", "--", "-a"}, "127.0.0.1:8080", 5, false, []string{"-a"}},
		{[]string{"a", "-", "-t", "5"}, "127.0.0.1:8080", 5, false, []string{"a", "-"}},
		// A flag value of "--" is taken for the end of the flags, as before.
		{[]string{"-s", "--", "b", "-t", "5"}, "--", 3, false, []string{"b", "-t", "5"}},
	}
	for _, c := range cases {
		cmd := &base.Command{}
		setSharedFlags(cmd)
		parseFlags(cmd, c.args)
		if apiServerAddrPtr != c.server || apiTimeout != c.timeout || apiJSON != c.json || !slices.Equal(cmd.Flag.Args(), c.unnamedArgs) {
			t.Error("args", c.args, "gave server", apiServerAddrPtr, "timeout", apiTimeout, "json", apiJSON, "arguments", cmd.Flag.Args())
		}
	}
}
