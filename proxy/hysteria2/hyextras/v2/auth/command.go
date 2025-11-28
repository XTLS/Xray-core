package auth

import (
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/server"
)

var _ server.Authenticator = &CommandAuthenticator{}

type CommandAuthenticator struct {
	Cmd string
}

func (a *CommandAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	cmd := exec.Command(a.Cmd, addr.String(), auth, strconv.Itoa(int(tx)))
	out, err := cmd.Output()
	if err != nil {
		// This includes failing to execute the command,
		// or the command exiting with a non-zero exit code.
		return false, ""
	} else {
		return true, strings.TrimSpace(string(out))
	}
}
