package ctlcmd

import (
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/platform"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func Run(args []string, input io.Reader) (buf.MultiBuffer, error) {
	xctl := platform.GetToolLocation("xctl")
	if _, err := os.Stat(xctl); err != nil {
		return nil, newError("xctl doesn't exist").Base(err)
	}

	var errBuffer buf.MultiBufferContainer
	var outBuffer buf.MultiBufferContainer

	cmd := exec.Command(xctl, args...)
	cmd.Stderr = &errBuffer
	cmd.Stdout = &outBuffer
	cmd.SysProcAttr = getSysProcAttr()
	if input != nil {
		cmd.Stdin = input
	}

	if err := cmd.Start(); err != nil {
		return nil, newError("failed to start xctl").Base(err)
	}

	if err := cmd.Wait(); err != nil {
		msg := "failed to execute xctl"
		if errBuffer.Len() > 0 {
			msg += ": \n" + strings.TrimSpace(errBuffer.MultiBuffer.String())
		}
		return nil, newError(msg).Base(err)
	}

	// log stderr, info message
	if !errBuffer.IsEmpty() {
		newError("<xctl message> \n", strings.TrimSpace(errBuffer.MultiBuffer.String())).AtInfo().WriteToLog()
	}

	return outBuffer.MultiBuffer, nil
}
