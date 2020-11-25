package base

import (
	"os"
	"path"
)

// CommandEnvHolder is a struct holds the environment info of commands
type CommandEnvHolder struct {
	Exec string
}

// CommandEnv holds the environment info of commands
var CommandEnv CommandEnvHolder

func init() {
	exec, err := os.Executable()
	if err != nil {
		return
	}
	CommandEnv.Exec = path.Base(exec)
	CommandEnv.Exec = "xray"
}
