package base

// CommandEnvHolder is a struct holds the environment info of commands
type CommandEnvHolder struct {
	// Executable name of current binary
	Exec string
	// commands column width of current command
	CommandsWidth int
}

// CommandEnv holds the environment info of commands
var CommandEnv CommandEnvHolder

func init() {
	CommandEnv.Exec = "xray"
}
