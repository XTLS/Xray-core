package main

import (
	"fmt"

	"github.com/hosemorinho412/xray-core/core"
	"github.com/hosemorinho412/xray-core/main/commands/base"
)

var cmdVersion = &base.Command{
	UsageLine: "{{.Exec}} version",
	Short:     "Show current version of Xray",
	Long: `Version prints the build information for Xray executables.
	`,
	Run: executeVersion,
}

func executeVersion(cmd *base.Command, args []string) {
	printVersion()
}

func printVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		fmt.Println(s)
	}
}
