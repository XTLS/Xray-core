// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package base defines shared basic pieces of the commands,
// in particular logging and the Command structure.
package base

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

// A Command is an implementation of a xray command
// like xray run or xray version.
type Command struct {
	// Run runs the command.
	// The args are the arguments after the command name.
	Run func(cmd *Command, args []string)

	// UsageLine is the one-line usage message.
	// The words between "go" and the first flag or argument in the line are taken to be the command name.
	UsageLine string

	// Short is the short description shown in the 'go help' output.
	Short string

	// Long is the long message shown in the 'go help <this-command>' output.
	Long string

	// Flag is a set of flags specific to this command.
	Flag flag.FlagSet

	// CustomFlags indicates that the command will do its own
	// flag parsing.
	CustomFlags bool

	// Commands lists the available commands and help topics.
	// The order here is the order in which they are printed by 'go help'.
	// Note that subcommands are in general best avoided.
	Commands []*Command
}

// LongName returns the command's long name: all the words in the usage line between "go" and a flag or argument,
func (c *Command) LongName() string {
	name := c.UsageLine
	if i := strings.Index(name, " ["); i >= 0 {
		name = name[:i]
	}
	if name == CommandEnv.Exec {
		return ""
	}
	return strings.TrimPrefix(name, CommandEnv.Exec+" ")
}

// Name returns the command's short name: the last word in the usage line before a flag or argument.
func (c *Command) Name() string {
	name := c.LongName()
	if i := strings.LastIndex(name, " "); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// Usage prints usage of the Command
func (c *Command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "Run 'xray help %s' for details.\n", c.LongName())
	SetExitStatus(2)
	Exit()
}

// Runnable reports whether the command can be run; otherwise
// it is a documentation pseudo-command such as importpath.
func (c *Command) Runnable() bool {
	return c.Run != nil
}

// Exit exits with code set with SetExitStatus()
func Exit() {
	os.Exit(exitStatus)
}

// Fatalf logs error and exit with code 1
func Fatalf(format string, args ...interface{}) {
	Errorf(format, args...)
	Exit()
}

// Errorf logs error and set exit status to 1, but not exit
func Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	SetExitStatus(1)
}

// ExitIfErrors exits if current status is not zero
func ExitIfErrors() {
	if exitStatus != 0 {
		Exit()
	}
}

var exitStatus = 0
var exitMu sync.Mutex

// SetExitStatus set exit status code
func SetExitStatus(n int) {
	exitMu.Lock()
	if exitStatus < n {
		exitStatus = n
	}
	exitMu.Unlock()
}

// GetExitStatus get exit status code
func GetExitStatus() int {
	return exitStatus
}
