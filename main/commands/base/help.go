// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"
)

// Help implements the 'help' command.
func Help(w io.Writer, args []string) {
	cmd := RootCommand
Args:
	for i, arg := range args {
		for _, sub := range cmd.Commands {
			if sub.Name() == arg {
				cmd = sub
				continue Args
			}
		}

		// helpSuccess is the help command using as many args as possible that would succeed.
		helpSuccess := CommandEnv.Exec + " help"
		if i > 0 {
			helpSuccess += " " + strings.Join(args[:i], " ")
		}
		fmt.Fprintf(os.Stderr, "%s help %s: unknown help topic. Run '%s'.\n", CommandEnv.Exec, strings.Join(args, " "), helpSuccess)
		SetExitStatus(2) // failed at 'xray help cmd'
		Exit()
	}

	if len(cmd.Commands) > 0 {
		PrintUsage(os.Stdout, cmd)
	} else {
		tmpl(os.Stdout, helpTemplate, makeTmplData(cmd))
	}
}

var usageTemplate = `{{.Long | trim}}

Usage:

	{{.Exec}} <command> [arguments]

The commands are:
{{range .Commands}}{{if and (ne .Short "") (or (.Runnable) .Commands)}}
	{{.Name | printf "%-12s"}} {{.Short}}{{end}}{{end}}

Use "{{.Exec}} help{{with .LongName}} {{.}}{{end}} <command>" for more information about a command.
`

// APPEND FOLLOWING TO 'usageTemplate' IF YOU WANT DOC,
// A DOC TOPIC IS JUST A COMMAND NOT RUNNABLE:
//
// {{if eq (.UsageLine) (.Exec)}}
// Additional help topics:
// {{range .Commands}}{{if and (not .Runnable) (not .Commands)}}
// 	{{.Name | printf "%-15s"}} {{.Short}}{{end}}{{end}}
//
// Use "{{.Exec}} help{{with .LongName}} {{.}}{{end}} <topic>" for more information about that topic.
// {{end}}

var helpTemplate = `{{if .Runnable}}usage: {{.UsageLine}}

{{end}}{{.Long | trim}}
`

// An errWriter wraps a writer, recording whether a write error occurred.
type errWriter struct {
	w   io.Writer
	err error
}

func (w *errWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err != nil {
		w.err = err
	}
	return n, err
}

// tmpl executes the given template text on data, writing the result to w.
func tmpl(w io.Writer, text string, data interface{}) {
	t := template.New("top")
	t.Funcs(template.FuncMap{"trim": strings.TrimSpace, "capitalize": capitalize})
	template.Must(t.Parse(text))
	ew := &errWriter{w: w}
	err := t.Execute(ew, data)
	if ew.err != nil {
		// I/O error writing. Ignore write on closed pipe.
		if strings.Contains(ew.err.Error(), "pipe") {
			SetExitStatus(1)
			Exit()
		}
		Fatalf("writing output: %v", ew.err)
	}
	if err != nil {
		panic(err)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToTitle(r)) + s[n:]
}

// PrintUsage prints usage of cmd to w
func PrintUsage(w io.Writer, cmd *Command) {
	bw := bufio.NewWriter(w)
	tmpl(bw, usageTemplate, makeTmplData(cmd))
	bw.Flush()
}

// buildCommandsText build text of command and its children as template
func buildCommandsText(cmd *Command) {
	buildCommandText(cmd)
	for _, cmd := range cmd.Commands {
		buildCommandsText(cmd)
	}
}

// buildCommandText build command text as template
func buildCommandText(cmd *Command) {
	cmd.UsageLine = buildText(cmd.UsageLine, makeTmplData(cmd))
	cmd.Short = buildText(cmd.Short, makeTmplData(cmd))
	cmd.Long = buildText(cmd.Long, makeTmplData(cmd))
}

func buildText(text string, data interface{}) string {
	buf := bytes.NewBuffer([]byte{})
	tmpl(buf, text, data)
	return buf.String()
}

type tmplData struct {
	*Command
	*CommandEnvHolder
}

func makeTmplData(cmd *Command) tmplData {
	return tmplData{
		Command:          cmd,
		CommandEnvHolder: &CommandEnv,
	}
}
