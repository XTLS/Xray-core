package lua

import (
	"os"
	"path/filepath"

	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdSign = &base.Command{
	UsageLine: "{{.Exec}} lua sign [-key seed] [-o output-file] <input-file>",
	Short:     "Sign a local Lua script for privileged execution",
	Long: `
Sign a local Lua file using a 32-byte Ed25519 private key seed in unpadded
Base64URL. Use {{.Exec}} ed25519 to generate a key pair.
Write back to the input file, or use -o to write another file (- for stdout).
`,
}

var (
	signKey    = cmdSign.Flag.String("key", "", "Ed25519 private key seed in unpadded Base64URL.")
	signOutput = cmdSign.Flag.String("o", "", "Output file, or - for stdout. Default: input file.")
)

func init() {
	cmdSign.Run = executeSign
}

func executeSign(cmd *base.Command, args []string) {
	if len(args) != 1 {
		cmd.Usage()
	}

	input, info, err := filesystem.ResolveRegularFile(args[0])
	if err != nil {
		base.Fatalf("failed to inspect Lua file: %s", err)
	}
	if filepath.Ext(input) != ".lua" {
		base.Fatalf("Lua file extension must be .lua")
	}

	code, err := os.ReadFile(input)
	if err != nil {
		base.Fatalf("failed to read Lua file: %s", err)
	}

	signed, err := xlua.SignPrivilegedScript(code, *signKey)
	if err != nil {
		base.Fatalf("failed to sign Lua file: %s", err)
	}

	if *signOutput == "-" {
		if _, err := os.Stdout.Write(signed); err != nil {
			base.Fatalf("failed to write signed Lua file: %s", err)
		}
		return
	}
	output := *signOutput
	if output == "" {
		output = input
	}
	if err := writeSignedFile(output, signed, info.Mode().Perm()); err != nil {
		base.Fatalf("failed to write signed Lua file: %s", err)
	}
}

func writeSignedFile(path string, code []byte, mode os.FileMode) error {
	if resolved, info, err := filesystem.ResolveRegularFile(path); err == nil {
		path = resolved
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".xray-lua-sign-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(code); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
