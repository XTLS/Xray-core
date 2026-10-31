package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

var (
	directory = flag.String("pwd", "", "Working directory of Xray vprotogen.")
	mode      = flag.String("mode", "generate", "Execution mode. 'generate' (default) compiles and saves changes. 'check' reports out-of-date files and exits with non-zero.")
)

// topoSort sorts file descriptors so each dependency appears before files importing it.
func topoSort(files []protoreflect.FileDescriptor) []*descriptorpb.FileDescriptorProto {
	fileMap := make(map[string]protoreflect.FileDescriptor)
	for _, f := range files {
		fileMap[f.Path()] = f
	}

	visited := make(map[string]bool)
	var sorted []*descriptorpb.FileDescriptorProto

	var visit func(fd protoreflect.FileDescriptor)
	visit = func(fd protoreflect.FileDescriptor) {
		if visited[fd.Path()] {
			return
		}
		visited[fd.Path()] = true

		imports := fd.Imports()
		for i := 0; i < imports.Len(); i++ {
			if dep, ok := fileMap[imports.Get(i).Path()]; ok {
				visit(dep)
			}
		}
		sorted = append(sorted, protodesc.ToFileDescriptorProto(fd))
	}

	for _, f := range files {
		visit(f)
	}
	return sorted
}

func runPlugin(pluginName, pwd string, req *pluginpb.CodeGeneratorRequest) (*pluginpb.CodeGeneratorResponse, error) {
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("go", "tool", pluginName)
	cmd.Dir = pwd
	cmd.Stdin = bytes.NewReader(reqBytes)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, stderr.String())
	}

	var resp pluginpb.CodeGeneratorResponse
	if err := proto.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if resp.GetError() != "" {
		return nil, fmt.Errorf("%s", resp.GetError())
	}
	return &resp, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of vprotogen:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if !filepath.IsAbs(*directory) {
		pwd, err := os.Getwd()
		if err != nil {
			fmt.Println("Can not get current working directory.")
			os.Exit(1)
		}
		*directory = filepath.Join(pwd, *directory)
	}
	pwd := *directory

	isCheck := false
	switch *mode {
	case "generate", "":
		isCheck = false
	case "check":
		isCheck = true
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized 'mode': %s. Use 'generate' or 'check'.\n", *mode)
		os.Exit(1)
	}

	if isCheck {
		fmt.Println("Checking for out-of-date Protobuf generated files...")
	}

	var protoFiles []string
	var existingPbFiles []string
	err := filepath.WalkDir(pwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(d.Name(), ".proto") {
			rel, _ := filepath.Rel(pwd, path)
			protoFiles = append(protoFiles, filepath.ToSlash(rel))
		}
		if strings.HasSuffix(d.Name(), ".pb.go") {
			existingPbFiles = append(existingPbFiles, path)
		}
		return nil
	})
	if err != nil {
		fmt.Println("Walk error:", err)
		os.Exit(1)
	}

	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: []string{pwd},
		}),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}

	linkedFiles, err := compiler.Compile(context.Background(), protoFiles...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Protobuf compilation failed:\n%v\n", err)
		os.Exit(1)
	}

	var fdList []protoreflect.FileDescriptor
	for _, f := range linkedFiles {
		fdList = append(fdList, f)
	}

	req := &pluginpb.CodeGeneratorRequest{
		FileToGenerate: protoFiles,
		Parameter:      new("paths=source_relative"),
		ProtoFile:      topoSort(fdList),
	}

	var diffCount int
	generatedFiles := make(map[string]struct{})
	for _, plugin := range []string{"protoc-gen-go", "protoc-gen-go-grpc"} {
		resp, err := runPlugin(plugin, pwd, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s failed: %v\n", plugin, err)
			os.Exit(1)
		}

		for _, f := range resp.File {
			targetPath := filepath.Join(pwd, filepath.FromSlash(f.GetName()))
			generatedFiles[targetPath] = struct{}{}
			content := []byte(f.GetContent())

			hasDiff := false
			existing, err := os.ReadFile(targetPath)
			if err != nil {
				hasDiff = true
			} else {
				oldNorm := bytes.ReplaceAll(existing, []byte("\r\n"), []byte("\n"))
				newNorm := bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
				if !bytes.Equal(oldNorm, newNorm) {
					hasDiff = true
				}
			}

			if hasDiff {
				diffCount++
				fmt.Println(targetPath)

				if isCheck {
					continue
				}

				if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
					os.Exit(1)
				}
				mode := os.FileMode(0o644)
				if stat, err := os.Stat(targetPath); err == nil {
					mode = stat.Mode().Perm()
				}
				if err := os.WriteFile(targetPath, content, mode); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", targetPath, err)
					os.Exit(1)
				}
			}
		}
	}

	for _, path := range existingPbFiles {
		if _, ok := generatedFiles[path]; !ok {
			diffCount++
			if isCheck {
				fmt.Printf("Orphaned Protobuf file: %s\n", path)
			} else {
				fmt.Printf("Removing orphaned Protobuf file: %s\n", path)
				if err := os.Remove(path); err != nil {
					fmt.Fprintf(os.Stderr, "Error removing %s: %v\n", path, err)
					os.Exit(1)
				}
			}
		}
	}

	if isCheck {
		if diffCount > 0 {
			fmt.Println("Protobuf generated file problem(s) found.")
			fmt.Println("Please run 'go run ./infra/vprotogen' to regenerate them.")
			os.Exit(1)
		}
		fmt.Println("All Protobuf generated file check has been passed.")
	}
}
