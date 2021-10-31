package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println("can not get current working directory")
		os.Exit(1)
	}
	pkg := filepath.Base(pwd)
	if pkg == "xray-core" {
		pkg = "core"
	}

	file, err := os.OpenFile("errors.generated.go", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		fmt.Printf("Failed to generate errors.generated.go: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	fmt.Fprintf(file, `package %s

import "github.com/xtls/xray-core/common/errors"

type errPathObjHolder struct{}

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).WithPathObj(errPathObjHolder{})
}
`, pkg)
}
