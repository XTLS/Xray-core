package core

//go:generate go install -v google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
//go:generate go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
//go:generate go run ../infra/vprotogen/main.go -pwd ./..
