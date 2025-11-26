#!/bin/bash
# 生成独立的 gRPC client 模块
# 从主项目复制必要的生成代码
# 关键：此脚本在 api-client 目录下执行，避免触发 core/format.go

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
API_CLIENT_DIR="$SCRIPT_DIR"

echo "Generating independent gRPC client module..."
echo "Working directory: $API_CLIENT_DIR"

# 关键：使用临时目录生成文件，然后复制到 api-client/generated
# 这样所有改动都限定在 api-client 文件夹里，不会修改主项目
cd "$PROJECT_ROOT"
GOBIN=$(go env GOBIN)
if [ -z "$GOBIN" ]; then
    GOBIN=$(go env GOPATH)/bin
fi

# 创建临时目录用于生成
TEMP_GEN_DIR=$(mktemp -d)
trap "rm -rf $TEMP_GEN_DIR" EXIT

# 创建必要的目录结构
mkdir -p "$API_CLIENT_DIR/generated/app/stats/command"
mkdir -p "$API_CLIENT_DIR/generated/app/proxyman/command"
mkdir -p "$API_CLIENT_DIR/generated/common/protocol"
mkdir -p "$API_CLIENT_DIR/generated/common/serial"

# 在临时目录中创建相同的目录结构
mkdir -p "$TEMP_GEN_DIR/app/stats/command"
mkdir -p "$TEMP_GEN_DIR/app/proxyman/command"
mkdir -p "$TEMP_GEN_DIR/common/protocol"
mkdir -p "$TEMP_GEN_DIR/common/serial"

# 只生成需要的 proto 文件到临时目录
echo "Generating only required proto files for api-client (using temp directory)..."
protoc --version

# 生成 stats service - 输出到临时目录
protoc \
    --go_out="$TEMP_GEN_DIR" \
    --go_opt=paths=source_relative \
    --go-grpc_out="$TEMP_GEN_DIR" \
    --go-grpc_opt=paths=source_relative \
    --plugin=protoc-gen-go="$GOBIN/protoc-gen-go" \
    --plugin=protoc-gen-go-grpc="$GOBIN/protoc-gen-go-grpc" \
    -I="$PROJECT_ROOT" \
    app/stats/command/command.proto

# 生成 handler service - 输出到临时目录
protoc \
    --go_out="$TEMP_GEN_DIR" \
    --go_opt=paths=source_relative \
    --go-grpc_out="$TEMP_GEN_DIR" \
    --go-grpc_opt=paths=source_relative \
    --plugin=protoc-gen-go="$GOBIN/protoc-gen-go" \
    --plugin=protoc-gen-go-grpc="$GOBIN/protoc-gen-go-grpc" \
    -I="$PROJECT_ROOT" \
    app/proxyman/command/command.proto

# 生成依赖的 proto 文件 - 输出到临时目录
protoc \
    --go_out="$TEMP_GEN_DIR" \
    --go_opt=paths=source_relative \
    --plugin=protoc-gen-go="$GOBIN/protoc-gen-go" \
    -I="$PROJECT_ROOT" \
    common/protocol/user.proto

protoc \
    --go_out="$TEMP_GEN_DIR" \
    --go_opt=paths=source_relative \
    --plugin=protoc-gen-go="$GOBIN/protoc-gen-go" \
    -I="$PROJECT_ROOT" \
    common/serial/typed_message.proto

# 从临时目录复制到 api-client/generated
echo "Copying generated gRPC code to api-client/generated..."
cp "$TEMP_GEN_DIR/app/stats/command/command_grpc.pb.go" "$API_CLIENT_DIR/generated/app/stats/command/"
cp "$TEMP_GEN_DIR/app/stats/command/command.pb.go" "$API_CLIENT_DIR/generated/app/stats/command/"
cp "$TEMP_GEN_DIR/app/proxyman/command/command_grpc.pb.go" "$API_CLIENT_DIR/generated/app/proxyman/command/"
cp "$TEMP_GEN_DIR/app/proxyman/command/command.pb.go" "$API_CLIENT_DIR/generated/app/proxyman/command/"
cp "$TEMP_GEN_DIR/common/protocol/user.pb.go" "$API_CLIENT_DIR/generated/common/protocol/"
cp "$TEMP_GEN_DIR/common/serial/typed_message.pb.go" "$API_CLIENT_DIR/generated/common/serial/"

echo "Done! Generated files are in $API_CLIENT_DIR/generated/"

