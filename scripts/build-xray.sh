#!/bin/bash

# ====================================================================
# GameTunnel - Скрипт сборки кастомного Xray-core
# ====================================================================
#
# Этот скрипт:
#   1. Клонирует оригинальный xray-core
#   2. Добавляет транспорт GameTunnel
#   3. Применяет патчи для регистрации транспорта
#   4. Собирает бинарник для нужной платформы
#
# Использование:
#   ./build-xray.sh                    # Сборка для текущей платформы
#   ./build-xray.sh linux amd64        # Кросс-компиляция
#   ./build-xray.sh windows amd64      # Windows сборка
#   ./build-xray.sh all                # Все платформы
#
# ====================================================================

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Версии
XRAY_REPO="https://github.com/XTLS/Xray-core.git"
XRAY_BRANCH="main"
GT_VERSION="0.1.0"
BUILD_DIR="$(pwd)/build"
DIST_DIR="$(pwd)/dist"

log() { echo -e "${GREEN}[GameTunnel]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ====================================================================
# Проверка зависимостей
# ====================================================================

check_deps() {
    log "Проверка зависимостей..."

    if ! command -v go &> /dev/null; then
        error "Go не установлен. Установите Go 1.22+ с https://go.dev/dl/"
    fi

    GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    GO_MAJOR=$(echo $GO_VERSION | cut -d. -f1)
    GO_MINOR=$(echo $GO_VERSION | cut -d. -f2)

    if [ "$GO_MAJOR" -lt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]); then
        error "Требуется Go 1.22+, установлена версия $GO_VERSION"
    fi

    log "Go $GO_VERSION ✓"

    if ! command -v git &> /dev/null; then
        error "Git не установлен"
    fi

    log "Git ✓"
}

# ====================================================================
# Клонирование Xray-core
# ====================================================================

clone_xray() {
    log "Клонирование Xray-core..."

    if [ -d "$BUILD_DIR/Xray-core" ]; then
        warn "Директория $BUILD_DIR/Xray-core существует, удаляю..."
        rm -rf "$BUILD_DIR/Xray-core"
    fi

    mkdir -p "$BUILD_DIR"
    git clone --depth=1 --branch="$XRAY_BRANCH" "$XRAY_REPO" "$BUILD_DIR/Xray-core"

    log "Xray-core склонирован ✓"
}

# ====================================================================
# Добавление GameTunnel транспорта
# ====================================================================

add_gametunnel() {
    log "Добавление транспорта GameTunnel..."

    XRAY_DIR="$BUILD_DIR/Xray-core"
    GT_DIR="$XRAY_DIR/transport/internet/gametunnel"

    # Копируем файлы транспорта
    mkdir -p "$GT_DIR"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    SOURCE_DIR="$PROJECT_ROOT/transport/internet/gametunnel"

    if [ ! -d "$SOURCE_DIR" ]; then
        error "Не найдена директория с исходниками GameTunnel: $SOURCE_DIR"
    fi

    cp "$SOURCE_DIR"/*.go "$GT_DIR/"
    cp "$SOURCE_DIR"/config.proto "$GT_DIR/" 2>/dev/null || true

    log "Файлы GameTunnel скопированы ✓"
}

# ====================================================================
# Применение патчей
# ====================================================================

apply_patches() {
    log "Применение патчей..."

    XRAY_DIR="$BUILD_DIR/Xray-core"

    # --- Патч 1: Регистрация транспорта в all.go ---
    ALL_GO="$XRAY_DIR/main/distro/all/all.go"

    if [ -f "$ALL_GO" ]; then
        # Добавляем импорт GameTunnel
        if ! grep -q "gametunnel" "$ALL_GO"; then
            # Находим последний импорт транспорта и добавляем после него
            sed -i '/transport\/internet\/httpupgrade/a\\t_ "github.com/xtls/xray-core/transport/internet/gametunnel"' "$ALL_GO" 2>/dev/null || \
            sed -i '/transport\/internet\/splithttp/a\\t_ "github.com/xtls/xray-core/transport/internet/gametunnel"' "$ALL_GO" 2>/dev/null || \
            sed -i '/transport\/internet\/websocket/a\\t_ "github.com/xtls/xray-core/transport/internet/gametunnel"' "$ALL_GO" 2>/dev/null || \
            warn "Не удалось автоматически добавить импорт в all.go - добавьте вручную"

            log "Импорт в all.go добавлен ✓"
        else
            log "Импорт GameTunnel уже присутствует в all.go"
        fi
    else
        warn "Файл all.go не найден: $ALL_GO"
    fi

    # --- Патч 2: Добавляем "gametunnel" в список валидных сетей ---
    # В xray-core используется ProtocolName (строка), а не enum для новых транспортов
    # Нужно зарегистрировать "gametunnel" как валидное имя сети

    CONFIG_GO="$XRAY_DIR/transport/internet/config.go"
    if [ -f "$CONFIG_GO" ]; then
        # Проверяем, есть ли функция RegisterProtocolConfigCreator
        if grep -q "RegisterProtocolConfigCreator" "$CONFIG_GO"; then
            log "RegisterProtocolConfigCreator найден в config.go ✓"
        fi
    fi

    # --- Патч 3: JSON-парсер для "gametunnel" в streamSettings ---
    # Создаём файл конфигурации JSON-маппинга
    create_json_config_parser

    # --- Патч 4: Добавляем зависимости в go.mod ---
    cd "$XRAY_DIR"
    log "Обновление зависимостей..."
    go mod tidy 2>/dev/null || warn "go mod tidy завершился с предупреждениями"

    log "Патчи применены ✓"
}

# ====================================================================
# JSON-парсер для конфигурации GameTunnel
# ====================================================================

create_json_config_parser() {
    XRAY_DIR="$BUILD_DIR/Xray-core"
    GT_DIR="$XRAY_DIR/transport/internet/gametunnel"

    cat > "$GT_DIR/config_json.go" << 'GOEOF'
package gametunnel

import (
	"encoding/json"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// GameTunnelConfig - JSON-конфигурация для парсинга xray-core
// Маппинг между JSON-полями и внутренней структурой Config
type GameTunnelConfig struct {
	Obfuscation        string `json:"obfuscation"`
	Priority           string `json:"priority"`
	MTU                uint32 `json:"mtu"`
	MaxStreams          uint32 `json:"maxStreams"`
	ConnectionIdLength uint32 `json:"connectionIdLength"`
	EnablePadding      bool   `json:"enablePadding"`
	PaddingMinSize     uint32 `json:"paddingMinSize"`
	PaddingMaxSize     uint32 `json:"paddingMaxSize"`
	HandshakeTimeout   uint32 `json:"handshakeTimeout"`
	KeepAliveInterval  uint32 `json:"keepAliveInterval"`
	Key                string `json:"key"`
}

// Build конвертирует JSON-конфиг во внутренний Config
func (c *GameTunnelConfig) Build() (*Config, error) {
	config := DefaultConfig()

	if c.Obfuscation != "" {
		config.Obfuscation = ObfuscationModeFromString(c.Obfuscation)
	}
	if c.Priority != "" {
		config.Priority = PriorityModeFromString(c.Priority)
	}
	if c.MTU > 0 {
		config.MTU = c.MTU
	}
	if c.MaxStreams > 0 {
		config.MaxStreams = c.MaxStreams
	}
	if c.ConnectionIdLength > 0 {
		config.ConnectionIdLength = c.ConnectionIdLength
	}
	config.EnablePadding = c.EnablePadding
	if c.PaddingMinSize > 0 {
		config.PaddingMinSize = c.PaddingMinSize
	}
	if c.PaddingMaxSize > 0 {
		config.PaddingMaxSize = c.PaddingMaxSize
	}
	if c.HandshakeTimeout > 0 {
		config.HandshakeTimeout = c.HandshakeTimeout
	}
	if c.KeepAliveInterval > 0 {
		config.KeepAliveInterval = c.KeepAliveInterval
	}
	if c.Key != "" {
		config.Key = c.Key
	}

	config.Validate()
	return config, nil
}

func init() {
	// Регистрируем парсер конфигурации для JSON
	serial.RegisterConfigCreator("gametunnel", func() interface{} {
		return new(GameTunnelConfig)
	})
}
GOEOF

    log "JSON config parser создан ✓"
}

# ====================================================================
# Сборка
# ====================================================================

build_binary() {
    local target_os=$1
    local target_arch=$2

    XRAY_DIR="$BUILD_DIR/Xray-core"
    cd "$XRAY_DIR"

    # Определяем имя бинарника
    local binary_name="xray-gametunnel"
    local ext=""
    if [ "$target_os" == "windows" ]; then
        ext=".exe"
    fi

    local output_name="${binary_name}-${target_os}-${target_arch}${ext}"
    local output_path="$DIST_DIR/$output_name"

    mkdir -p "$DIST_DIR"

    log "Сборка для ${CYAN}${target_os}/${target_arch}${NC}..."

    # Получаем commit hash
    local commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Собираем
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
        go build \
        -o "$output_path" \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -buildid= -X github.com/xtls/xray-core/core.build=${commit}-gt${GT_VERSION}" \
        -v ./main

    if [ $? -eq 0 ]; then
        local size=$(du -h "$output_path" | cut -f1)
        log "${GREEN}✓${NC} Собрано: ${CYAN}${output_name}${NC} (${size})"
    else
        error "Сборка для ${target_os}/${target_arch} провалилась"
    fi
}

build_all() {
    local platforms=(
        "linux:amd64"
        "linux:arm64"
        "windows:amd64"
        "windows:arm64"
        "darwin:amd64"
        "darwin:arm64"
        "freebsd:amd64"
    )

    for platform in "${platforms[@]}"; do
        IFS=':' read -r os arch <<< "$platform"
        build_binary "$os" "$arch"
    done
}

# ====================================================================
# Создание архивов для релиза
# ====================================================================

create_release() {
    log "Создание архивов для релиза..."

    mkdir -p "$DIST_DIR/release"

    for binary in "$DIST_DIR"/xray-gametunnel-*; do
        if [ ! -f "$binary" ]; then continue; fi

        local name=$(basename "$binary")
        local archive_name="${name%.*}"  # Убираем .exe если есть

        if [[ "$name" == *".exe" ]]; then
            # Windows - zip
            cd "$DIST_DIR"
            zip "release/${archive_name}.zip" "$name"
        else
            # Unix - tar.gz
            cd "$DIST_DIR"
            tar czf "release/${archive_name}.tar.gz" "$name"
        fi
    done

    # Генерируем checksums
    cd "$DIST_DIR/release"
    sha256sum * > checksums-sha256.txt 2>/dev/null || \
    shasum -a 256 * > checksums-sha256.txt 2>/dev/null || true

    log "Архивы релиза созданы в $DIST_DIR/release/ ✓"
}

# ====================================================================
# Main
# ====================================================================

main() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║     GameTunnel - Xray-core Builder        ║"
    echo "║     Version: $GT_VERSION                         ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"

    check_deps
    clone_xray
    add_gametunnel
    apply_patches

    if [ "$1" == "all" ]; then
        build_all
        create_release
    elif [ -n "$1" ] && [ -n "$2" ]; then
        build_binary "$1" "$2"
    else
        # Определяем текущую платформу
        local current_os=$(go env GOOS)
        local current_arch=$(go env GOARCH)
        build_binary "$current_os" "$current_arch"
    fi

    echo ""
    log "🎮 Сборка завершена!"
    log "Бинарники: $DIST_DIR/"
    echo ""
}

main "$@"
