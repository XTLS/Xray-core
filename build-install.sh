#!/usr/bin/env bash
# Сборка xray из текущего дерева и установка поверх рабочего бинарника
# с бэкапом старого.
#
#   ./build-install.sh              собрать и установить
#   ./build-install.sh --restart    ещё и перезапустить systemd-сервис
#   ./build-install.sh --build-only собрать, ничего не устанавливать
#
# Переменные окружения:
#   INSTALL_PATH   куда ставить бинарник        (по умолчанию /usr/local/bin/xray)
#   SERVICE        имя systemd-сервиса          (по умолчанию xray)
#   KEEP_BACKUPS   сколько бэкапов хранить      (по умолчанию 5)
set -euo pipefail

INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/xray}"
SERVICE="${SERVICE:-xray}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"

RESTART=0
BUILD_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --restart)    RESTART=1 ;;
        --build-only) BUILD_ONLY=1 ;;
        -h|--help)    sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "неизвестный аргумент: $arg" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$(readlink -f "$0")")"
OUT="$PWD/xray"

# sudo только если не root
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

# 1. Удаляем ранее собранный бинарник в папке сборки
if [ -e "$OUT" ]; then
    echo ">> удаляю старый собранный бинарник: $OUT"
    rm -f -- "$OUT"
fi

# 2. Сборка
echo ">> сборка ($(go version))"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o "$OUT" ./main
chmod 0755 "$OUT"
echo ">> собрано: $OUT ($(du -h "$OUT" | cut -f1))"
"$OUT" version | head -n 1

if [ "$BUILD_ONLY" -eq 1 ]; then
    exit 0
fi

# 3. Бэкап текущего бинарника
INSTALL_DIR="$(dirname "$INSTALL_PATH")"
if [ -e "$INSTALL_PATH" ]; then
    BACKUP="${INSTALL_PATH}.bak-$(date +%Y%m%d-%H%M%S)"
    echo ">> бэкап: $INSTALL_PATH -> $BACKUP"
    $SUDO cp -p -- "$INSTALL_PATH" "$BACKUP"
else
    echo ">> $INSTALL_PATH не существует, бэкапить нечего"
fi

# 4. Установка: копируем во временный файл в той же папке и переименовываем.
#    mv атомарен и не падает с «Text file busy», даже если xray сейчас запущен.
TMP="${INSTALL_PATH}.new.$$"
$SUDO install -m 0755 -- "$OUT" "$TMP"
$SUDO mv -f -- "$TMP" "$INSTALL_PATH"
echo ">> установлено: $INSTALL_PATH"
"$INSTALL_PATH" version | head -n 1

# 5. Чистим старые бэкапы (только наши, по маске .bak-<дата>)
if [ "$KEEP_BACKUPS" -gt 0 ]; then
    # shellcheck disable=SC2012
    ls -1t -- "${INSTALL_PATH}".bak-* 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" | while read -r old; do
        echo ">> удаляю старый бэкап: $old"
        $SUDO rm -f -- "$old"
    done
fi

# 6. Перезапуск сервиса по желанию
if [ "$RESTART" -eq 1 ]; then
    echo ">> перезапуск $SERVICE"
    $SUDO systemctl restart "$SERVICE"
    $SUDO systemctl --no-pager --lines=0 status "$SERVICE" || true
else
    echo ">> сервис не перезапускался; чтобы применить: sudo systemctl restart $SERVICE"
fi
