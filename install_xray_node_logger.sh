#!/bin/sh
set -eu

APP_DIR="/opt/xray-log-bot"
OUT_DIR="$APP_DIR/out"
SCRIPT_PATH="$APP_DIR/xray-log-bot.sh"
CONF_PATH="$APP_DIR/xray-log-bot.conf"
README_PATH="$APP_DIR/README.md"
SERVICE_NAME="xray-log-bot.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

log() {
  printf '%s\n' "[install $(date '+%F %T')] $*"
}

fail() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Запусти от root. Пример: curl -fsSL ... | sudo sh"
  fi
}

need_tty() {
  if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    fail "Не удалось получить доступ к /dev/tty для интерактивного ввода"
  fi
}

install_pkg_if_missing() {
  BIN_NAME="$1"
  PKG_NAME="$2"

  if ! command -v "$BIN_NAME" >/dev/null 2>&1; then
    log "Устанавливаю пакет: $PKG_NAME"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y "$PKG_NAME"
  fi
}

ask() {
  VAR_NAME="$1"
  PROMPT="$2"
  DEFAULT_VALUE="$3"

  if [ -n "$DEFAULT_VALUE" ]; then
    printf '%s' "$PROMPT [$DEFAULT_VALUE]: " > /dev/tty
  else
    printf '%s' "$PROMPT: " > /dev/tty
  fi

  IFS= read -r INPUT_VALUE < /dev/tty || true
  INPUT_VALUE=$(printf '%s' "$INPUT_VALUE" | tr -d '\r')

  if [ -z "$INPUT_VALUE" ]; then
    INPUT_VALUE="$DEFAULT_VALUE"
  fi

  eval "$VAR_NAME=\$INPUT_VALUE"
}

ask_secret() {
  VAR_NAME="$1"
  PROMPT="$2"

  printf '%s' "$PROMPT: " > /dev/tty
  stty -echo < /dev/tty
  IFS= read -r INPUT_VALUE < /dev/tty || true
  stty echo < /dev/tty
  printf '\n' > /dev/tty

  INPUT_VALUE=$(printf '%s' "$INPUT_VALUE" | tr -d '\r')

  if [ -z "$INPUT_VALUE" ]; then
    fail "$PROMPT не может быть пустым"
  fi

  eval "$VAR_NAME=\$INPUT_VALUE"
}

check_systemctl() {
  command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl не найден"
}

check_docker() {
  command -v docker >/dev/null 2>&1 || fail "Docker не найден. Сначала установи Docker."
  docker info >/dev/null 2>&1 || fail "Docker установлен, но daemon недоступен"
}

check_container_exists() {
  if ! docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    fail "Контейнер '$CONTAINER_NAME' не найден"
  fi
}

check_log_path_in_container() {
  if ! docker exec "$CONTAINER_NAME" sh -lc "[ -f \"$LOG_PATH_IN_CONTAINER\" ]"; then
    fail "Файл лога '$LOG_PATH_IN_CONTAINER' не найден внутри контейнера '$CONTAINER_NAME'"
  fi

  if ! docker exec "$CONTAINER_NAME" sh -lc "test -r \"$LOG_PATH_IN_CONTAINER\""; then
    fail "Файл лога '$LOG_PATH_IN_CONTAINER' существует, но недоступен для чтения внутри контейнера '$CONTAINER_NAME'"
  fi
}

check_telegram_api() {
  log "Проверяю Telegram API getMe"
  RESP="$(curl -fsS --max-time 20 "https://api.telegram.org/bot${BOT_TOKEN}/getMe" 2>/dev/null || true)"
  echo "$RESP" | grep '"ok":true' >/dev/null 2>&1 || fail "Не удалось пройти проверку Telegram API getMe. Проверь BOT_TOKEN."
}

send_test_to_telegram() {
  TEST_FILE="/tmp/xray_log_bot_test_$$.txt"
  cat > "$TEST_FILE" <<EOF
Xray Log Bot test message

NODE_NAME=$NODE_NAME
CONTAINER_NAME=$CONTAINER_NAME
LOG_PATH_IN_CONTAINER=$LOG_PATH_IN_CONTAINER
DATE=$(date '+%F %T')
HOST=$(hostname 2>/dev/null || echo unknown)
CHAT_ID=$CHAT_ID
MESSAGE_THREAD_ID=${MESSAGE_THREAD_ID:-}
EOF

  log "Отправляю тестовый файл в Telegram"

  if [ -n "${MESSAGE_THREAD_ID:-}" ]; then
    RESP="$(curl -sS --max-time 60 \
      -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendDocument" \
      -F "chat_id=${CHAT_ID}" \
      -F "message_thread_id=${MESSAGE_THREAD_ID}" \
      -F "caption=Test from xray-log-bot installer" \
      -F "document=@${TEST_FILE}" \
      2>/dev/null || true)"
  else
    RESP="$(curl -sS --max-time 60 \
      -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendDocument" \
      -F "chat_id=${CHAT_ID}" \
      -F "caption=Test from xray-log-bot installer" \
      -F "document=@${TEST_FILE}" \
      2>/dev/null || true)"
  fi

  rm -f "$TEST_FILE"

  echo "$RESP" | grep '"ok":true' >/dev/null 2>&1 || fail "Не удалось отправить тестовый файл в Telegram. Проверь CHAT_ID, MESSAGE_THREAD_ID и права бота на чат."
}

write_main_script() {
  cat > "$SCRIPT_PATH" <<'EOF'
#!/usr/bin/env bash
set -u
set -o pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$BASE_DIR/xray-log-bot.conf}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config not found: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

mkdir -p "$OUTPUT_DIR"

CURRENT_FILE=""
CURRENT_START_EPOCH=0
CURRENT_END_EPOCH=0
LOCK_FILE="/tmp/xray-log-bot.lock"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "Another instance is already running"
  exit 1
fi

log() {
  echo "[$(date '+%F %T')] $*"
}

csv_escape() {
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

format_ts_file() {
  date -d "@$1" '+%Y-%m-%d_%H-%M-%S'
}

make_file_path() {
  local start_epoch="$1"
  local end_epoch="$2"
  local start_str end_str
  start_str="$(format_ts_file "$start_epoch")"
  end_str="$(format_ts_file "$end_epoch")"
  printf '%s/%s_%s__%s.csv' "$OUTPUT_DIR" "$NODE_NAME" "$start_str" "$end_str"
}

open_new_file() {
  local start_epoch="$1"
  local end_epoch="$2"

  CURRENT_FILE="$(make_file_path "$start_epoch" "$end_epoch")"
  CURRENT_START_EPOCH="$start_epoch"
  CURRENT_END_EPOCH="$end_epoch"

  cat > "$CURRENT_FILE" <<'CSVEOF'
date,time,protocol_in,protocol_out,user_ip,target,port,inbound,outbound,user_id
CSVEOF

  log "Opened new file: $CURRENT_FILE"
}

zip_file() {
  local src_file="$1"
  local zip_file="${src_file%.csv}.zip"
  local base_name
  base_name="$(basename "$src_file")"

  rm -f "$zip_file"

  (
    cd "$(dirname "$src_file")" || exit 1
    zip -q -j "$zip_file" "$base_name"
  ) || return 1

  rm -f "$src_file"
  printf '%s\n' "$zip_file"
}

rotate_file_if_needed() {
  local now
  now="$(date +%s)"

  if (( now < CURRENT_END_EPOCH )); then
    return 0
  fi

  local old_file="$CURRENT_FILE"
  local new_start="$now"
  local new_end=$(( new_start + ROTATE_SECONDS ))

  open_new_file "$new_start" "$new_end"

  if [[ -n "$old_file" && -f "$old_file" ]]; then
    local zipped=""
    if zipped="$(zip_file "$old_file")"; then
      log "Rotated and zipped: $zipped"
    else
      log "Failed to zip file: $old_file"
    fi
  fi
}

send_ready_archives() {
  shopt -s nullglob
  local archives=("$OUTPUT_DIR"/*.zip)
  shopt -u nullglob

  local current_base=""
  current_base="$(basename "$CURRENT_FILE" .csv)"

  local archive base resp rc
  local -a curl_args

  for archive in "${archives[@]}"; do
    base="$(basename "$archive")"

    if [[ "$base" == "${current_base}.zip" ]]; then
      continue
    fi

    log "Sending to Telegram: $base"

    curl_args=(
      -sS
      --max-time 600
      -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendDocument"
      -F "chat_id=${CHAT_ID}"
      -F "caption=${base}"
      -F "document=@${archive}"
    )

    if [[ -n "${MESSAGE_THREAD_ID:-}" ]]; then
      curl_args+=(-F "message_thread_id=${MESSAGE_THREAD_ID}")
    fi

    resp="$(curl "${curl_args[@]}" 2>&1)"
    rc=$?

    if [[ $rc -eq 0 && "$resp" == *'"ok":true'* ]]; then
      rm -f -- "$archive"
      log "Sent and removed: $base"
    else
      log "Telegram send failed for $base"
      log "Response: $resp"
    fi
  done
}

trim_spaces() {
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

parse_line_to_csv() {
  local line="$1"

  [[ -z "$line" ]] && return 1
  [[ "$line" == *" DOH//"* ]] && return 1
  [[ "$line" == *" got answer:"* ]] && return 1

  local re='^([0-9]{4}/[0-9]{2}/[0-9]{2})[[:space:]]+([0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?[[:space:]]+from[[:space:]]+((tcp|udp):)?([0-9A-Fa-f:.]+):[0-9]+[[:space:]]+accepted[[:space:]]+(tcp|udp):([^:[:space:]]+):([0-9]+)[[:space:]]+\[([^]]+)\][[:space:]]+email:[[:space:]]+([0-9]+\.)?([^[:space:]]+)[[:space:]]*$'

  [[ ! "$line" =~ $re ]] && return 1

  local date_part="${BASH_REMATCH[1]}"
  local time_part="${BASH_REMATCH[2]}"
  local proto_in="${BASH_REMATCH[5]}"
  local user_ip="${BASH_REMATCH[6]}"
  local proto_out="${BASH_REMATCH[7]}"
  local target="${BASH_REMATCH[8]}"
  local port="${BASH_REMATCH[9]}"
  local bracket="${BASH_REMATCH[10]}"
  local user_id="${BASH_REMATCH[12]}"

  local inbound outbound
  if [[ "$bracket" == *">>"* ]]; then
    inbound="${bracket%%>>*}"
    outbound="${bracket#*>>}"
  elif [[ "$bracket" == *"->"* ]]; then
    inbound="${bracket%%->*}"
    outbound="${bracket#*->}"
  else
    inbound="$bracket"
    outbound=""
  fi

  inbound="$(printf '%s' "$inbound" | trim_spaces)"
  outbound="$(printf '%s' "$outbound" | trim_spaces)"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$date_part")" \
    "$(csv_escape "$time_part")" \
    "$(csv_escape "$proto_in")" \
    "$(csv_escape "${proto_out,,}")" \
    "$(csv_escape "$user_ip")" \
    "$(csv_escape "$target")" \
    "$(csv_escape "$port")" \
    "$(csv_escape "$inbound")" \
    "$(csv_escape "$outbound")" \
    "$(csv_escape "$user_id")"
}

start_stream() {
  docker exec -i "$CONTAINER_NAME" sh -lc "tail -n 0 -F '$LOG_PATH_IN_CONTAINER'"
}

main() {
  local now
  now="$(date +%s)"
  open_new_file "$now" $(( now + ROTATE_SECONDS ))

  while true; do
    log "Connecting to $CONTAINER_NAME:$LOG_PATH_IN_CONTAINER"

    coproc LOGSTREAM { start_stream; }

    if [[ -z "${LOGSTREAM_PID:-}" ]]; then
      log "Failed to start docker stream"
      sleep "$RECONNECT_DELAY"
      continue
    fi

    while true; do
      rotate_file_if_needed
      send_ready_archives || true

      local line=""
      if IFS= read -r -t 1 -u "${LOGSTREAM[0]}" line; then
        rotate_file_if_needed

        local parsed=""
        if parsed="$(parse_line_to_csv "$line")"; then
          printf '%s\n' "$parsed" >> "$CURRENT_FILE"
        fi
      else
        if ! kill -0 "$LOGSTREAM_PID" 2>/dev/null; then
          log "Stream ended, reconnecting..."
          break
        fi
      fi
    done

    exec {LOGSTREAM[0]}>&- || true
    wait "$LOGSTREAM_PID" 2>/dev/null || true
    sleep "$RECONNECT_DELAY"
  done
}

main
EOF

  chmod 755 "$SCRIPT_PATH"
}

write_config() {
  cat > "$CONF_PATH" <<EOF
NODE_NAME="$NODE_NAME"
CONTAINER_NAME="$CONTAINER_NAME"
LOG_PATH_IN_CONTAINER="$LOG_PATH_IN_CONTAINER"
OUTPUT_DIR="$OUT_DIR"
BOT_TOKEN="$BOT_TOKEN"
CHAT_ID="$CHAT_ID"
MESSAGE_THREAD_ID="$MESSAGE_THREAD_ID"
ROTATE_SECONDS=$ROTATE_SECONDS
RECONNECT_DELAY=2
EOF

  chmod 600 "$CONF_PATH"
}

write_service() {
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Xray log ZIP rotator and Telegram sender
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$SCRIPT_PATH
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

write_readme() {
  cat > "$README_PATH" <<EOF
# Xray Log Bot

Папка проекта:
$APP_DIR

Файлы:
- Основной скрипт: $SCRIPT_PATH
- Конфиг: $CONF_PATH
- Выходные файлы: $OUT_DIR
- systemd service: $SERVICE_PATH

Параметры конфига:
- NODE_NAME
- CONTAINER_NAME
- LOG_PATH_IN_CONTAINER
- OUTPUT_DIR
- BOT_TOKEN
- CHAT_ID
- MESSAGE_THREAD_ID
- ROTATE_SECONDS
- RECONNECT_DELAY

Логика отправки:
- если MESSAGE_THREAD_ID пустой, отправка идёт в CHAT_ID
- если MESSAGE_THREAD_ID задан, отправка идёт в соответствующий топик

Что делает:
- читает лог из docker-контейнера
- парсит строки в CSV
- пишет CSV с заголовками
- ротирует файл каждые $ROTATE_SECONDS секунд
- упаковывает завершённый CSV в ZIP
- отправляет ZIP в Telegram
- после успешной отправки удаляет ZIP

Полезные команды:
systemctl status $SERVICE_NAME
journalctl -u $SERVICE_NAME -f
systemctl restart $SERVICE_NAME
systemctl stop $SERVICE_NAME
systemctl disable $SERVICE_NAME

Редактирование конфига:
nano $CONF_PATH

После изменения конфига:
systemctl restart $SERVICE_NAME

Проверить файлы:
ls -lah $OUT_DIR
EOF

  chmod 644 "$README_PATH"
}

start_service() {
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
}

show_summary() {
  printf '\n'
  printf '%s\n' "Установка завершена."
  printf '%s\n' ""
  printf '%s\n' "Папка проекта: $APP_DIR"
  printf '%s\n' "Основной скрипт: $SCRIPT_PATH"
  printf '%s\n' "Конфиг: $CONF_PATH"
  printf '%s\n' "README: $README_PATH"
  printf '%s\n' "Папка выходных файлов: $OUT_DIR"
  printf '%s\n' ""
  printf '%s\n' "Полезные команды:"
  printf '%s\n' "  systemctl status $SERVICE_NAME"
  printf '%s\n' "  journalctl -u $SERVICE_NAME -f"
  printf '%s\n' "  systemctl restart $SERVICE_NAME"
  printf '%s\n' "  ls -lah $OUT_DIR"
  printf '\n'
}

main() {
  need_root
  need_tty

  install_pkg_if_missing bash bash
  install_pkg_if_missing curl curl
  install_pkg_if_missing zip zip
  install_pkg_if_missing flock util-linux

  check_systemctl
  check_docker

  ask_secret BOT_TOKEN "Введите BOT_TOKEN"
  ask CHAT_ID "Введите CHAT_ID" ""
  ask MESSAGE_THREAD_ID "Введите MESSAGE_THREAD_ID (если не нужен — оставь пустым)" ""
  ask NODE_NAME "Введите NODE_NAME" "node-fi-1"
  ask ROTATE_SECONDS "Введите ROTATE_SECONDS" "10800"
  ask CONTAINER_NAME "Введите CONTAINER_NAME" "remnanode"
  ask LOG_PATH_IN_CONTAINER "Введите LOG_PATH_IN_CONTAINER" "/var/log/supervisor/xray.out.log"

  [ -n "$CHAT_ID" ] || fail "CHAT_ID не может быть пустым"
  [ -n "$NODE_NAME" ] || fail "NODE_NAME не может быть пустым"
  [ -n "$ROTATE_SECONDS" ] || fail "ROTATE_SECONDS не может быть пустым"
  [ -n "$CONTAINER_NAME" ] || fail "CONTAINER_NAME не может быть пустым"
  [ -n "$LOG_PATH_IN_CONTAINER" ] || fail "LOG_PATH_IN_CONTAINER не может быть пустым"

  check_telegram_api
  check_container_exists
  check_log_path_in_container
  send_test_to_telegram

  mkdir -p "$APP_DIR"
  mkdir -p "$OUT_DIR"

  write_main_script
  write_config
  write_service
  write_readme
  start_service
  show_summary
}

main "$@"