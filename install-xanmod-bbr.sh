#!/usr/bin/env bash
set -euo pipefail

# install-xanmod-bbr.sh
# Установка XanMod + включение BBR + отключение IPv6
# Работает на Debian/Ubuntu (apt)

REPO_KEY_URL="https://gitlab.com/afrd.gpg"
REPO_LINE="deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main"
REPO_LIST="/etc/apt/sources.list.d/xanmod-release.list"
KEYRING_PATH="/usr/share/keyrings/xanmod-archive-keyring.gpg"
PSABI_CHECK_URL="https://dl.xanmod.org/check_x86-64_psabi.sh"

SYSCTL_FILE="/etc/sysctl.d/99-xanmod-bbr-ipv6.conf"
MARKER_FILE="/var/lib/xanmod-bbr/.needs_reboot"
KERNEL_PKG="${KERNEL_PKG:-linux-xanmod-x64v3}"   # можно переопределить: KERNEL_PKG=linux-xanmod-x64v2 ./script.sh
AUTO_REBOOT="${AUTO_REBOOT:-0}"                  # AUTO_REBOOT=1 ./script.sh

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Запусти от root: sudo $0"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_deps() {
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates gnupg wget awk
}

add_repo_key() {
  install -d -m 0755 "$(dirname "$KEYRING_PATH")"
  if [[ -f "$KEYRING_PATH" ]]; then
    echo "[OK] Keyring уже существует: $KEYRING_PATH"
    return
  fi
  echo "[..] Добавляю ключ репозитория..."
  wget -qO - "$REPO_KEY_URL" | gpg --dearmor -o "$KEYRING_PATH"
  chmod 0644 "$KEYRING_PATH"
  echo "[OK] Ключ добавлен: $KEYRING_PATH"
}

add_repo() {
  if [[ -f "$REPO_LIST" ]] && grep -qF "$REPO_LINE" "$REPO_LIST"; then
    echo "[OK] Репозиторий уже добавлен: $REPO_LIST"
    return
  fi
  echo "[..] Добавляю репозиторий..."
  echo "$REPO_LINE" > "$REPO_LIST"
  chmod 0644 "$REPO_LIST"
  echo "[OK] Репозиторий добавлен: $REPO_LIST"
}

check_arch() {
  echo "[..] Проверяю поддерживаемую архитектуру (PSABI)..."
  # Скрипт выводит x64v1/x64v2/x64v3/x64v4
  local result
  result="$(wget -qO - "$PSABI_CHECK_URL" | awk -f - | tail -n 1 || true)"
  echo "[INFO] PSABI: ${result:-не удалось определить}"
}

install_kernel() {
  echo "[..] Обновляю список пакетов..."
  apt-get update -y

  echo "[..] Устанавливаю ядро: $KERNEL_PKG"
  apt-get install -y "$KERNEL_PKG"

  install -d -m 0755 "$(dirname "$MARKER_FILE")"
  touch "$MARKER_FILE"
  echo "[OK] Ядро установлено. Нужна перезагрузка."
}

write_sysctl() {
  echo "[..] Пишу sysctl настройки в: $SYSCTL_FILE"
  cat > "$SYSCTL_FILE" <<'EOF'
# XanMod + BBR + disable IPv6

# BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  chmod 0644 "$SYSCTL_FILE"

  echo "[..] Применяю sysctl..."
  sysctl --system >/dev/null
  echo "[OK] sysctl применён."
}

post_reboot_checks() {
  echo "[..] Выполняю depmod -a"
  depmod -a || true

  echo "[..] Проверяю модуль tcp_bbr (modinfo)..."
  if modinfo tcp_bbr >/dev/null 2>&1; then
    echo "[OK] tcp_bbr доступен."
  else
    echo "[WARN] tcp_bbr не найден через modinfo. Возможно, ядро ещё не XanMod/BBR или модуль не в этой сборке."
  fi

  echo "[..] Текущие значения sysctl:"
  sysctl net.core.default_qdisc net.ipv4.tcp_congestion_control \
         net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6 || true
}

main() {
  require_root

  if ! have_cmd apt-get; then
    echo "Этот скрипт рассчитан на Debian/Ubuntu (apt)."
    exit 1
  fi

  # Если уже был 1-й проход и попросили ребут — значит мы сейчас после ребута.
  if [[ -f "$MARKER_FILE" ]]; then
    echo "[INFO] Обнаружен маркер перезагрузки. Выполняю пост-проверки..."
    rm -f "$MARKER_FILE"
    post_reboot_checks
    echo "[DONE] Готово."
    exit 0
  fi

  ensure_deps
  add_repo_key
  add_repo
  check_arch
  install_kernel
  write_sysctl

  if [[ "$AUTO_REBOOT" == "1" ]]; then
    echo "[INFO] AUTO_REBOOT=1 -> перезагрузка..."
    reboot
  else
    echo
    echo "=== Дальше нужно перезагрузиться ==="
    echo "Выполни: sudo reboot"
    echo "После перезагрузки запусти этот же скрипт ещё раз:"
    echo "sudo $0"
  fi
}

main "$@"
