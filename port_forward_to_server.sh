#!/bin/bash
set -euo pipefail

# ================================
# DNAT helper with de-dup & sysctl
# ================================

usage() {
  echo "Использование: wget -qO- https://raw.githubusercontent.com/likstanov/scripts/refs/heads/main/port_forward_to_server.sh | $0 --ip <IP> --remote-port <REMOTE_PORT> [--local-port <LOCAL_PORT>] [--protocol <tcp|udp|both>] [--enable-ip-forward] [--static] [--delete] [--dev]"
  echo "  --ip:                 IP назначения (например, 54.37.234.130)"
  echo "  --remote-port:        Удаленный порт (например, 51820)"
  echo "  --local-port:         Локальный порт (по умолчанию = удалённому)"
  echo "  --protocol:           tcp|udp|both (по умолчанию tcp)"
  echo "  --enable-ip-forward:  Включить net.ipv4.ip_forward=1 (и ослабить rp_filter)"
  echo "  --static:             Сохранить правила и включить автоподъём после ребута"
  echo "  --delete:             Удалить правила для данного проксирования"
  echo "  --dev:                Показать инфо о разработчике"
  exit 1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Этот скрипт нужно запускать с правами root."
    exit 1
  fi
}

detect_distro() {
  if [ -f /etc/debian_version ]; then
    DISTRO_FAMILY="debian"
  elif [ -f /etc/redhat-release ]; then
    DISTRO_FAMILY="rhel"
  else
    DISTRO_FAMILY="unknown"
  fi
}

install_firewall_tools_noninteractive() {
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    export DEBIAN_FRONTEND=noninteractive
    export UCF_FORCE_CONFFNEW=1
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    apt-get -yq update
    apt-get -yq install iptables iptables-persistent netfilter-persistent
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  elif [ "$DISTRO_FAMILY" = "rhel" ]; then
    yum -y install iptables iptables-services >/dev/null 2>&1 || dnf -y install iptables iptables-services
    systemctl enable iptables >/dev/null 2>&1 || true
    systemctl start iptables  >/dev/null 2>&1 || true
  else
    echo "Не удалось определить дистрибутив. Установите вручную iptables + persistent."
    exit 1
  fi
}

check_install_iptables_tooling() {
  if ! command -v iptables-save >/dev/null 2>&1; then
    echo "Не найден iptables-save. Устанавливаю необходимые пакеты..."
    install_firewall_tools_noninteractive
  else
    if [ "$DISTRO_FAMILY" = "debian" ]; then
      dpkg -s iptables-persistent >/dev/null 2>&1 || install_firewall_tools_noninteractive
    elif [ "$DISTRO_FAMILY" = "rhel" ]; then
      rpm -q iptables-services >/dev/null 2>&1 || install_firewall_tools_noninteractive
    fi
  fi
}

save_iptables_rules() {
  if [ "$SAVE_STATIC_RULES" = true ]; then
    echo "Сохраняю правила iptables для автоподъёма..."
    if [ "$DISTRO_FAMILY" = "debian" ]; then
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules.v4
      if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
        systemctl enable netfilter-persistent >/dev/null 2>&1 || true
      fi
      FINAL_MESSAGE+="Правила сохранены и загрузятся при старте (Debian/Ubuntu).\n"
    elif [ "$DISTRO_FAMILY" = "rhel" ]; then
      service iptables save >/dev/null 2>&1 || /usr/libexec/iptables/iptables.init save >/dev/null 2>&1 || true
      systemctl enable iptables >/dev/null 2>&1 || true
      FINAL_MESSAGE+="Правила сохранены и загрузятся при старте (RHEL/CentOS/Alma/Rocky).\n"
    else
      iptables-save > /etc/iptables/rules.v4 || true
      FINAL_MESSAGE+="Правила сохранены в /etc/iptables/rules.v4 (автоподъём не гарантирован).\n"
    fi
  fi
}

# ---------- sysctl (ip_forward + rp_filter) ----------
ensure_sysctl_for_dnat() {
  # rp_filter: 0 — полностью выключить strict rp_filter (рекомендуется для DNAT);
  # если хочешь "loose", поменяй на 2.
  local want_forward=1 want_rp_all=0 want_rp_def=0
  local cur_forward cur_rp_all cur_rp_def
  cur_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
  cur_rp_all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 1)
  cur_rp_def=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo 1)

  if [ "$cur_forward" != "$want_forward" ]; then
    sysctl -w net.ipv4.ip_forward="$want_forward" >/dev/null || true
    FINAL_MESSAGE+="net.ipv4.ip_forward выставлен в $want_forward.\n"
  else
    FINAL_MESSAGE+="net.ipv4.ip_forward уже $cur_forward.\n"
  fi

  if [ "$cur_rp_all" != "$want_rp_all" ]; then
    sysctl -w net.ipv4.conf.all.rp_filter="$want_rp_all" >/dev/null || true
    FINAL_MESSAGE+="net.ipv4.conf.all.rp_filter выставлен в $want_rp_all.\n"
  fi
  if [ "$cur_rp_def" != "$want_rp_def" ]; then
    sysctl -w net.ipv4.conf.default.rp_filter="$want_rp_def" >/dev/null || true
    FINAL_MESSAGE+="net.ipv4.conf.default.rp_filter выставлен в $want_rp_def.\n"
  fi

  # пропишем в sysctl.conf, если ещё нет
  grep -qE "^\s*net\.ipv4\.ip_forward\s*=\s*$want_forward\s*$" /etc/sysctl.conf || echo "net.ipv4.ip_forward = $want_forward" >> /etc/sysctl.conf
  grep -qE "^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*$want_rp_all\s*$" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = $want_rp_all" >> /etc/sysctl.conf
  grep -qE "^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*$want_rp_def\s*$" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = $want_rp_def" >> /etc/sysctl.conf
  sysctl -p >/dev/null || true
}

# ---------- проверки правил / недублирование ----------
policy_is_accept() { iptables -S | grep -qE "^-P[[:space:]]+$1[[:space:]]+ACCEPT$"; }
has_unconditional_accept_rule() { iptables -S "$1" | grep -qE "^-A[[:space:]]+$1[[:space:]]+-j[[:space:]]+ACCEPT$"; }

ensure_chain_all_accept() {
  local chain=$1
  if policy_is_accept "$chain"; then
    FINAL_MESSAGE+="$chain уже с политикой ACCEPT.\n"
  elif has_unconditional_accept_rule "$chain"; then
    FINAL_MESSAGE+="$chain уже имеет безусловный ACCEPT.\n"
  else
    iptables -A "$chain" -j ACCEPT
    FINAL_MESSAGE+="Добавлен безусловный ACCEPT в $chain.\n"
  fi
}

rule_exists_exact() {
  local table_opt=$1; shift
  if [ -n "$table_opt" ]; then iptables $table_opt -C "$@" 2>/dev/null; else iptables -C "$@" 2>/dev/null; fi
}

# удаляет все дубликаты данного правила, оставляя максимум одно (если keep_one=true)
dedup_rule() {
  local keep_one=$1; shift
  local table_opt=$1; shift
  local args=( "$@" )

  local count=0
  # посчитаем по iptables-save — грубо, но эффективно
  local save_out pattern
  save_out="$(iptables-save $table_opt 2>/dev/null || true)"
  # построим безопасный шаблон (упрощённо)
  pattern="$(printf "%s" "${args[*]}" | sed -E 's/[.[\*^$()+?{}|]/\\&/g')"
  count=$(printf "%s\n" "$save_out" | grep -c -- "$pattern" || true)

  if [ "$count" -gt 1 ]; then
    local to_remove=$((count - (keep_one ? 1 : 0) ))
    # В bash нет тернарника, вычислим явно:
    if [ "$keep_one" = true ]; then
      to_remove=$(( count - 1 ))
    else
      to_remove=$count
    fi
    local i=0
    while [ $i -lt $to_remove ]; do
      if [ -n "$table_opt" ]; then iptables $table_opt -D "${args[@]}" || true; else iptables -D "${args[@]}" || true; fi
      i=$((i+1))
    done
    FINAL_MESSAGE+="Очищены дубликаты правила: ${args[*]} (удалено $to_remove).\n"
  fi
}

ensure_port_accept() {
  local chain=$1 proto=$2 port=$3
  # Сначала почистим дубли (оставим одно)
  dedup_rule true "" "$chain" -p "$proto" --dport "$port" -j ACCEPT
  if ! rule_exists_exact "" "$chain" -p "$proto" --dport "$port" -j ACCEPT; then
    iptables -A "$chain" -p "$proto" --dport "$port" -j ACCEPT
    FINAL_MESSAGE+="Добавлен $chain ACCEPT для $proto:$port.\n"
  else
    FINAL_MESSAGE+="$chain ACCEPT для $proto:$port уже существует.\n"
  fi
}

dnat_exists()   { rule_exists_exact "-t nat" PREROUTING  -p "$1" --dport "$LOCAL_PORT" -j DNAT --to-destination "$IP:$REMOTE_PORT"; }
forward_exists(){ rule_exists_exact ""        FORWARD    -p "$1" -d "$IP" --dport "$REMOTE_PORT" -j ACCEPT; }
masq_exists()   { rule_exists_exact "-t nat" POSTROUTING -p "$1" -d "$IP" --dport "$REMOTE_PORT" -j MASQUERADE; }

dedup_dnat_set() {
  local proto=$1
  dedup_rule true "-t nat" PREROUTING  -p "$proto" --dport "$LOCAL_PORT" -j DNAT --to-destination "$IP:$REMOTE_PORT"
  dedup_rule true ""        FORWARD    -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j ACCEPT
  dedup_rule true "-t nat" POSTROUTING -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j MASQUERADE
}

manage_rule() {
  local action=$1 proto=$2

  # Сначала почистим возможные дубли
  dedup_dnat_set "$proto"

  if [ "$action" = "add" ]; then
    echo "Добавляю правила для $proto ..."

    if ! dnat_exists "$proto"; then
      iptables -t nat -A PREROUTING -p "$proto" --dport "$LOCAL_PORT" -j DNAT --to-destination "$IP:$REMOTE_PORT"
      FINAL_MESSAGE+="DNAT $proto:$LOCAL_PORT -> $IP:$REMOTE_PORT добавлен.\n"
    else
      FINAL_MESSAGE+="DNAT $proto:$LOCAL_PORT уже существует.\n"
    fi

    if ! forward_exists "$proto"; then
      iptables -A FORWARD -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j ACCEPT
      FINAL_MESSAGE+="FORWARD ACCEPT к $IP:$REMOTE_PORT ($proto) добавлен.\n"
    else
      FINAL_MESSAGE+="FORWARD ACCEPT к $IP:$REMOTE_PORT ($proto) уже существует.\n"
    fi

    if ! masq_exists "$proto"; then
      iptables -t nat -A POSTROUTING -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j MASQUERADE
      FINAL_MESSAGE+="POSTROUTING MASQUERADE для $IP:$REMOTE_PORT ($proto) добавлен.\n"
    else
      FINAL_MESSAGE+="POSTROUTING MASQUERADE для $IP:$REMOTE_PORT ($proto) уже существует.\n"
    fi

    # Глобальный полный доступ, если отсутствует (без дублей)
    ensure_chain_all_accept INPUT
    ensure_chain_all_accept OUTPUT
    # Точечный доступ для порта (без дублей)
    ensure_port_accept INPUT  "$proto" "$LOCAL_PORT"
    ensure_port_accept OUTPUT "$proto" "$REMOTE_PORT"

  elif [ "$action" = "delete" ]; then
    echo "Удаляю правила для $proto ..."

    # Удалим ВСЕ вхождения наших правил (сколько бы ни было)
    while dnat_exists "$proto";    do iptables -t nat -D PREROUTING  -p "$proto" --dport "$LOCAL_PORT" -j DNAT --to-destination "$IP:$REMOTE_PORT" || break; done
    while forward_exists "$proto"; do iptables -D FORWARD -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j ACCEPT || break; done
    while masq_exists "$proto";    do iptables -t nat -D POSTROUTING -p "$proto" -d "$IP" --dport "$REMOTE_PORT" -j MASQUERADE || break; done

    # Точечные INPUT/OUTPUT
    while rule_exists_exact "" INPUT  -p "$proto" --dport "$LOCAL_PORT"  -j ACCEPT; do iptables -D INPUT  -p "$proto" --dport "$LOCAL_PORT"  -j ACCEPT || break; done
    while rule_exists_exact "" OUTPUT -p "$proto" --dport "$REMOTE_PORT" -j ACCEPT; do iptables -D OUTPUT -p "$proto" --dport "$REMOTE_PORT" -j ACCEPT || break; done

    FINAL_MESSAGE+="Правила для $proto удалены (если существовали).\n"
  fi
}

# ---- аргументы ----
if [ "$#" -lt 2 ]; then usage; fi

require_root
detect_distro

ENABLE_IP_FORWARD=true
LOCAL_PORT=
SAVE_STATIC_RULES=false
DELETE_RULE=false
PROTOCOL="tcp"
FINAL_MESSAGE=""

IP=""
REMOTE_PORT=""

while [ "${1:-}" != "" ]; do
  case "$1" in
    --ip) shift; IP=${1:-};;
    --remote-port) shift; REMOTE_PORT=${1:-};;
    --local-port) shift; LOCAL_PORT=${1:-};;
    --protocol) shift; PROTOCOL=${1:-};;
    --enable-ip-forward) ENABLE_IP_FORWARD=true;;
    --static) SAVE_STATIC_RULES=true;;
    --delete) DELETE_RULE=true;;
    *) usage;;
  esac
  shift || true
done

[ -n "$IP" ] && [ -n "$REMOTE_PORT" ] || usage
[ -n "${LOCAL_PORT:-}" ] || LOCAL_PORT="$REMOTE_PORT"

# Подтянуть инструменты
check_install_iptables_tooling

# Включить форвардинг + ослабить rp_filter (если просили)
if [ "$ENABLE_IP_FORWARD" = true ]; then
  ensure_sysctl_for_dnat
fi

# Добавление/удаление правил (с дедупом)
if [ "$PROTOCOL" = "both" ]; then
  for proto in tcp udp; do
    if [ "$DELETE_RULE" = true ]; then
      manage_rule delete "$proto"
    else
      manage_rule add "$proto"
    fi
  done
else
  if [ "$DELETE_RULE" = true ]; then
    manage_rule delete "$PROTOCOL"
  else
    manage_rule add "$PROTOCOL"
  fi
fi

# Сохранить на диск (если надо)
save_iptables_rules

echo -e "$FINAL_MESSAGE"