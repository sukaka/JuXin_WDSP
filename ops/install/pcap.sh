#!/usr/bin/env bash
# 可选请求PCAP：只配置签名公钥抓包与加密证据存储，不包含私钥或默认抓包范围。
PCAP_ENABLE=false
PCAP_IFACE=""
PCAP_PORTS=""
PCAP_HOT_DIR=""
PCAP_WARM_DIR=""

pcap_validate_args() {
  [[ "$PCAP_ENABLE" == "true" ]] && return 0
  if [[ -n "$PCAP_IFACE" || -n "$PCAP_PORTS" || -n "$PCAP_HOT_DIR" || -n "$PCAP_WARM_DIR" ]]; then
    die "PCAP参数必须与 --enable-pcap 一起使用"
  fi
  return 0
}

pcap_validate_enabled() {
  [[ "$PCAP_ENABLE" == "true" ]] || return 0
  [[ "$PCAP_IFACE" =~ ^[A-Za-z0-9_.:-]{1,64}$ ]] || die "--pcap-iface 必须是显式的合法网卡名"
  [[ "$PCAP_PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "--pcap-ports 只接受逗号分隔的明确端口，不支持区间"
  local old_ifs="$IFS" port
  IFS=','
  read -ra _pcap_ports <<< "$PCAP_PORTS"
  IFS="$old_ifs"
  [[ "${#_pcap_ports[@]}" -le 128 ]] || die "PCAP端口最多128个"
  for port in "${_pcap_ports[@]}"; do
    (( 10#$port >= 1 && 10#$port <= 65535 )) || die "PCAP端口越界: $port"
  done
  [[ "$PCAP_HOT_DIR" =~ ^/[A-Za-z0-9._/-]+$ && "$PCAP_WARM_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "PCAP热/温目录必须是受限字符的绝对路径"
  PCAP_HOT_DIR="${PCAP_HOT_DIR%/}"
  PCAP_WARM_DIR="${PCAP_WARM_DIR%/}"
  [[ -n "$PCAP_HOT_DIR" && -n "$PCAP_WARM_DIR" && "$PCAP_HOT_DIR" != "$PCAP_WARM_DIR" ]] || die "PCAP热目录与温目录必须是两个不同的非根目录"
  case "/$PCAP_HOT_DIR/" in */../*|*/./*) die "PCAP热目录不能包含相对路径段" ;; esac
  case "/$PCAP_WARM_DIR/" in */../*|*/./*) die "PCAP温目录不能包含相对路径段" ;; esac
}

pcap_configure() {
  [[ "$PCAP_ENABLE" == "true" ]] || return 0
  log_info "配置显式启用的请求PCAP（网卡=${PCAP_IFACE}，端口=${PCAP_PORTS}）"
  install -d -m 0700 -o 1000 -g 1000 "$PCAP_HOT_DIR" "$PCAP_WARM_DIR"
  install -d -m 0700 -o 1000 -g 1000 ./runtime/pcap-private
  install -d -m 0755 -o 1000 -g 1000 ./runtime/pcap-public
  cat >> "$JZ_ENV_FILE" <<EOF

# 请求PCAP：仅在安装命令明确指定 --enable-pcap 后生成。
COMPOSE_PROFILES=request-pcap
REQUEST_PCAP_CAPTURE_ENABLED=true
REQUEST_PCAP_IFACE=$PCAP_IFACE
REQUEST_PCAP_PORTS=$PCAP_PORTS
REQUEST_PCAP_HOT_DIR=$PCAP_HOT_DIR
REQUEST_PCAP_WARM_DIR=$PCAP_WARM_DIR
REQUEST_PCAP_POLICY_VERSION=installer-approved-v1
PCAP_SERVER_HOT_DIR=/app/runtime/pcap-hot
PCAP_SERVER_WARM_DIR=/app/runtime/pcap-warm
PCAP_SERVER_KEY_FILE=/app/runtime/pcap-private/private.key
PCAP_SERVER_PUBLIC_DIR=/app/runtime/pcap-public
REQUEST_PCAP_RETENTION=24h
REQUEST_PCAP_HOT_AGE=15m
REQUEST_PCAP_GRANT_TTL=24h
REQUEST_PCAP_MIGRATE_BPS=33554432
REQUEST_PCAP_MIN_FREE_PERCENT=10
EOF
  chmod 600 "$JZ_ENV_FILE"
  log_info "PCAP私钥将只保存在API私有目录；节点只读签名公钥；默认保留24h、热层15min、SAS迁移32MiB/s"
}
