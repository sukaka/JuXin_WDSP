#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/ops/lib/common.sh"
source "$ROOT/ops/install/pcap.sh"
PCAP_ENABLE=true
PCAP_IFACE=eth0
PCAP_PORTS=80,443
PCAP_HOT_DIR=/srv/jiuzhang-ssd/pcap
PCAP_WARM_DIR=/srv/jiuzhang-sas/pcap
pcap_validate_args
pcap_validate_enabled
[[ "$PCAP_HOT_DIR" == /srv/jiuzhang-ssd/pcap && "$PCAP_WARM_DIR" == /srv/jiuzhang-sas/pcap ]]
for invalid in "80-443" "80,,443" "0" "65536" "80:443"; do
  if (PCAP_PORTS="$invalid"; pcap_validate_enabled) >/dev/null 2>&1; then
    printf 'invalid PCAP ports accepted: %s\n' "$invalid" >&2
    exit 1
  fi
done
if (PCAP_HOT_DIR=/same; PCAP_WARM_DIR=/same; pcap_validate_enabled) >/dev/null 2>&1; then
  echo 'same hot/warm directory accepted' >&2
  exit 1
fi
if (PCAP_ENABLE=false; pcap_validate_args) >/dev/null 2>&1; then
  echo 'PCAP arguments were accepted without explicit enablement' >&2
  exit 1
fi
printf 'PCAP installer argument and storage-boundary tests passed\n'
