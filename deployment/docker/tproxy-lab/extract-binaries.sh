#!/usr/bin/env bash
# 从本机锁定镜像提取 caddy / testorigin 二进制到本构建上下文。
#
# 背景：Docker Hub 在本实验环境不可达，而 BuildKit 无法把自建镜像的
# name@digest 引用解析到本地镜像存储（本地构建产物没有 registry RepoDigest，
# 会回源到 registry 解析而失败），故按任务约定以 docker cp 提取（docker
# create/cp 走 daemon 本地解析，与 docker-compose.routed-lab.yml 的 image
# digest 引用同一路径）。提取产物为构建上下文临时工件，已被 .gitignore 忽略。
#
# 用法（仓库根目录或本目录均可）：
#   bash deployment/docker/tproxy-lab/extract-binaries.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 本机已有镜像按 digest 锁定（括号内为便于识别的标签）
GW_IMAGE="jiuzhang-gateway@sha256:9996b3d154de6726ddb4a94aba3c538af8627a40d174d9214a92c7a693b3ffe1"       # jiuzhang-gateway:stage5
ORIGIN_IMAGE="jiuzhang-testorigin@sha256:670887ef1dc10268fbc9eeb3203c6791cb7fa525196b5a7e417c4bd763375149" # jiuzhang-testorigin:stage1

extract() { # image container-path dest
  local image="$1" src="$2" dst="$3" cid
  cid="$(docker create "$image")"
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:$src" "$dst"
  docker rm -f "$cid" >/dev/null
  trap - EXIT
  chmod 0755 "$dst"
}

extract "$GW_IMAGE" /usr/bin/caddy "$DIR/caddy"
extract "$ORIGIN_IMAGE" /usr/local/bin/testorigin "$DIR/testorigin"
ls -l "$DIR/caddy" "$DIR/testorigin"
