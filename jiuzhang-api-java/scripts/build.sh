#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
rm -rf "$ROOT/build/classes"
mkdir -p "$ROOT/build/classes" "$ROOT/dist"
SOURCES=("$ROOT"/src/main/java/com/jiuzhang/apisecurity/*.java)
javac --release 21 -encoding UTF-8 -Xlint:all -Werror -d "$ROOT/build/classes" "${SOURCES[@]}"
jar --create --file "$ROOT/dist/jiuzhang-api-security.jar" \
  --main-class com.jiuzhang.apisecurity.Main \
  -C "$ROOT/build/classes" .
printf 'built %s\n' "$ROOT/dist/jiuzhang-api-security.jar"
