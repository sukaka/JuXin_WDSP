#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
"$ROOT/scripts/build.sh"
rm -rf "$ROOT/build/test-classes"
mkdir -p "$ROOT/build/test-classes"
SOURCES=("$ROOT"/src/test/java/com/jiuzhang/apisecurity/*.java)
javac --release 21 -encoding UTF-8 -Xlint:all -Werror \
  -cp "$ROOT/build/classes" -d "$ROOT/build/test-classes" "${SOURCES[@]}"
java -ea -cp "$ROOT/build/classes:$ROOT/build/test-classes" \
  com.jiuzhang.apisecurity.TestMain
