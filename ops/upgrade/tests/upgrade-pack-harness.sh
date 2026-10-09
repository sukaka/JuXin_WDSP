#!/usr/bin/env bash
# shellcheck disable=SC1090
# upgrade-pack-harness.sh —— 多组件功能升级包构建脚本（ops/upgrade/build-upgrade-pack.sh）
# 与宿主机执行器升级协议（ops/upgrade/upgrade-executor.sh 的 package_type=upgrade）回归测试。
#
# 约定与 scripts/tests/offline-signing-harness.sh 一致：纯 bash、PASS/FAIL 计数、全程在
# 临时目录内进行，不触碰 docker/系统状态（镜像用预造的小假 tar 经 --images-dir 注入）。
#
# 核心证据：内置 Go 校验器（临时目录生成、go build 一次）按
# server/internal/upgrades/artifact.go 同口径重算 files_manifest_sha256 并核对
# 「归档常规文件 ↔ manifest.files 精确一一对应（files 不含 manifest.json/manifest.sig
# 两个保留根文件）」，正包必须通过、篡改包必须失败。签名链路证据：包内 manifest.sig
# （base64 单行）对 manifest.json 归档字节验签通过；篡改 manifest.json 后验签失败；
# 篡改镜像文件后 manifest.sig 仍有效而 files 哈希校验失败（链式信任：签名锁 manifest，
# manifest 锁文件）。单文件格式：不再产出独立 .sig 旁车与 manifest 副本。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
BUILDER="$REPO_ROOT/ops/upgrade/build-upgrade-pack.sh"
EXECUTOR="$REPO_ROOT/ops/upgrade/upgrade-executor.sh"
COMMON="$REPO_ROOT/ops/lib/common.sh"
SIGNING="$REPO_ROOT/ops/lib/signing.sh"

for cmd in jq tar gzip openssl go python3 git; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "harness 缺少命令: $cmd" >&2; exit 1; }
done

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-upg-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-upg-harness.*) rm -rf "$TMP_ROOT" ;;
    *) echo "拒绝清理非测试临时目录: $TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); printf 'FAIL: %s\n' "$*" >&2; }
check() { # check NAME CMD...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}
expect_exit() { # expect_exit NAME WANT_RC CMD...
  local name="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1
  local rc=$?
  if [[ "$rc" == "$want" ]]; then pass "$name"; else fail "${name}（退出码 ${rc}，期望 ${want}）"; fi
}

case "$(uname -m)" in
  x86_64|amd64)  HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
  *) echo "harness 不支持宿主架构: $(uname -m)" >&2; exit 1 ;;
esac

# ---------- 0. 语法检查 ----------
for f in "$BUILDER" "$EXECUTOR" "$COMMON" "$SIGNING"; do
  check "bash -n $(basename "$f")" bash -n "$f"
done
if grep -Fq 'wait_selected_services || return 1' "$EXECUTOR" \
  && grep -Fq 'docker inspect --format' "$EXECUTOR" \
  && grep -Fq '升级后组件 $service 未就绪' "$EXECUTOR"; then
  pass "执行器包含逐组件就绪校验"
else
  fail "执行器逐组件就绪校验缺失"
fi
if python3 "$SCRIPT_DIR/test_executor_readiness.py"; then
  pass "执行器故障关闭、实际探测与连续稳定回归"
else
  fail "执行器故障关闭、实际探测与连续稳定回归"
fi
if python3 "$SCRIPT_DIR/test_executor_dependencies.py"; then
  pass "执行器/安装器依赖核查（diffutils 点名）回归"
else
  fail "执行器/安装器依赖核查（diffutils 点名）回归"
fi

# ---------- 1. 用法与参数校验 ----------
expect_exit "--help 退出码 0" 0 bash "$BUILDER" --help
expect_exit "未知组件拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --from 1.2.0 --to 1.3.0 --components "api foo"
expect_exit "重复组件拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --to 1.3.0 --components "api api web"
expect_exit "缺少 --to 拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --from 1.2.0
expect_exit "目标版本不高于起始版本拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --from 1.2.0 --to 1.2.0
expect_exit "非法架构拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --to 1.3.0 --arch riscv64
expect_exit "非法 --from 拒绝" 2 env -u WDSP_SIGNING_KEY bash "$BUILDER" --from 1.2 --to 1.3.0

# ---------- 2. Go 同口径校验器（artifact.go 语义：根目录/manifest 唯一/一一对应/紧凑摘要） ----------
CHECKER_SRC="$TMP_ROOT/artifactcheck"
mkdir -p "$CHECKER_SRC"
cat > "$CHECKER_SRC/main.go" <<'GO_EOF'
// artifactcheck —— 与 server/internal/upgrades/artifact.go 同口径的归档校验（测试夹具）。
// 校验：路径安全、单一公共根目录、恰一个根级 manifest.json、至多一个根级 manifest.sig
// （两个保留根文件，均不进 files；manifest.sig 存在时必须是 base64 单行、解码后为
// 64 字节 Ed25519 签名）、常规文件与 manifest.files 精确一一对应（files 不得含
// manifest.json/manifest.sig）、files_manifest_sha256 等于
// sha256(json.Marshal(files))（Go 紧凑序列化口径），以及 manifest.version 等于期望值。
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type packageManifest struct {
	Product             string         `json:"product"`
	Version             string         `json:"version"`
	Arch                string         `json:"arch"`
	Files               []manifestFile `json:"files"`
	FilesManifestSHA256 string         `json:"files_manifest_sha256"`
}

type entry struct {
	path    string
	size    int64
	hash    string
	content []byte
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ARTIFACT-CHECK-FAIL: "+format+"\n", args...)
	os.Exit(1)
}

// normalize 与 artifact.go normalizeArchivePath 等价（posix 口径）。
func normalize(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", errors.New("空文件名")
	}
	if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("路径不安全: %s", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("路径穿越: %s", name)
		}
	}
	cleaned := path.Clean(name)
	if cleaned == "." || cleaned == "" {
		return "", nil
	}
	return cleaned, nil
}

func main() {
	if len(os.Args) != 3 {
		fail("用法: artifactcheck <pkg.tar.gz> <expectVersion>")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("读取归档失败: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		fail("gzip 格式无效: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var entries []entry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fail("tar 格式无效: %v", err)
		}
		norm, err := normalize(hdr.Name)
		if err != nil {
			fail("%v", err)
		}
		if norm == "" {
			continue
		}
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			fail("不允许的文件类型: %s", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		h := sha256.New()
		var dst bytes.Buffer
		if _, err := io.Copy(io.MultiWriter(h, &dst), io.LimitReader(tr, hdr.Size)); err != nil {
			fail("读取成员失败: %v", err)
		}
		if int64(dst.Len()) != hdr.Size {
			fail("成员大小不完整: %s", hdr.Name)
		}
		e := entry{path: norm, size: hdr.Size, hash: hex.EncodeToString(h.Sum(nil))}
		if path.Base(norm) == "manifest.json" || path.Base(norm) == "manifest.sig" {
			e.content = append([]byte(nil), dst.Bytes()...)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		fail("归档为空")
	}
	root := entries[0].path
	if idx := strings.IndexByte(root, '/'); idx >= 0 {
		root = root[:idx]
	}
	for _, e := range entries[1:] {
		first := e.path
		if idx := strings.IndexByte(first, '/'); idx >= 0 {
			first = first[:idx]
		}
		if first != root {
			root = ""
			break
		}
	}
	strip := func(p string) string {
		if root == "" {
			return p
		}
		if p == root {
			return ""
		}
		return strings.TrimPrefix(p, root+"/")
	}
	files := map[string]entry{}
	var manifestBytes, sigBytes []byte
	manifestFound := false
	sigFound := false
	for _, e := range entries {
		n := strip(e.path)
		if n == "" {
			continue
		}
		if n == "manifest.json" {
			if manifestFound {
				fail("重复 manifest.json")
			}
			manifestFound = true
			manifestBytes = e.content
			continue
		}
		if n == "manifest.sig" {
			if sigFound {
				fail("重复 manifest.sig")
			}
			sigFound = true
			sigBytes = e.content
			continue
		}
		if _, dup := files[n]; dup {
			fail("重复文件: %s", n)
		}
		files[n] = e
	}
	if !manifestFound {
		fail("缺少 manifest.json")
	}
	var m packageManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		fail("manifest 非合法 JSON: %v", err)
	}
	if m.Version != os.Args[2] {
		fail("manifest.version %q 与期望 %q 不一致", m.Version, os.Args[2])
	}
	if len(m.Files) == 0 {
		fail("manifest.files 为空")
	}
	filesJSON, err := json.Marshal(m.Files)
	if err != nil {
		fail("序列化 files 失败: %v", err)
	}
	digest := sha256.Sum256(filesJSON)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), m.FilesManifestSHA256) {
		fail("files_manifest_sha256 不一致: manifest=%s 重算=%s",
			m.FilesManifestSHA256, hex.EncodeToString(digest[:]))
	}
	listed := map[string]struct{}{}
	for _, item := range m.Files {
		n, err := normalize(item.Path)
		if err != nil {
			fail("files 路径无效: %v", err)
		}
		if n == "" || n == "manifest.json" || n == "manifest.sig" {
			fail("files 含保留路径: %s", item.Path)
		}
		if _, dup := listed[n]; dup {
			fail("files 重复: %s", n)
		}
		listed[n] = struct{}{}
		actual, ok := files[n]
		if !ok {
			fail("声明的文件缺失: %s", n)
		}
		if actual.size != item.Size || !strings.EqualFold(actual.hash, item.SHA256) {
			fail("文件摘要或大小不一致: %s", n)
		}
	}
	if len(files) != len(listed) {
		fail("归档存在未在 manifest 中声明的文件")
	}
	if sigFound {
		sigText := strings.TrimSpace(string(sigBytes))
		if sigText == "" || strings.ContainsAny(sigText, "\r\n") {
			fail("manifest.sig 非 base64 单行文本")
		}
		rawSig, err := base64.StdEncoding.DecodeString(sigText)
		if err != nil || len(rawSig) != 64 {
			fail("manifest.sig 解码后非 64 字节 Ed25519 签名")
		}
	}
	sigState := "absent"
	if sigFound {
		sigState = "present"
	}
	fmt.Printf("ARTIFACT-CHECK-OK version=%s files=%d root=%s manifest.sig=%s\n", m.Version, len(listed), root, sigState)
}
GO_EOF
if (cd "$CHECKER_SRC" && GO111MODULE=off go build -o artifactcheck main.go) >/dev/null 2>&1; then
  pass "Go 同口径校验器编译"
else
  fail "Go 同口径校验器编译失败"
  printf '\n========== harness 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
  exit 1
fi
CHECKER="$CHECKER_SRC/artifactcheck"

# ---------- 3. 测试夹具：预造小假镜像 tar（<组件>-<arch>.tar.gz） ----------
FIX="$TMP_ROOT/images-in"
mkdir -p "$FIX"
for c in api web gateway netmgrd; do
  d="$TMP_ROOT/imgsrc/$c"
  mkdir -p "$d"
  printf 'fake image payload for %s\n' "$c" > "$d/payload.txt"
  COPYFILE_DISABLE=1 tar -C "$d" -czf "$FIX/$c-$HOST_ARCH.tar.gz" payload.txt
done

# ---------- 4. 未签名全组件构建（--unsigned --skip-build --images-dir） ----------
DIST_U="$TMP_ROOT/dist-unsigned"
U_OUT="$TMP_ROOT/build-unsigned.out"
PKG_U="$DIST_U/jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.tar.gz"
if env -u WDSP_SIGNING_KEY bash "$BUILDER" --from 1.2.0 --to 1.3.0 --arch "$HOST_ARCH" \
    --components "api web gateway netmgrd" --skip-build --images-dir "$FIX" \
    --unsigned --output-dir "$DIST_U" > "$U_OUT" 2>&1; then
  pass "未签名全组件构建执行成功"
else
  fail "未签名全组件构建执行失败（输出见 ${U_OUT}）"
fi
if [[ -f "$PKG_U" && -f "$PKG_U.sha256" && ! -f "$PKG_U.sig" \
   && ! -f "$DIST_U/jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.manifest.json" ]] \
   && grep -q '未签名' "$U_OUT"; then
  pass "未签名产物齐全（仅包 + .sha256，无独立 .sig / manifest 副本，有醒目告警）"
else
  fail "未签名产物完整性（输出见 ${U_OUT}）"
fi
# 旁车 .sha256 与包体一致
if (cd "$DIST_U" && sha256sum -c "jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.tar.gz.sha256" >/dev/null 2>&1) \
   || (cd "$DIST_U" && [[ "$(shasum -a 256 "jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.tar.gz" | awk '{print $1}')" == "$(awk 'NR==1{print $1}' "jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.tar.gz.sha256")" ]]); then
  pass "旁车 .sha256 与包体一致"
else
  fail "旁车 .sha256 与包体一致"
fi

# ---------- 5. manifest 双口径字段断言 ----------
EX_U="$TMP_ROOT/extract-unsigned"
mkdir -p "$EX_U"
tar -xzf "$PKG_U" -C "$EX_U"
ROOT_NAME="jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH"
MANIFEST="$EX_U/$ROOT_NAME/manifest.json"
[[ -f "$MANIFEST" ]] || { fail "包内缺少 $ROOT_NAME/manifest.json"; }

EXPECTED_SCHEMA="$(ls "$REPO_ROOT/server/migrations" \
  | grep -E '^[0-9]{6}_[a-z0-9_]+\.up\.sql$' | cut -c1-6 | sort -n | tail -1 | sed 's/^0*//')"

if jq -e --arg arch "$HOST_ARCH" --argjson schema "$EXPECTED_SCHEMA" '
  .format_version == "1" and
  .package_type == "upgrade" and
  .change_type == "feature" and
  .product == "wdsp" and
  .version == "1.3.0" and .version_from == "1.2.0" and .version_to == "1.3.0" and
  .arch == $arch and
  .target_schema_version == $schema and
  (.components | sort) == ["api","gateway","netmgrd","web"] and
  (.images | length == 4) and
  (all(.images[]; (.component == .service) and
    (.image == ("jiuzhang-" + (if .component == "api" then "server" else .component end) + ":1.3.0")) and
    (.tar == "images/" + .component + "-'"$HOST_ARCH"'.tar.gz"))) and
  (.files_manifest_sha256 | test("^[0-9a-f]{64}$"))
' "$MANIFEST" >/dev/null; then
  pass "manifest 字段双口径断言（服务端 version/arch/files_manifest_sha256 + 执行器 images/components）"
else
  fail "manifest 字段双口径断言"
fi

# files 清单：恰为 4 镜像 + 2 安装器 + 1 compose 片段 + SHA256SUMS，且不含 manifest.json/manifest.sig
if jq -e '
  (.files | length == 8) and
  (all(.files[]; (.path | test("^[A-Za-z0-9._/-]+$")) and .path != "manifest.json" and .path != "manifest.sig"
    and (.sha256 | test("^[0-9a-f]{64}$")) and (.size | type == "number" and . > 0))) and
  ([.files[].path] | sort) == (["SHA256SUMS",
    "compose/upgrade-services.yml",
    "images/api-'"$HOST_ARCH"'.tar.gz", "images/gateway-'"$HOST_ARCH"'.tar.gz",
    "images/netmgrd-'"$HOST_ARCH"'.tar.gz", "images/web-'"$HOST_ARCH"'.tar.gz",
    "installer/install-executor.sh", "installer/upgrade-executor.sh"] | sort)
' "$MANIFEST" >/dev/null; then
  pass "files 清单精确收录 8 个文件且不含 manifest.json/manifest.sig"
else
  fail "files 清单内容（$(jq -r '.files[].path' "$MANIFEST" | tr '\n' ' ')）"
fi

# 归档成员：单一公共根目录、恰一个 manifest.json；未签名包不得含 manifest.sig
roots_in_pkg="$(tar -tzf "$PKG_U" | awk -F/ 'NF>1 {print $1}' | LC_ALL=C sort -u)"
if [[ "$roots_in_pkg" == "$ROOT_NAME" ]] \
   && [[ "$(tar -tzf "$PKG_U" | grep -c '/manifest.json$')" == "1" ]] \
   && [[ "$(tar -tzf "$PKG_U" | grep -c '/manifest.sig$')" == "0" ]]; then
  pass "归档单一根目录 + 恰一个 manifest.json（未签名包无 manifest.sig）"
else
  fail "归档根目录/manifest.json/manifest.sig 数量（根: $(printf '%s' "$roots_in_pkg" | tr '\n' ',')）"
fi

# ---------- 6. Go 同口径校验（核心证据：紧凑序列化摘要 + 一一对应） ----------
if "$CHECKER" "$PKG_U" "1.3.0" > "$TMP_ROOT/check-unsigned.out" 2>&1; then
  pass "Go 同口径校验通过（files_manifest_sha256 与 Go json.Marshal 字节级一致）"
else
  fail "Go 同口径校验（$(cat "$TMP_ROOT/check-unsigned.out")"
fi

# 执行器运行时校验兼容：包内 SHA256SUMS 可通过 sha256sum -c
if (cd "$EX_U/$ROOT_NAME" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
  pass "包内 SHA256SUMS 纵深校验通过"
else
  fail "包内 SHA256SUMS 校验"
fi

# compose 片段：netmgrd 服务定义与 stage5 口径一致的关键字段
FRAG="$EX_U/$ROOT_NAME/compose/upgrade-services.yml"
if [[ -f "$FRAG" ]] \
   && grep -q 'image: jiuzhang-netmgrd:1.3.0' "$FRAG" \
   && grep -q 'network_mode: service:gateway' "$FRAG" \
   && grep -q 'container_name: jiuzhang-netmgrd' "$FRAG" \
   && grep -q 'gateway-admin:/var/run/caddy' "$FRAG"; then
  pass "compose 片段含 netmgrd 首次部署定义"
else
  fail "compose 片段 netmgrd 定义"
fi

# ---------- 7. 执行器升级协议守卫（静态 + 用真实包清单跑执行器 jq 判定式） ----------
if grep -q 'upgrade) process_upgrade_pack' "$EXECUTOR" \
   && grep -q 'netmgrd' "$EXECUTOR" \
   && grep -q 'compose-overrides.d' "$EXECUTOR" \
   && grep -q 'install-executor.sh' "$EXECUTOR"; then
  pass "执行器接受 package_type=upgrade、组件白名单含 netmgrd、支持 compose 片段并入"
else
  fail "执行器升级协议守卫"
fi

# 直接从执行器脚本抽取 process_upgrade_pack 的 jq 判定式（防抄写漂移），
# 对构建产物 manifest 做正/负例判定：这是「构建器产物 ↔ 执行器准入」的协议兼容证据。
PRED_JQ="$TMP_ROOT/executor-predicate.jq"
if python3 - "$EXECUTOR" "$PRED_JQ" <<'PY'
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
i = src.index('process_upgrade_pack()')
m = re.search(r"jq -e --arg from \"\$version_from\" --arg to \"\$version_to\" '\n(.*?)\n  ' \"\$manifest\"", src[i:], re.S)
if not m:
    sys.exit(1)
open(sys.argv[2], 'w', encoding='utf-8').write(m.group(1))
PY
then
  if jq -e --arg from "1.2.0" --arg to "1.3.0" -f "$PRED_JQ" "$MANIFEST" >/dev/null; then
    pass "执行器 jq 判定式接受构建产物 manifest（协议兼容）"
  else
    fail "执行器 jq 判定式拒绝构建产物 manifest"
  fi
  pred_reject() { # pred_reject NAME JQ_FILTER —— 变异 manifest 后判定式必须拒绝
    local name="$1" filter="$2" mutated="$TMP_ROOT/mutated.json"
    jq "$filter" "$MANIFEST" > "$mutated"
    if jq -e --arg from "1.2.0" --arg to "1.3.0" -f "$PRED_JQ" "$mutated" >/dev/null 2>&1; then
      fail "$name（变异 manifest 未被拒绝）"
    else
      pass "$name"
    fi
  }
  pred_reject "判定式拒绝白名单外组件" '.components[3] = "foo"'
  pred_reject "判定式拒绝 images↔components 不对应" '.images[0].component = "web"'
  pred_reject "判定式拒绝 files 收录 manifest.json" '.files[0].path = "manifest.json"'
  pred_reject "判定式拒绝 files 收录 manifest.sig" '.files[0].path = "manifest.sig"'
  pred_reject "判定式拒绝 files 路径穿越" '.files[0].path = "../evil"'
  if jq -e --arg from "1.2.0" --arg to "1.2.0" -f "$PRED_JQ" "$MANIFEST" >/dev/null 2>&1; then
    fail "判定式拒绝 version_to 与任务不一致"
  else
    pass "判定式拒绝 version_to 与任务不一致"
  fi
else
  fail "无法从执行器脚本抽取 jq 判定式"
fi

# ---------- 8. 临时密钥签名构建 + 包内 manifest.sig 验签（服务端口径） ----------
openssl genpkey -algorithm ED25519 -out "$TMP_ROOT/rel.key" 2>/dev/null
openssl pkey -in "$TMP_ROOT/rel.key" -pubout -out "$TMP_ROOT/rel.pub" 2>/dev/null
# 只在隔离夹具内信任测试公钥，生产构建器必须拒绝随机密钥。
SIGNED_FIX="$TMP_ROOT/signed-repo"
mkdir -p "$SIGNED_FIX/ops/upgrade" "$SIGNED_FIX/ops/lib" "$SIGNED_FIX/ops/offline-package" "$SIGNED_FIX/server/migrations"
cp "$BUILDER" "$EXECUTOR" "$REPO_ROOT/ops/upgrade/install-executor.sh" "$SIGNED_FIX/ops/upgrade/"
cp "$COMMON" "$SIGNING" "$SIGNED_FIX/ops/lib/"
cp "$REPO_ROOT/VERSION.md" "$SIGNED_FIX/VERSION.md"
cp "$TMP_ROOT/rel.pub" "$SIGNED_FIX/ops/offline-package/release-signing.pub"
printf 'SELECT 1;\n' > "$SIGNED_FIX/server/migrations/000001_fixture.up.sql"
git -C "$SIGNED_FIX" init -q
git -C "$SIGNED_FIX" config user.name harness
git -C "$SIGNED_FIX" config user.email harness@example.invalid
git -C "$SIGNED_FIX" add -A
git -C "$SIGNED_FIX" commit -qm baseline
git -C "$SIGNED_FIX" tag wdsp-v1.2.0
mkdir -p "$SIGNED_FIX/web"
printf 'changed\n' > "$SIGNED_FIX/web/app.js"
printf 'changed\n' > "$SIGNED_FIX/server/app.go"
expect_exit "正式构建拒绝不受信任的随机密钥" 1 env WDSP_SIGNING_KEY="$TMP_ROOT/rel.key" \
  bash "$BUILDER" --to 1.4.0 --components api --images-dir "$FIX" --output-dir "$TMP_ROOT/wrong-key"
DIST_S="$TMP_ROOT/dist-signed"
S_OUT="$TMP_ROOT/build-signed.out"
ROOT_S="jiuzhang-wdsp-upgrade-1.4.0-$HOST_ARCH"
PKG_S="$DIST_S/$ROOT_S.tar.gz"
if WDSP_SIGNING_KEY="$TMP_ROOT/rel.key" bash "$SIGNED_FIX/ops/upgrade/build-upgrade-pack.sh" --to 1.4.0 --arch "$HOST_ARCH" \
    --images-dir "$FIX" --output-dir "$DIST_S" > "$S_OUT" 2>&1; then
  pass "默认 auto 自动识别并签名构建成功"
else
  fail "签名构建执行失败（输出见 ${S_OUT}）"
fi
# 产物形态：仅包 + .sha256，无独立 .sig 旁车、无 manifest 副本
if [[ -f "$PKG_S" && -f "$PKG_S.sha256" && ! -f "$PKG_S.sig" \
   && ! -f "$DIST_S/$ROOT_S.manifest.json" ]]; then
  pass "签名产物为单文件（包 + .sha256，无独立 .sig / manifest 副本）"
else
  fail "签名产物形态（输出见 ${S_OUT}）"
fi
# 包内含恰一个根级 manifest.sig；抽回 manifest.json + manifest.sig 备验签
EX_S="$TMP_ROOT/extract-signed"
mkdir -p "$EX_S"
if [[ "$(tar -tzf "$PKG_S" | grep -c '/manifest.sig$')" == "1" ]] \
   && tar -xzf "$PKG_S" -C "$EX_S" "$ROOT_S/manifest.json" "$ROOT_S/manifest.sig"; then
  pass "签名包内含恰一个根级 manifest.sig 且可抽回"
else
  fail "签名包 manifest.sig 缺失/重复或抽回失败"
fi
SIG_S="$EX_S/$ROOT_S/manifest.sig"
MANIFEST_S="$EX_S/$ROOT_S/manifest.json"
if [[ -f "$SIG_S" ]] && [[ "$(wc -l < "$SIG_S" | tr -d ' ')" == "1" ]] \
   && grep -Eq '^[A-Za-z0-9+/]+={0,2}$' "$SIG_S"; then
  pass "manifest.sig 为 base64 单行文本"
else
  fail "manifest.sig 单行格式"
fi
if [[ -f "$MANIFEST_S" ]] \
   && jq -e 'all(.files[]; .path != "manifest.json" and .path != "manifest.sig")' "$MANIFEST_S" >/dev/null; then
  pass "files 清单不含 manifest.json/manifest.sig（签名包）"
else
  fail "files 清单含保留路径（签名包）"
fi
# 对归档内 manifest.json 原始字节验签（服务端口径）
if (
  source "$COMMON"; source "$SIGNING"
  ed25519_verify_file "$TMP_ROOT/rel.pub" "$MANIFEST_S" "$SIG_S"
); then
  pass "manifest.sig 对 manifest.json 归档字节验签通过（服务端口径）"
else
  fail "manifest.sig 验签"
fi
# 签名包 Go 同口径校验（含 manifest.sig 保留路径与结构断言）
if "$CHECKER" "$PKG_S" "1.4.0" > "$TMP_ROOT/check-signed.out" 2>&1; then
  pass "签名包 Go 同口径校验通过（files_manifest_sha256 + manifest.sig 保留路径）"
else
  fail "签名包 Go 同口径校验（$(cat "$TMP_ROOT/check-signed.out")）"
fi
# 交付边界：构建脚本只产出包并引导到前台“系统升级”页面，绝不打印 curl/CLI 上传旁路。
if grep -q '仅可通过前台“系统升级”页面上传' "$S_OUT" \
   && ! grep -q 'curl ' "$S_OUT" \
   && ! grep -q '/api/v1/upgrades/packages/upload' "$S_OUT"; then
  pass "构建结果仅引导到前台系统升级页面（无 curl/CLI 上传旁路）"
else
  fail "前台唯一上传引导（输出见 ${S_OUT}）"
fi

# 同名输出必须保持原字节，补丁版本同样由统一入口自动识别并签名。
cp "$PKG_S" "$TMP_ROOT/original-signed.tar.gz"
expect_exit "拒绝覆盖同名升级包" 1 env WDSP_SIGNING_KEY="$TMP_ROOT/rel.key" \
  bash "$SIGNED_FIX/ops/upgrade/build-upgrade-pack.sh" --to 1.4.0 --arch "$HOST_ARCH" \
  --images-dir "$FIX" --output-dir "$DIST_S"
check "拒绝覆盖后原包字节不变" cmp "$PKG_S" "$TMP_ROOT/original-signed.tar.gz"
PATCH_DIST="$TMP_ROOT/unified-bugfix"
if WDSP_SIGNING_KEY="$TMP_ROOT/rel.key" bash "$SIGNED_FIX/ops/upgrade/build-upgrade-pack.sh" \
    --to 1.2.1 --arch "$HOST_ARCH" --images-dir "$FIX" --output-dir "$PATCH_DIST" \
    > "$TMP_ROOT/bugfix.out" 2>&1 \
   && tar -xOzf "$PATCH_DIST/jiuzhang-wdsp-upgrade-1.2.1-$HOST_ARCH.tar.gz" \
      "jiuzhang-wdsp-upgrade-1.2.1-$HOST_ARCH/manifest.json" \
      | jq -e '.change_type == "bugfix" and .package_type == "upgrade" and .components == ["api", "web"]' >/dev/null; then
  pass "Bug 修复与功能更新使用同一自动签名打包入口"
else
  fail "统一 Bug 修复包构建或 manifest 校验失败"
fi

# ---------- 9. 负例：未配置私钥且未显式 --unsigned ----------
N_OUT="$TMP_ROOT/build-nokey.out"
if env -u WDSP_SIGNING_KEY bash "$BUILDER" --to 1.5.0 --arch "$HOST_ARCH" \
    --components "api web" --images-dir "$FIX" --output-dir "$TMP_ROOT/dist-nokey" > "$N_OUT" 2>&1; then
  fail "未配置私钥且未 --unsigned 应失败"
else
  rc=$?
  if [[ "$rc" == "1" ]] && grep -q 'WDSP_SIGNING_KEY' "$N_OUT"; then
    pass "未配置私钥 fail-closed（退出码 1 + 提示 WDSP_SIGNING_KEY）"
  else
    fail "未配置私钥处置异常（rc=${rc}，输出见 ${N_OUT}）"
  fi
fi

# ---------- 10. 负例：篡改签名包镜像文件 → files 哈希校验失败（链式信任证据） ----------
TP="$TMP_ROOT/tamper-payload"
mkdir -p "$TP"
tar -xzf "$PKG_S" -C "$TP"
printf 'x' >> "$TP/$ROOT_S/images/api-$HOST_ARCH.tar.gz"
COPYFILE_DISABLE=1 tar -C "$TP" -czf "$TMP_ROOT/tampered-payload.tar.gz" "$ROOT_S"
if "$CHECKER" "$TMP_ROOT/tampered-payload.tar.gz" "1.4.0" >/dev/null 2>&1; then
  fail "篡改签名包镜像文件未被检出"
else
  pass "篡改签名包镜像文件：files 哈希校验失败被检出"
fi
# 链式信任：manifest.json 未动，manifest.sig 验签仍通过 → 篡改由 manifest.files 层兜住
if (
  source "$COMMON"; source "$SIGNING"
  ed25519_verify_file "$TMP_ROOT/rel.pub" "$TP/$ROOT_S/manifest.json" "$TP/$ROOT_S/manifest.sig"
); then
  pass "链式信任：镜像被篡改时 manifest.sig 仍验签通过（由 files 层检出）"
else
  fail "链式信任：镜像篡改后 manifest.sig 应仍验签通过"
fi

# ---------- 11. 负例：篡改 manifest 后清单摘要校验失败 ----------
TM="$TMP_ROOT/tamper-manifest"
mkdir -p "$TM"
tar -xzf "$PKG_U" -C "$TM"
jq '(.files[0].sha256) |= (if startswith("0") then "1" + .[1:] else "0" + .[1:] end)' \
  "$TM/$ROOT_NAME/manifest.json" > "$TM/$ROOT_NAME/manifest.json.new"
mv "$TM/$ROOT_NAME/manifest.json.new" "$TM/$ROOT_NAME/manifest.json"
COPYFILE_DISABLE=1 tar -C "$TM" -czf "$TMP_ROOT/tampered-manifest.tar.gz" "$ROOT_NAME"
if "$CHECKER" "$TMP_ROOT/tampered-manifest.tar.gz" "1.3.0" >/dev/null 2>&1; then
  fail "篡改 manifest 未被检出"
else
  pass "篡改 manifest：files_manifest_sha256 摘要不一致被检出"
fi

# ---------- 12. 负例：篡改签名包 manifest.json 后 manifest.sig 验签失败 ----------
if [[ -f "$PKG_S" ]]; then
  TM_S="$TMP_ROOT/tamper-signed-manifest"
  mkdir -p "$TM_S"
  tar -xzf "$PKG_S" -C "$TM_S"
  jq '.version = "1.4.1"' "$TM_S/$ROOT_S/manifest.json" > "$TM_S/$ROOT_S/manifest.json.new"
  mv "$TM_S/$ROOT_S/manifest.json.new" "$TM_S/$ROOT_S/manifest.json"
  (
    source "$COMMON"; source "$SIGNING"
    rc=0
    ed25519_verify_file "$TMP_ROOT/rel.pub" "$TM_S/$ROOT_S/manifest.json" "$TM_S/$ROOT_S/manifest.sig" 2>/dev/null || rc=$?
    [[ "$rc" -eq 1 ]]
  ) && pass "篡改 manifest.json 后 manifest.sig 验签失败" || fail "篡改 manifest 验签检出"
else
  fail "签名包缺失，跳过 manifest 篡改验签负例"
fi

# ---------- 13. --from 缺省读取 VERSION.md ----------
VER_BASE="$(grep -E '当前已发布版本：`[0-9]+\.[0-9]+\.[0-9]+`' "$REPO_ROOT/VERSION.md" \
  | head -1 | sed -E 's/.*`([0-9]+\.[0-9]+\.[0-9]+)`.*/\1/')"
DIST_D="$TMP_ROOT/dist-default-from"
ROOT_D="jiuzhang-wdsp-upgrade-1.6.0-$HOST_ARCH"
if env -u WDSP_SIGNING_KEY bash "$BUILDER" --to 1.6.0 --arch "$HOST_ARCH" \
    --components "api web" --images-dir "$FIX" --unsigned --output-dir "$DIST_D" >/dev/null 2>&1; then
  EX_D="$TMP_ROOT/extract-default"
  mkdir -p "$EX_D"
  tar -xzf "$DIST_D/$ROOT_D.tar.gz" -C "$EX_D" "$ROOT_D/manifest.json"
  if jq -e --arg v "$VER_BASE" '.version_from == $v and .version == "1.6.0" and .version_to == "1.6.0"' \
      "$EX_D/$ROOT_D/manifest.json" >/dev/null; then
    pass "--from 缺省读取 VERSION.md（${VER_BASE}）"
  else
    fail "--from 缺省值未写入 manifest"
  fi
else
  fail "--from 缺省构建执行失败"
fi

# ---------- 14. --components auto 自动识别（临时 git 仓库夹具） ----------
# 夹具 = 迷你仓库：ops/ 支撑脚本 + server/ + web/ 基线提交并打 tag wdsp-v1.2.0；
# 第二轮提交改 server/+web/，另加未跟踪 gateway/netmgrd/ 路径（未提交改动须告警）。
# 注意：git 写操作全部发生在临时夹具仓库内，不触碰真实仓库。
AUTO_FIX="$TMP_ROOT/auto-repo"
mkdir -p "$AUTO_FIX/ops/upgrade" "$AUTO_FIX/ops/lib" "$AUTO_FIX/server/migrations" \
         "$AUTO_FIX/web/src" "$AUTO_FIX/gateway/netmgrd"
cp "$BUILDER" "$REPO_ROOT/ops/upgrade/install-executor.sh" \
   "$REPO_ROOT/ops/upgrade/upgrade-executor.sh" "$AUTO_FIX/ops/upgrade/"
cp "$COMMON" "$SIGNING" "$AUTO_FIX/ops/lib/"
printf 'CREATE TABLE t(id INTEGER);\n' > "$AUTO_FIX/server/migrations/000001_init.up.sql"
printf 'api baseline\n' > "$AUTO_FIX/server/app.txt"
printf 'web baseline\n' > "$AUTO_FIX/web/src/app.txt"
git -C "$AUTO_FIX" init -q
git -C "$AUTO_FIX" config user.name harness
git -C "$AUTO_FIX" config user.email harness@example.invalid
git -C "$AUTO_FIX" add -A
git -C "$AUTO_FIX" commit -qm "baseline"
git -C "$AUTO_FIX" tag wdsp-v1.2.0
printf 'api changed\n' >> "$AUTO_FIX/server/app.txt"
printf 'web changed\n' >> "$AUTO_FIX/web/src/app.txt"
git -C "$AUTO_FIX" add -A
git -C "$AUTO_FIX" commit -qm "server+web changes"
printf 'netmgrd new file\n' > "$AUTO_FIX/gateway/netmgrd/newfile.txt"

AUTO_OUT="$TMP_ROOT/build-auto.out"
if env -u WDSP_SIGNING_KEY bash "$AUTO_FIX/ops/upgrade/build-upgrade-pack.sh" --from 1.2.0 --to 1.3.0 \
    --arch "$HOST_ARCH" --components auto --images-dir "$FIX" --unsigned \
    --output-dir "$TMP_ROOT/dist-auto" > "$AUTO_OUT" 2>&1; then
  pass "auto 构建执行成功"
else
  fail "auto 构建执行失败（输出见 ${AUTO_OUT}）"
fi
if grep -q 'auto 证据: api ←' "$AUTO_OUT" \
   && grep -q 'auto 证据: web ←' "$AUTO_OUT" \
   && grep -q 'auto 证据: netmgrd ←' "$AUTO_OUT" \
   && ! grep -q 'auto 证据: gateway ←' "$AUTO_OUT"; then
  pass "auto 证据行逐组件打印（api/web/netmgrd，无 gateway）"
else
  fail "auto 证据行打印（输出见 ${AUTO_OUT}）"
fi
grep -q '未提交改动' "$AUTO_OUT" \
  && pass "auto 检出未提交改动并告警" \
  || fail "auto 未提交改动告警（输出见 ${AUTO_OUT}）"
EX_A="$TMP_ROOT/extract-auto"
mkdir -p "$EX_A"
tar -xzf "$TMP_ROOT/dist-auto/jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH.tar.gz" -C "$EX_A" \
  "jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH/manifest.json"
if jq -e '(.components | sort) == ["api","netmgrd","web"]' \
    "$EX_A/jiuzhang-wdsp-upgrade-1.3.0-$HOST_ARCH/manifest.json" >/dev/null; then
  pass "auto 识别组件集合正确（api netmgrd web，写入 manifest）"
else
  fail "auto 识别组件集合"
fi

expect_exit "auto 与显式清单互斥" 2 env -u WDSP_SIGNING_KEY \
  bash "$BUILDER" --from 1.2.0 --to 1.7.0 --components "auto api"
expect_exit "auto 与显式清单互斥（逗号分隔）" 2 env -u WDSP_SIGNING_KEY \
  bash "$BUILDER" --from 1.2.0 --to 1.7.0 --components "auto,web"

TAGMISS_OUT="$TMP_ROOT/auto-notag.out"
env -u WDSP_SIGNING_KEY bash "$AUTO_FIX/ops/upgrade/build-upgrade-pack.sh" --from 1.1.0 --to 1.3.0 \
  --arch "$HOST_ARCH" --components auto --images-dir "$FIX" --unsigned \
  --output-dir "$TMP_ROOT/dist-notag" > "$TAGMISS_OUT" 2>&1
rc=$?
if [[ "$rc" == "1" ]] && grep -q 'wdsp-v1.1.0' "$TAGMISS_OUT" && grep -q 'git fetch --tags' "$TAGMISS_OUT"; then
  pass "auto 基准 tag 缺失报错并提示 git fetch --tags（脚本不自行 fetch）"
else
  fail "auto tag 缺失处置（rc=${rc}，输出见 ${TAGMISS_OUT}）"
fi

# 纯非镜像路径变更（docs）→ auto 报错并提示
AUTO_FIX2="$TMP_ROOT/auto-repo-docs"
mkdir -p "$AUTO_FIX2/ops/upgrade" "$AUTO_FIX2/ops/lib" "$AUTO_FIX2/server/migrations" "$AUTO_FIX2/docs"
cp "$BUILDER" "$REPO_ROOT/ops/upgrade/install-executor.sh" \
   "$REPO_ROOT/ops/upgrade/upgrade-executor.sh" "$AUTO_FIX2/ops/upgrade/"
cp "$COMMON" "$SIGNING" "$AUTO_FIX2/ops/lib/"
printf 'CREATE TABLE t(id INTEGER);\n' > "$AUTO_FIX2/server/migrations/000001_init.up.sql"
printf 'doc baseline\n' > "$AUTO_FIX2/docs/note.md"
git -C "$AUTO_FIX2" init -q
git -C "$AUTO_FIX2" config user.name harness
git -C "$AUTO_FIX2" config user.email harness@example.invalid
git -C "$AUTO_FIX2" add -A
git -C "$AUTO_FIX2" commit -qm "baseline"
git -C "$AUTO_FIX2" tag wdsp-v1.2.0
printf 'doc changed\n' >> "$AUTO_FIX2/docs/note.md"
git -C "$AUTO_FIX2" add -A
git -C "$AUTO_FIX2" commit -qm "docs only"
DOCS_OUT="$TMP_ROOT/auto-docs.out"
env -u WDSP_SIGNING_KEY bash "$AUTO_FIX2/ops/upgrade/build-upgrade-pack.sh" --from 1.2.0 --to 1.3.0 \
  --arch "$HOST_ARCH" --components auto --images-dir "$FIX" --unsigned \
  --output-dir "$TMP_ROOT/dist-autodocs" > "$DOCS_OUT" 2>&1
rc=$?
if [[ "$rc" == "1" ]] && grep -q '未识别出需要构建的镜像组件' "$DOCS_OUT" \
   && grep -q '不产生镜像组件' "$DOCS_OUT"; then
  pass "纯 docs 变更 auto 报错（提示不产生镜像组件 + 未识别出组件）"
else
  fail "纯 docs 变更 auto 处置（rc=${rc}，输出见 ${DOCS_OUT}）"
fi

printf '\n========== harness 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
