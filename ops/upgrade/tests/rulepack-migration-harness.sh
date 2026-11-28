#!/usr/bin/env bash
# rulepack-migration-harness.sh —— 离线 WAF 规则卷（gateway-rules）跨版本迁移与防降级自动化夹具。
#
# 覆盖场景：
#   1. 首次迁移（旧版 ./gateway/rules bind mount → 新版 gateway-rules 命名卷）：
#      - 停容器前带 Compose 项目/卷标签创建卷；
#      - 从新 release/gateway/rules 写入 releases/builtin-<to_version>/；
#      - 创建相对软链 current -> releases/builtin-<to_version>；
#      - 目录 0750 / 文件 0640 权限；
#      - 校验锚点文件（coraza.conf / crs/crs-setup.conf / jiuzhang/post-contrib-blocking.conf）
#        以及兼容软链（保障旧 autosave.json --resume 零中断）。
#   2. 防降级保护（§9.2）：
#      - 已有客户日期规则包 current -> releases/20261201.1；
#      - 系统升级 1.20.0 -> 1.21.0 旁路写入 releases/builtin-1.21.0/，绝不改写 current。
#   3. 内置基线升级与失败回滚：
#      - current -> releases/builtin-1.20.0 升级到 builtin-1.21.0；
#      - 切换后健康检查失败触发 rollback.sh 自动恢复 current -> releases/builtin-1.20.0。
#   4. Fail-closed 拒绝：
#      - 种子目录缺失核心锚点（post-contrib-blocking.conf）在停容器前直接中止；
#      - 客户规则包软链损坏/指向缺失快照在停容器前直接中止。
#
# 注意：本夹具使用伪 docker/curl 模拟编排行为，不替代目标 Linux 真实容器升级验收（见 UPGRADE_INCIDENT_2026-11-17.md）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"

for cmd in bash jq python3 base64 cmp mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: missing command $cmd" >&2; exit 1; }
done

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf 'FAIL: %s\n' "$*" >&2; }

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-rulepack-mig-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-rulepack-mig-harness.*) rm -rf "$TMP_ROOT" ;;
    *) echo "拒绝清理非测试目录: $TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

mode_octal() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

make_rules_tree() {
  local dir="$1" marker="$2"
  mkdir -p "$dir/crs/rules" "$dir/contrib/CUSTOM_PACK" "$dir/exclusions" "$dir/jiuzhang"
  printf '# coraza %s\nSecRuleEngine On\n' "$marker" > "$dir/coraza.conf"
  printf '# crs-setup %s\n' "$marker" > "$dir/crs/crs-setup.conf"
  printf '4.28.0\n' > "$dir/crs/VERSION.txt"
  printf 'SecRule ARGS "@contains %s" "id:942100,phase:2,block"\n' "$marker" > "$dir/crs/rules/REQUEST-942.conf"
  printf '# contrib %s\n' "$marker" > "$dir/contrib/CUSTOM_PACK/cve.conf"
  printf '# before %s\n' "$marker" > "$dir/exclusions/before-crs.conf"
  printf '# after %s\n' "$marker" > "$dir/exclusions/after-crs.conf"
  printf '# custom %s\n' "$marker" > "$dir/jiuzhang/jiuzhang-custom.conf"
  printf '# post-blocking %s\n' "$marker" > "$dir/jiuzhang/post-contrib-blocking.conf"
}

setup_case() {
  local name="$1" to_ver="$2" old_uses_vol="$3"
  local case_dir="$TMP_ROOT/$name"
  mkdir -p "$case_dir/bin" "$case_dir/ops/lib" "$case_dir/ops/upgrade" "$case_dir/ops/healthcheck" \
           "$case_dir/old-release" "$case_dir/new-release/images" "$case_dir/new-release/ops/install" \
           "$case_dir/volumes/jiuzhang-wdsp_gateway-config/_data/caddy"

  cp "$REPO_ROOT/ops/lib/common.sh" "$case_dir/ops/lib/common.sh"
  cp "$REPO_ROOT/ops/upgrade/apply.sh" "$case_dir/ops/upgrade/apply.sh"
  cp "$REPO_ROOT/ops/upgrade/rollback.sh" "$case_dir/ops/upgrade/rollback.sh"
  chmod +x "$case_dir/ops/upgrade/apply.sh" "$case_dir/ops/upgrade/rollback.sh"

  cat > "$case_dir/ops/healthcheck/check.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HEALTH_LOG"
if [[ -n "${FAIL_SECOND_HEALTH:-}" && "$(wc -l < "$HEALTH_LOG")" -ge 2 ]]; then
  exit 1
fi
exit 0
EOF
  chmod +x "$case_dir/ops/healthcheck/check.sh"

  cat > "$case_dir/new-release/ops/install/install-hostctl.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$case_dir/new-release/ops/install/install-hostctl.sh"

  cat > "$case_dir/old-release/ops-install-executor.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  mkdir -p "$case_dir/old-release/ops/upgrade" "$case_dir/old-release/ops/install"
  cp "$case_dir/old-release/ops-install-executor.sh" "$case_dir/old-release/ops/upgrade/install-executor.sh"
  cp "$case_dir/new-release/ops/install/install-hostctl.sh" "$case_dir/old-release/ops/install/install-hostctl.sh"
  chmod +x "$case_dir/old-release/ops/upgrade/install-executor.sh" "$case_dir/old-release/ops/install/install-hostctl.sh"

  for img in jiuzhang-server jiuzhang-web jiuzhang-gateway jiuzhang-netmgrd jiuzhang-logrotator jiuzhang-containerops; do
    printf 'fixture' > "$case_dir/new-release/images/${img}.tar"
  done

  printf '{"version":"%s","edition":"wdsp"}\n' "$to_ver" > "$case_dir/new-release/manifest.json"
  make_rules_tree "$case_dir/new-release/gateway/rules" "seed-${to_ver}"
  make_rules_tree "$case_dir/old-release/gateway/rules" "old-legacy"

  cat > "$case_dir/.env" <<'EOF'
INITIAL_ADMIN_USERNAME=admin
POSTGRES_PASSWORD=fixture
VALKEY_PASSWORD=fixture
JIUZHANG_MASTER_KEY=fixture
EOF

  # 写入 autosave.json（默认引用扁平 /etc/caddy/rules/coraza.conf，验证跨版本升级兼容）
  cat > "$case_dir/volumes/jiuzhang-wdsp_gateway-config/_data/caddy/autosave.json" <<'EOF'
{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"waf","directives":"Include /etc/caddy/rules/coraza.conf\n"}]}]}}}}}
EOF

  # 生成 old & new compose JSON（由伪 docker compose config 直接回显）
  python3 - "$case_dir" "$to_ver" "$old_uses_vol" <<'PY'
import json, pathlib, sys
case_dir = pathlib.Path(sys.argv[1])
to_ver = sys.argv[2]
old_uses_vol = sys.argv[3] == "true"

def base_compose(tag, use_rules_vol):
    api_vols = [{"type": "volume", "source": "runtime-data", "target": "/app/runtime"}]
    gw_vols = [
        {"type": "volume", "source": "gateway-config", "target": "/config"},
        {"type": "volume", "source": "gateway-admin", "target": "/var/run/caddy"},
    ]
    vols = {
        "runtime-data": {"name": "jiuzhang-wdsp_runtime-data"},
        "gateway-config": {"name": "jiuzhang-wdsp_gateway-config"},
        "gateway-admin": {"name": "jiuzhang-wdsp_gateway-admin"},
    }
    if use_rules_vol:
        api_vols.append({"type": "volume", "source": "gateway-rules", "target": "/app/runtime/rules"})
        gw_vols.append({"type": "volume", "source": "gateway-rules", "target": "/etc/caddy/rules", "read_only": True})
        vols["gateway-rules"] = {"name": "jiuzhang-wdsp_gateway-rules"}
    else:
        gw_vols.append({"type": "bind", "source": str(case_dir / "old-release/gateway/rules"), "target": "/etc/caddy/rules", "read_only": True})
    return {
        "name": "jiuzhang-wdsp",
        "services": {
            "api": {"image": f"jiuzhang-server:{tag}", "volumes": api_vols},
            "web": {"image": f"jiuzhang-web:{tag}"},
            "gateway": {
                "image": f"jiuzhang-gateway:{tag}",
                "user": "0:0",
                "entrypoint": ["/usr/local/bin/wdsp-gateway-bind"],
                "cap_drop": ["ALL"],
                "cap_add": ["NET_BIND_SERVICE", "SETUID", "SETGID", "SETPCAP"],
                "security_opt": ["no-new-privileges:true"],
                "volumes": gw_vols,
            },
            "netmgrd": {"image": f"jiuzhang-netmgrd:{tag}"},
            "logrotator": {"image": f"jiuzhang-logrotator:{tag}"},
            "containerops": {"image": f"jiuzhang-containerops:{tag}"},
        },
        "volumes": vols,
    }

(case_dir / "old-release/docker-compose.yml").write_text(json.dumps(base_compose("1.19.1", old_uses_vol)))
(case_dir / "new-release/docker-compose.yml").write_text(json.dumps(base_compose(to_ver, True)))

fixture = {
    "volume_root": str(case_dir / "volumes"),
    "schema": 254,
    "target_schema": 255,
    "postgres_id": "a" * 64,
    "images": {},
    "volumes": {
        "jiuzhang-wdsp_gateway-config": {"mountpoint": str(case_dir / "volumes/jiuzhang-wdsp_gateway-config/_data"), "labels": {}},
    },
    "running": {
        "api": {"id": "1" * 64, "image": "jiuzhang-server:1.19.1", "image_id": "sha256:api-old", "mounts": []},
        "gateway": {
            "id": "2" * 64,
            "image": "jiuzhang-gateway:1.19.1",
            "image_id": "sha256:gw-old",
            "mounts": [{"Destination": "/config", "Source": str(case_dir / "volumes/jiuzhang-wdsp_gateway-config/_data")}],
        },
    },
}
for svc, repo in (("api", "jiuzhang-server"), ("web", "jiuzhang-web"), ("gateway", "jiuzhang-gateway"),
                  ("netmgrd", "jiuzhang-netmgrd"), ("logrotator", "jiuzhang-logrotator"), ("containerops", "jiuzhang-containerops")):
    ep = ["/usr/local/bin/wdsp-gateway-bind"] if svc == "gateway" else None
    fixture["images"][f"{repo}:1.19.1"] = {"id": f"sha256:{svc}-old", "entrypoint": ep}
    fixture["images"][f"{repo}:{to_ver}"] = {"id": f"sha256:{svc}-new", "entrypoint": ep}
(case_dir / "fixture.json").write_text(json.dumps(fixture))
PY

  # 伪 docker CLI
  cat > "$case_dir/bin/docker" <<'PYEOF'
#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

fixture_path = Path(os.environ["DOCKER_FIXTURE"])
fixture = json.loads(fixture_path.read_text())
args = sys.argv[1:]

def log(event):
    with open(os.environ["DOCKER_LOG"], "a") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")

def find_image(ref):
    if ref in fixture["images"]:
        return fixture["images"][ref]
    for v in fixture["images"].values():
        if v["id"] == ref:
            return v
    return None

if args[:2] == ["image", "inspect"]:
    fmt, ref = "", ""
    i = 2
    while i < len(args):
        if args[i] == "--format":
            fmt = args[i + 1]; i += 2; continue
        if args[i].startswith("--format="):
            fmt = args[i].split("=", 1)[1]
        elif not args[i].startswith("-"):
            ref = args[i]
        i += 1
    found = find_image(ref)
    if not found:
        sys.exit(1)
    if fmt == "{{.Id}}":
        print(found["id"])
    elif fmt == "{{json .Config.Entrypoint}}":
        print(json.dumps(found.get("entrypoint")))
    sys.exit(0)

if args[:1] == ["load"]:
    log({"kind": "load"})
    sys.exit(0)

if args[:1] == ["tag"]:
    found = find_image(args[1])
    if not found:
        sys.exit(1)
    fixture["images"][args[2]] = dict(found)
    fixture_path.write_text(json.dumps(fixture))
    sys.exit(0)

if args[:1] == ["run"]:
    log({"kind": "run", "args": args})
    if fixture["schema"] > 254:
        fixture["schema"] -= 1
        fixture_path.write_text(json.dumps(fixture))
    sys.exit(0)

if args[:1] == ["inspect"]:
    fmt = args[args.index("--format") + 1]
    cid = args[-1]
    target = next((v for v in fixture.get("running", {}).values() if v["id"] == cid), None)
    if not target:
        sys.exit(1)
    if fmt == "{{.State.Status}}":
        print("running")
    elif fmt == "{{json .Mounts}}":
        print(json.dumps(target.get("mounts", [])))
    elif fmt == "{{json .NetworkSettings.Networks}}":
        print("{}")
    else:
        if fmt.endswith("{{.State.StartedAt}}"):
            print(f"running|healthy|{target['image_id']}|0|2026-11-28T00:00:00Z")
        else:
            print(f"running|healthy|{target['image_id']}")
    sys.exit(0)

if args[:1] == ["exec"]:
    cmd_str = " ".join(args)
    if args[1] == fixture["postgres_id"]:
        if "SELECT COUNT(*)" in cmd_str:
            print(max(0, fixture["schema"] - 254))
        else:
            print(fixture["schema"])
    sys.exit(0)

if args[:1] == ["volume"]:
    sub = args[1]
    vols = fixture.setdefault("volumes", {})
    if sub == "inspect":
        fmt, name = "", ""
        i = 2
        while i < len(args):
            if args[i] == "--format":
                fmt = args[i + 1]; i += 2; continue
            if args[i].startswith("--format="):
                fmt = args[i].split("=", 1)[1]
            elif not args[i].startswith("-"):
                name = args[i]
            i += 1
        vol = vols.get(name)
        if not vol:
            sys.exit(1)
        if fmt == "{{.Mountpoint}}":
            print(vol["mountpoint"])
        else:
            print(json.dumps(vol))
        sys.exit(0)
    if sub == "create":
        labels, name = {}, ""
        i = 2
        while i < len(args):
            if args[i] == "--label":
                k, _, v = args[i + 1].partition("=")
                labels[k] = v; i += 2; continue
            if args[i].startswith("--label="):
                k, _, v = args[i].split("=", 1)[1].partition("=")
                labels[k] = v
            elif not args[i].startswith("-"):
                name = args[i]
            i += 1
        mp = Path(fixture["volume_root"]) / name / "_data"
        mp.mkdir(parents=True, exist_ok=True)
        vols[name] = {"mountpoint": str(mp), "labels": labels}
        fixture_path.write_text(json.dumps(fixture))
        log({"kind": "volume-create", "name": name, "labels": labels})
        print(name)
        sys.exit(0)
    sys.exit(1)

if args[:1] == ["compose"]:
    files = []
    i = 1
    while i < len(args):
        if args[i] == "-f":
            files.append(args[i + 1]); i += 2; continue
        if args[i] == "--env-file":
            i += 2; continue
        break
    sub = args[i]
    rest = args[i + 1:]
    cfg = json.loads(Path(files[0]).read_text())
    if sub == "config":
        print(json.dumps(cfg))
        sys.exit(0)
    if sub == "ps":
        svc = rest[-1]
        if svc == "postgres":
            print(fixture["postgres_id"])
            sys.exit(0)
        cur = fixture.get("running", {}).get(svc)
        if cur:
            print(cur["id"])
        sys.exit(0)
    if sub in ("rm", "stop"):
        log({"kind": "compose", "action": sub, "services": rest})
        sys.exit(0)
    if sub == "up":
        svcs = [s for s in rest if not s.startswith("-")]
        log({"kind": "compose", "action": "up", "services": svcs, "file": files[0]})
        for idx, svc in enumerate(svcs):
            img = cfg["services"][svc]["image"]
            info = find_image(img)
            fixture.setdefault("running", {})[svc] = {
                "id": f"{idx+1}" * 64,
                "image": img,
                "image_id": info["id"],
                "mounts": [],
            }
        if "new-release" in files[0]:
            fixture["schema"] = fixture["target_schema"]
        fixture_path.write_text(json.dumps(fixture))
        sys.exit(0)
sys.exit(1)
PYEOF
  chmod +x "$case_dir/bin/docker"

  cat > "$case_dir/bin/curl" <<'PYEOF'
#!/usr/bin/env python3
import sys
args = " ".join(sys.argv[1:])
if "/api/v1/auth/login" in args:
    print('{"code":"SUCCESS","data":{"csrf_token":"fixture-csrf"}}')
elif "-X POST" in args and "/api/v1/backups" in args:
    print('{"code":"SUCCESS","data":{"job":{"id":"11111111-1111-4111-8111-111111111111"}}}')
elif "/api/v1/backups/11111111-1111-4111-8111-111111111111" in args:
    print('{"code":"SUCCESS","data":{"job":{"status":"SUCCESS","verified":true}}}')
elif "/api/v1/health" in args:
    print('{"code":"SUCCESS"}')
PYEOF
  chmod +x "$case_dir/bin/curl"

  cat > "$case_dir/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$case_dir/bin/sleep"

  cat > "$case_dir/bin/timeout" <<'EOF'
#!/usr/bin/env bash
shift
exec "$@"
EOF
  chmod +x "$case_dir/bin/timeout"

  ln -s "$case_dir/old-release" "$case_dir/current"
  printf '%s\n' "$case_dir"
}

run_apply() {
  local case_dir="$1"
  shift || true
  env \
    PATH="$case_dir/bin:$PATH" \
    DOCKER_FIXTURE="$case_dir/fixture.json" \
    DOCKER_LOG="$case_dir/docker.log" \
    HEALTH_LOG="$case_dir/health.log" \
    JZ_ADMIN_PASSWORD="fixture-password" \
    JZ_CAPTCHA_CODE="fixture-captcha" \
    "$@" \
    bash "$case_dir/ops/upgrade/apply.sh" \
      --full \
      --images-dir "$case_dir/new-release/images" \
      --compose-file "$case_dir/old-release/docker-compose.yml" \
      --env-file "$case_dir/.env" \
      --new-compose-file "$case_dir/new-release/docker-compose.yml" \
      --previous-compose-file "$case_dir/old-release/docker-compose.yml" \
      --current-link "$case_dir/current" \
      --timeout 5
}

# ---------- 场景 1：首次跨卷迁移（bind mount → gateway-rules） ----------
c1="$(setup_case case1_first_migration 1.20.0 false)"
if run_apply "$c1" >"$c1/out.log" 2>"$c1/err.log"; then
  vol="$c1/volumes/jiuzhang-wdsp_gateway-rules/_data"
  link_target="$(readlink "$vol/current" 2>/dev/null || true)"
  dir_mode="$(mode_octal "$vol/releases/builtin-1.20.0")"
  file_mode="$(mode_octal "$vol/releases/builtin-1.20.0/coraza.conf")"
  if [[ "$link_target" == "releases/builtin-1.20.0" ]] \
    && [[ "$dir_mode" == "750" && "$file_mode" == "640" ]] \
    && [[ -s "$vol/coraza.conf" && -s "$vol/crs/crs-setup.conf" && -s "$vol/jiuzhang/post-contrib-blocking.conf" ]] \
    && grep -q '"com.docker.compose.project": "jiuzhang-wdsp"' "$c1/docker.log" \
    && grep -q '"com.docker.compose.volume": "gateway-rules"' "$c1/docker.log"; then
    pass "场景 1：首次迁移创建带 Compose 标签的 gateway-rules 卷、写入 builtin-1.20.0、建立相对 current 与兼容软链且权限 0750/0640"
  else
    fail "场景 1：迁移结果断言失败 (link=$link_target dir_mode=$dir_mode file_mode=$file_mode)"
  fi
else
  fail "场景 1：apply.sh 执行失败: $(cat "$c1/err.log")"
fi

# ---------- 场景 2：防降级保护（客户日期规则包 20261201.1 不被系统升级 1.21.0 覆盖） ----------
c2="$(setup_case case2_non_downgrade 1.21.0 true)"
vol2="$c2/volumes/jiuzhang-wdsp_gateway-rules/_data"
mkdir -p "$vol2/releases" "$vol2/.staging"
make_rules_tree "$vol2/releases/20261201.1" "customer-0day-20261201.1"
ln -s "releases/20261201.1" "$vol2/current"
python3 - "$c2/fixture.json" "$vol2" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text())
d["volumes"]["jiuzhang-wdsp_gateway-rules"] = {"mountpoint": sys.argv[2], "labels": {}}
p.write_text(json.dumps(d))
PY
if run_apply "$c2" >"$c2/out.log" 2>"$c2/err.log"; then
  link2="$(readlink "$vol2/current" 2>/dev/null || true)"
  if [[ "$link2" == "releases/20261201.1" ]] \
    && [[ -f "$vol2/releases/builtin-1.21.0/coraza.conf" ]] \
    && grep -q 'customer-0day-20261201.1' "$vol2/current/coraza.conf" \
    && grep -q '保留客户规则包生效' "$c2/out.log"; then
    pass "场景 2：防降级规则生效，旁路写入 builtin-1.21.0 且完整保留客户规则包 current -> releases/20261201.1"
  else
    fail "场景 2：客户规则包未保留 (link=$link2)"
  fi
else
  fail "场景 2：apply.sh 执行失败: $(cat "$c2/err.log")"
fi

# ---------- 场景 3：builtin-1.20.0 -> builtin-1.21.0 升级失败后自动回滚恢复 current ----------
c3="$(setup_case case3_builtin_rollback 1.21.0 true)"
vol3="$c3/volumes/jiuzhang-wdsp_gateway-rules/_data"
mkdir -p "$vol3/releases" "$vol3/.staging"
make_rules_tree "$vol3/releases/builtin-1.20.0" "old-builtin-1.20.0"
ln -s "releases/builtin-1.20.0" "$vol3/current"
python3 - "$c3/fixture.json" "$vol3" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text())
d["volumes"]["jiuzhang-wdsp_gateway-rules"] = {"mountpoint": sys.argv[2], "labels": {}}
p.write_text(json.dumps(d))
PY
if run_apply "$c3" FAIL_SECOND_HEALTH=1 >"$c3/out.log" 2>"$c3/err.log"; then
  fail "场景 3：预期健康检查失败触发回滚，但 apply.sh 返回 0"
else
  link3="$(readlink "$vol3/current" 2>/dev/null || true)"
  if [[ "$link3" == "releases/builtin-1.20.0" ]] && grep -q '自动回滚完成' "$c3/err.log"; then
    pass "场景 3：内置基线升级后健康检查失败，rollback.sh 自动将 current 回切至 releases/builtin-1.20.0"
  else
    fail "场景 3：回滚后 current 未恢复 (link=$link3 err=$(cat "$c3/err.log"))"
  fi
fi

# ---------- 场景 4：种子缺核心锚点文件时停容器前 fail-closed 中止 ----------
c4="$(setup_case case4_missing_anchor 1.20.0 false)"
rm -f "$c4/new-release/gateway/rules/jiuzhang/post-contrib-blocking.conf"
if run_apply "$c4" >"$c4/out.log" 2>"$c4/err.log"; then
  fail "场景 4：缺少 post-contrib-blocking.conf 应 fail-closed 中止"
else
  if ! grep -q '"action": "up"' "$c4/docker.log" 2>/dev/null && grep -q '未切换容器' "$c4/err.log"; then
    pass "场景 4：新版本规则种子缺少锚点文件时在停容器前 fail-closed 中止"
  else
    fail "场景 4：未在停容器前中止 (err=$(cat "$c4/err.log"))"
  fi
fi

# ---------- 场景 5：客户规则包快照损坏时停容器前 fail-closed 中止 ----------
c5="$(setup_case case5_corrupt_customer_pack 1.21.0 true)"
vol5="$c5/volumes/jiuzhang-wdsp_gateway-rules/_data"
mkdir -p "$vol5/releases/20261201.1" "$vol5/.staging"
ln -s "releases/20261201.1" "$vol5/current"
python3 - "$c5/fixture.json" "$vol5" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
d = json.loads(p.read_text())
d["volumes"]["jiuzhang-wdsp_gateway-rules"] = {"mountpoint": sys.argv[2], "labels": {}}
p.write_text(json.dumps(d))
PY
if run_apply "$c5" >"$c5/out.log" 2>"$c5/err.log"; then
  fail "场景 5：损坏的客户规则快照应 fail-closed 中止，不得静默降级"
else
  if ! grep -q '"action": "up"' "$c5/docker.log" 2>/dev/null \
    && [[ "$(readlink "$vol5/current")" == "releases/20261201.1" ]]; then
    pass "场景 5：客户规则包快照不完整时停容器前 fail-closed 中止，绝不静默覆盖 current"
  else
    fail "场景 5：未正确中止或篡改了 current (err=$(cat "$c5/err.log"))"
  fi
fi

echo "============================================================"
echo "规则卷迁移夹具汇总: PASS=${PASS_COUNT} FAIL=${FAIL_COUNT}"
echo "============================================================"
[[ "$FAIL_COUNT" -eq 0 ]]
