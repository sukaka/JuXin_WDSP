#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time
import uuid

INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
NODE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TEST_MODE = os.environ.get("PCAP_TEST_ALLOW_NON_ROOT") == "1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_config(flag_path):
    with open(flag_path, encoding="utf-8") as stream:
        data = json.load(stream)
    require(isinstance(data, dict), "指令必须是对象")
    require(isinstance(data.get("enabled"), bool), "enabled必须为布尔值")
    request_id = data.get("requestID")
    uuid.UUID(request_id)
    interface = data.get("interface", "")
    require(isinstance(interface, str) and INTERFACE.fullmatch(interface), "网卡名称不合法")
    node = data.get("node_id", "")
    require(isinstance(node, str) and NODE.fullmatch(node), "节点ID不合法")
    ports = data.get("ports")
    require(isinstance(ports, list) and 1 <= len(ports) <= 128, "需要1至128个端口")
    require(all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in ports), "端口越界")
    require(len(set(ports)) == len(ports), "端口不能重复")
    data["ports"] = sorted(ports)
    for key in ("hot_dir", "warm_dir"):
        value = data.get(key, "")
        require(isinstance(value, str) and value.startswith("/") and len(value) <= 240, "存储路径必须是绝对路径")
        path = PurePosixPath(value)
        require(not any(part in ("", ".", "..") for part in path.parts[1:]), "存储路径必须规范")
        require("\x00" not in value and "\r" not in value and "\n" not in value and "'" not in value and "\\" not in value, "存储路径含非法字符")
        normalized = str(path)
        require(any(normalized.startswith(prefix) and len(normalized) > len(prefix) for prefix in allowed_roots()), "存储路径不在受控数据盘目录")
        data[key] = normalized
    hot, warm = Path(data["hot_dir"]), Path(data["warm_dir"])
    require(hot != warm and hot not in warm.parents and warm not in hot.parents, "冷热目录不能相同或嵌套")
    return data


def allowed_roots():
    if TEST_MODE and os.environ.get("PCAP_TEST_ALLOWED_ROOT"):
        return (os.environ["PCAP_TEST_ALLOWED_ROOT"].rstrip("/") + "/",)
    return (
        "/var/lib/jiuzhang-pcap/",
        "/var/lib/jiuzhang/",
        "/srv/jiuzhang-",
        "/srv/jiuzhang/",
        "/data/jiuzhang-",
        "/data/jiuzhang/",
        "/mnt/jiuzhang-",
        "/mnt/jiuzhang/",
        "/media/jiuzhang-",
        "/media/jiuzhang/",
    )


def atomic_write(path, content, mode=0o600, group=1000):
    path = Path(path)
    require(not path.parent.is_symlink(), f"目标目录不得为符号链接: {path.parent}")
    require(not path.is_symlink(), f"目标文件不得为符号链接: {path}")
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        try:
            os.fchmod(fd, mode)
            if os.geteuid() == 0:
                os.fchown(fd, 0, group)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                fd = -1
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _check_no_symlink_components(path):
    cur = Path("/")
    for part in path.parts[1:]:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"存储路径包含符号链接组件: {cur}")


def _safe_mkdir_dir(path, mode=0o700):
    _check_no_symlink_components(path)
    cur = Path("/")
    for part in path.parts[1:]:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"存储路径包含符号链接组件: {cur}")
        if cur.exists():
            require(cur.is_dir(), f"存储路径组件不是目录: {cur}")
        else:
            cur.mkdir(mode=mode)


def prepare_directories(root, config):
    for key in ("hot_dir", "warm_dir"):
        path = Path(config[key])
        _check_no_symlink_components(path)
        if path.exists():
            require(not path.is_symlink() and path.is_dir(), f"存储路径不是常规目录: {path}")
            st = os.lstat(path)
            if any(path.iterdir()) and (st.st_uid != 1000 or st.st_gid != 1000):
                raise ValueError(f"拒绝修改既有非空且非 1000:1000 属主目录的权限: {path}")
        else:
            _safe_mkdir_dir(path, mode=0o700)
        resolved = path.resolve(strict=True)
        require(resolved == path, f"存储目录解析后与声明路径不一致: {path}")
        resolved_str = str(resolved)
        require(
            any(resolved_str.startswith(prefix) and len(resolved_str) > len(prefix) for prefix in allowed_roots()),
            "存储目录解析后越出允许范围",
        )
        dir_fd = os.open(str(resolved), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(dir_fd)
            if any(resolved.iterdir()) and (st.st_uid != 1000 or st.st_gid != 1000):
                raise ValueError(f"拒绝修改既有非空且非 1000:1000 属主目录的权限: {resolved}")
            if os.geteuid() == 0:
                os.fchown(dir_fd, 1000, 1000)
            os.fchmod(dir_fd, 0o700)
        finally:
            os.close(dir_fd)
    runtime_dir = root / "runtime"
    require(not runtime_dir.is_symlink(), "runtime 目录不得为符号链接")
    for name, mode in (("pcap-private", 0o700), ("pcap-public", 0o755)):
        directory = runtime_dir / name
        require(not directory.is_symlink(), f"运行目录不得为符号链接: {directory}")
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
        dir_fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.geteuid() == 0:
                os.fchown(dir_fd, 1000, 1000)
            os.fchmod(dir_fd, mode)
        finally:
            os.close(dir_fd)


def merge_compose_profiles(original_env, extra_profile="request-pcap"):
    existing = []
    for raw_line in original_env.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key.strip() == "COMPOSE_PROFILES":
            val = val.strip().strip('"').strip("'")
            existing = [item.strip() for item in val.split(",") if item.strip()]
    merged = list(existing)
    if extra_profile and extra_profile not in merged:
        merged.append(extra_profile)
    return ",".join(merged)


def environment(config, compose_profiles="request-pcap"):
    enabled = "true" if config["enabled"] else "false"
    return "\n".join((
        f"COMPOSE_PROFILES={compose_profiles}",
        f"REQUEST_PCAP_CAPTURE_ENABLED={enabled}",
        f"REQUEST_PCAP_IFACE={config['interface']}",
        "REQUEST_PCAP_PORTS=" + ",".join(str(port) for port in config["ports"]),
        f"REQUEST_PCAP_HOT_DIR={config['hot_dir']}",
        f"REQUEST_PCAP_WARM_DIR={config['warm_dir']}",
        "REQUEST_PCAP_POLICY_VERSION=system-admin-v1",
        "PCAP_SERVER_HOT_DIR=/app/runtime/pcap-hot",
        "PCAP_SERVER_WARM_DIR=/app/runtime/pcap-warm",
        "PCAP_SERVER_KEY_FILE=/app/runtime/pcap-private/private.key",
        "PCAP_SERVER_PUBLIC_DIR=/app/runtime/pcap-public",
        "REQUEST_PCAP_RETENTION=24h",
        "REQUEST_PCAP_HOT_AGE=15m",
        "REQUEST_PCAP_GRANT_TTL=24h",
        "REQUEST_PCAP_MIGRATE_BPS=33554432",
        "REQUEST_PCAP_MIN_FREE_PERCENT=10",
        "",
    ))


def compose(root, *args):
    command = ["docker", "compose", "-f", str(root / "docker-compose.yml"),
               "--env-file", str(root / "runtime/pcap-runtime.env"), *args]
    return subprocess.run(command, cwd=root, check=True, capture_output=True, text=True, timeout=150)


def inspect_container(container_id):
    result = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", container_id],
                            check=True, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def wait_service(root, service, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = compose(root, "ps", "-q", service)
        container_id = result.stdout.strip()
        if re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id):
            status = inspect_container(container_id)
            if status in ("running|healthy", "running|"):
                time.sleep(5)
                if inspect_container(container_id) == status:
                    return
        time.sleep(1)
    raise RuntimeError(f"{service}未通过运行状态和健康检查")


VALID_DOCKER_NET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
BUILTIN_DOCKER_NETS = frozenset({"none", "host", "bridge"})


def _valid_extra_network(name):
    return isinstance(name, str) and bool(VALID_DOCKER_NET.fullmatch(name)) and name not in BUILTIN_DOCKER_NETS


def _container_networks(container):
    if not container:
        return []
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return []
    try:
        parsed = json.loads(result.stdout.strip())
    except ValueError:
        return []
    if not isinstance(parsed, dict):
        return []
    return sorted(name for name in parsed.keys() if _valid_extra_network(name))


def _compose_api_networks(root):
    try:
        result = compose(root, "config", "--format", "json")
        rendered = json.loads(result.stdout)
    except Exception:
        return set()
    if not isinstance(rendered, dict):
        return set()
    project = rendered.get("name") or ""
    top_nets = rendered.get("networks") if isinstance(rendered.get("networks"), dict) else {}
    api_svc = (rendered.get("services") or {}).get("api") or {}
    raw_nets = api_svc.get("networks")
    keys = list(raw_nets) if isinstance(raw_nets, list) else list(raw_nets.keys()) if isinstance(raw_nets, dict) else []
    resolved = set()
    for key in keys:
        entry = top_nets.get(key) if isinstance(top_nets.get(key), dict) else {}
        explicit = entry.get("name")
        if isinstance(explicit, str) and explicit:
            resolved.add(explicit)
        elif isinstance(project, str) and project:
            resolved.add(f"{project}_{key}")
        else:
            resolved.add(key)
    return resolved


def _colocated_apm_clickhouse_networks():
    info = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}|{{.Name}}", "jiuzhang-apm-clickhouse"],
        capture_output=True, text=True, timeout=10,
    )
    if info.returncode == 0 and info.stdout.strip() in ("true|/jiuzhang-apm-clickhouse", "true|jiuzhang-apm-clickhouse"):
        return _container_networks("jiuzhang-apm-clickhouse")
    ps = subprocess.run(
        [
            "docker", "ps", "-q", "--filter", "status=running",
            "--filter", "label=com.docker.compose.project=jiuzhang-apm",
            "--filter", "label=com.docker.compose.service=clickhouse",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if ps.returncode == 0:
        cid = next((line.strip() for line in ps.stdout.splitlines() if line.strip()), "")
        if cid and VALID_DOCKER_NET.fullmatch(cid):
            lbl = subprocess.run(
                [
                    "docker", "inspect", "--format",
                    '{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}',
                    cid,
                ],
                capture_output=True, text=True, timeout=10,
            )
            if lbl.returncode == 0 and lbl.stdout.strip() == "true|jiuzhang-apm|clickhouse":
                return _container_networks(cid)
    return []


def _capture_api_extra_networks(root):
    excluded = _compose_api_networks(root)
    candidates = set()
    try:
        old_api = compose(root, "ps", "-q", "api").stdout.strip()
    except Exception:
        old_api = ""
    if old_api:
        candidates.update(_container_networks(old_api))
    candidates.update(_colocated_apm_clickhouse_networks())
    return sorted(net for net in candidates if _valid_extra_network(net) and net not in excluded)


def _reattach_api_extra_networks(root, networks):
    if not networks:
        return
    api_id = compose(root, "ps", "-q", "api").stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", api_id):
        raise RuntimeError("重建 api 后无法定位容器 ID，无法恢复附加网络")
    current = set(_container_networks(api_id))
    for net in networks:
        if net in current:
            continue
        insp = subprocess.run(["docker", "network", "inspect", net], capture_output=True, text=True, timeout=10)
        if insp.returncode != 0:
            raise RuntimeError(f"api 附加网络不存在，无法恢复连接: {net}")
        conn = subprocess.run(["docker", "network", "connect", net, api_id], capture_output=True, text=True, timeout=15)
        if conn.returncode != 0:
            raise RuntimeError(f"为 api 容器恢复附加网络失败: {net}")
        after = set(_container_networks(api_id))
        if net not in after:
            raise RuntimeError(f"api 容器附加网络恢复校验失败: {net}")
        current = after


def recreate_api(root):
    extra_networks = _capture_api_extra_networks(root)
    compose(root, "up", "-d", "--no-deps", "--force-recreate", "api")
    _reattach_api_extra_networks(root, extra_networks)
    wait_service(root, "api")


def stop_capture(root):
    existing = subprocess.run(["docker", "inspect", "jiuzhang-pcapd"], capture_output=True, text=True, timeout=10)
    if existing.returncode == 0:
        compose(root, "stop", "-t", "10", "pcapd")
    state = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", "jiuzhang-pcapd"],
                           capture_output=True, text=True, timeout=10)
    if state.returncode == 0 and state.stdout.strip() == "true":
        raise RuntimeError("pcapd未能停止")


def apply(root, config):
    prepare_directories(root, config)
    control = root / "runtime/pcap-control.env"
    merged = root / "runtime/pcap-runtime.env"
    with open(root / ".env", encoding="utf-8") as stream:
        original = stream.read()
    profiles = merge_compose_profiles(original, "request-pcap")
    env_block = environment(config, compose_profiles=profiles)
    atomic_write(control, env_block)
    atomic_write(merged, original.rstrip("\n") + "\n\n# system-admin PCAP control\n" + env_block)
    if not config["enabled"]:
        stop_capture(root)
        recreate_api(root)
        return
    recreate_api(root)
    public = root / "runtime/pcap-public"
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if all((public / name).is_file() and (public / name).stat().st_size > 0 for name in ("pcap-public.json", "pcap-release.pub")):
            break
        time.sleep(1)
    else:
        raise RuntimeError("API未生成有效的PCAP公钥授权")
    compose(root, "up", "-d", "--no-deps", "--force-recreate", "pcapd")
    wait_service(root, "pcapd")


def write_status(root, request_id, state, message=""):
    atomic_write(root / "runtime/hostctl/pcap-status.state", json.dumps({
        "requestID": request_id, "state": state, "message": message,
        "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, ensure_ascii=False, separators=(",", ":")) + "\n", mode=0o640)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--flag", required=True)
    args = parser.parse_args()
    request_id = "unknown"
    try:
        if os.geteuid() != 0 and not TEST_MODE:
            raise RuntimeError("PCAP采集控制需要root权限")
        root = Path(args.repo_root).resolve(strict=True)
        require((root / "docker-compose.yml").is_file() and (root / ".env").is_file(), "部署目录缺少Compose或env")
        config = load_config(args.flag)
        request_id = config["requestID"]
        apply(root, config)
        write_status(root, request_id, "ENABLED" if config["enabled"] else "DISABLED")
        return 0
    except Exception as error:
        message = str(error)[:300]
        try:
            write_status(Path(args.repo_root), request_id, "FAILED", message)
        except Exception:
            pass
        print(f"PCAP采集控制失败: {message}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
