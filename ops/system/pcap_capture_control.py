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
        require(any(value.startswith(prefix) and len(value) > len(prefix) for prefix in allowed_roots()), "存储路径不在受控数据盘目录")
        data[key] = str(path)
    hot, warm = Path(data["hot_dir"]), Path(data["warm_dir"])
    require(hot != warm and hot not in warm.parents and warm not in hot.parents, "冷热目录不能相同或嵌套")
    return data


def allowed_roots():
    if TEST_MODE and os.environ.get("PCAP_TEST_ALLOWED_ROOT"):
        return (os.environ["PCAP_TEST_ALLOWED_ROOT"].rstrip("/") + "/",)
    return ("/srv/", "/var/lib/", "/data/", "/mnt/", "/media/")


def atomic_write(path, content, mode=0o600, group=1000):
    path = Path(path)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temp, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        if os.geteuid() == 0:
            os.chown(temp, 0, group)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def prepare_directories(root, config):
    for key in ("hot_dir", "warm_dir"):
        path = Path(config[key])
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = path.resolve(strict=True)
        require(any(str(resolved).startswith(prefix) for prefix in allowed_roots()), "存储目录解析后越出允许范围")
        if os.geteuid() == 0:
            os.chown(resolved, 1000, 1000)
        os.chmod(resolved, 0o700)
    for name, mode in (("pcap-private", 0o700), ("pcap-public", 0o755)):
        directory = root / "runtime" / name
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
        if os.geteuid() == 0:
            os.chown(directory, 1000, 1000)
        os.chmod(directory, mode)


def environment(config):
    enabled = "true" if config["enabled"] else "false"
    return "\n".join((
        "COMPOSE_PROFILES=request-pcap",
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


def recreate_api(root):
    compose(root, "up", "-d", "--no-deps", "--force-recreate", "api")
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
    atomic_write(control, environment(config))
    with open(root / ".env", encoding="utf-8") as stream:
        original = stream.read()
    atomic_write(merged, original.rstrip("\n") + "\n\n# system-admin PCAP control\n" + environment(config))
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
    atomic_write(root / "runtime/hostctl/pcap-status.json", json.dumps({
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
