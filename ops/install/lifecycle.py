#!/usr/bin/env python3
"""Scoped WDSP removal and retained-data reinstall support (Python 3 stdlib)."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

PROJECT = "jiuzhang-wdsp"
LABEL = "com.docker.compose.project"
STATE = ".wdsp-retained.json"


class LifecycleError(RuntimeError):
    pass


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        # Compose/inspect output can include credentials; never echo captured output.
        raise LifecycleError("命令失败：" + " ".join(args[:3]) + "；请检查 Docker/systemd 状态")
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Lifecycle:
    def __init__(self, root, run=command, system_dir=Path("/etc/systemd/system"),
                 executor_config=Path("/etc/jiuzhang/upgrade-executor.conf"),
                 executor_binary=Path("/usr/local/libexec/jiuzhang-upgrade-executor")):
        path = Path(root)
        if not path.is_absolute() or path.absolute() != path.resolve():
            raise LifecycleError("安装根目录必须为绝对路径，且不得经过符号链接")
        if len(path.parts) < 3 or str(path) in ("/usr/local", "/var/lib", "/var/log", "/home/root"):
            raise LifecycleError("拒绝使用系统公共目录作为安装根目录")
        self.root, self.run = path, run
        self.system_dir = Path(system_dir)
        self.config, self.binary = Path(executor_config), Path(executor_binary)
        self.state_path = path / STATE

    def inside(self, path):
        resolved = Path(path).resolve()
        return Path(path).is_absolute() and self.root in resolved.parents

    def product(self, path):
        path = Path(path)
        if not self.inside(path) or path.parent.parent != self.root / "releases" or path.is_symlink():
            raise LifecycleError("旧版本目录不属于本安装根目录")
        manifest = json.loads((path / "manifest.json").read_text())
        if manifest.get("edition") != "wdsp" or manifest.get("arch") != "amd64":
            raise LifecycleError("旧版本不是 WDSP amd64 正式安装目录")
        for name in (".env", "docker-compose.yml"):
            file = path / name
            if not file.is_file() or file.is_symlink():
                raise LifecycleError("旧版本缺少独立配置文件：" + name)
        runtime = path / "runtime"
        if not runtime.is_dir() or not self.inside(runtime):
            raise LifecycleError("旧 runtime 缺失或指向安装根目录之外")
        env = dict(line.split("=", 1) for line in (path / ".env").read_text().splitlines()
                   if "=" in line and not line.lstrip().startswith("#"))
        for key in ("POSTGRES_PASSWORD", "VALKEY_PASSWORD", "JIUZHANG_MASTER_KEY"):
            if not env.get(key, "").strip().strip("\"'"):
                raise LifecycleError("旧配置缺少必要密钥；拒绝生成新密钥覆盖数据")
        return path

    def selected(self):
        if self.state_path.is_symlink():
            raise LifecycleError("保留状态不得为符号链接")
        if self.state_path.exists():
            state = json.loads(self.state_path.read_text())
            return self.product(state["product"])
        current = self.root / "current"
        if current.is_symlink():
            return self.product(current.resolve())
        products = [p.parent for p in self.root.glob("releases/*/jiuzhang-wdsp-offline-*-amd64/manifest.json")
                    if (p.parent / ".env").exists()]
        if len(products) != 1:
            raise LifecycleError("无法唯一识别旧系统；请检查安装根目录及 current 链接")
        return self.product(products[0])

    def ids(self, *args):
        return self.run(["docker", *args]).split()

    def inspect(self, kind, names):
        if not names:
            return []
        prefix = ["docker", "inspect"] if kind == "container" else ["docker", kind, "inspect"]
        return json.loads(self.run(prefix + list(names)))

    def inventory(self):
        ids = self.ids("ps", "-aq", "--filter", "label=" + LABEL + "=" + PROJECT)
        containers = self.inspect("container", ids)
        container_ids = {c["Id"] for c in containers}
        for c in containers:
            labels = c.get("Config", {}).get("Labels", {}) or {}
            directory = labels.get(LABEL + ".working_dir", "")
            if labels.get(LABEL) != PROJECT or not directory or not self.inside(directory):
                raise LifecycleError("同名 Compose 项目属于其他安装目录；拒绝操作")
        networks = self.inspect("network", self.ids("network", "ls", "-q", "--filter", "label=" + LABEL + "=" + PROJECT))
        for network in networks:
            if (network.get("Labels") or {}).get(LABEL) != PROJECT or not set(network.get("Containers") or {}) <= container_ids:
                raise LifecycleError("WDSP 网络存在其他容器，拒绝删除")
        volumes = self.inspect("volume", self.ids("volume", "ls", "-q", "--filter", "label=" + LABEL + "=" + PROJECT))
        for volume in volumes:
            name = volume["Name"]
            if (volume.get("Labels") or {}).get(LABEL) != PROJECT or not name.startswith(PROJECT + "_"):
                raise LifecycleError("数据卷归属校验失败")
            consumers = set(self.ids("ps", "-aq", "--no-trunc", "--filter", "volume=" + name))
            if not consumers <= container_ids:
                raise LifecycleError("WDSP 数据卷被其他容器引用，拒绝操作")
        return containers, networks, volumes

    def owned_units(self):
        units, auxiliary = [], []
        for name in ("jiuzhang-gateway.service", "jiuzhang-pcapd.service"):
            if (self.system_dir / name).exists():
                raise LifecycleError("检测到裸机网关服务，需先按裸机流程迁移或卸载")
        for name in ("jiuzhang-hostctl.path", "jiuzhang-hostctl.service"):
            path = self.system_dir / name
            if path.exists() or path.is_symlink():
                content = path.read_text()
                if path.is_symlink() or "jiuzhang-managed: hostctl-unit" not in content or str(self.root) + "/releases/" not in content:
                    raise LifecycleError("systemd 单元归属不明：" + name)
                units.append(path)
        upgrade_units = [self.system_dir / ("jiuzhang-upgrade-executor." + suffix) for suffix in ("path", "service")]
        runtime = None
        if self.config.is_symlink() or self.binary.is_symlink():
            raise LifecycleError("升级执行器配置或程序不得为符号链接")
        if self.config.exists():
            config = {}
            for line in self.config.read_text().splitlines():
                if line and not line.lstrip().startswith("#"):
                    words = shlex.split(line)
                    if len(words) != 1 or "=" not in words[0]:
                        raise LifecycleError("升级执行器配置格式不受支持")
                    key, value = words[0].split("=", 1)
                    config[key] = value
            if not config.get("COMPOSE_FILE") or not self.inside(config["COMPOSE_FILE"]):
                raise LifecycleError("升级执行器属于其他安装目录")
            if not config.get("ENV_FILE") or not self.inside(config["ENV_FILE"]):
                raise LifecycleError("升级执行器环境文件归属不明")
            runtime = Path(config["RUNTIME_DIR"])
            auxiliary.append(self.config)
            if self.binary.exists():
                auxiliary.append(self.binary)
        for path in upgrade_units:
            if path.exists() or path.is_symlink():
                content = path.read_text()
                if runtime is None or path.is_symlink() or "JiuZhang WDSP" not in content:
                    raise LifecycleError("升级 systemd 单元归属不明")
                units.append(path)
        for unit in units:
            if (self.system_dir / (unit.name + ".d")).exists():
                raise LifecycleError("存在自定义 systemd drop-in，需先人工处理：" + unit.name)
        return units, auxiliary, runtime

    @contextmanager
    def executor_lock(self, runtime, volumes):
        if runtime is None:
            yield
            return
        mounts = [Path(v["Mountpoint"]).resolve() for v in volumes if v["Name"] == PROJECT + "_runtime-data"]
        if runtime.resolve() not in mounts:
            raise LifecycleError("升级执行器共享目录不是 WDSP runtime 数据卷")
        lock = runtime / "upgrade-executor/executor.lock"
        if lock.is_symlink() or not lock.parent.is_dir():
            raise LifecycleError("升级锁目录异常")
        with lock.open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LifecycleError("升级正在执行，请完成后重试卸载") from exc
            yield

    def write_state(self, state):
        temp = self.root / (STATE + ".tmp")
        if temp.is_symlink():
            raise LifecycleError("保留状态临时文件异常")
        with os.fdopen(os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(temp), 0o600)
        os.replace(str(temp), str(self.state_path))

    def check_delete_tree(self):
        allowed = {"releases", "current", STATE, STATE + ".tmp"}
        if any(p.name not in allowed for p in self.root.iterdir()):
            raise LifecycleError("安装根目录含非受管文件；拒绝彻底删除，请先移出")
        releases = self.root / "releases"
        if releases.is_symlink() or not releases.is_dir():
            raise LifecycleError("版本目录异常")
        for release in releases.iterdir():
            if release.is_symlink() or not release.is_dir():
                raise LifecycleError("版本目录中含非受管条目")
            products = list(release.glob("jiuzhang-wdsp-offline-*-amd64"))
            if len(products) != 1 or not products[0].is_dir() or products[0].is_symlink():
                raise LifecycleError("不能识别的版本目录，拒绝彻底删除")
            manifest = json.loads((products[0] / "manifest.json").read_text())
            if manifest.get("edition") != "wdsp":
                raise LifecycleError("版本目录产品归属不明")
            expected = {products[0].name + suffix for suffix in ("", ".tar.gz", ".tar.gz.sha256", ".tar.gz.sig")}
            if any(p.name not in expected for p in release.iterdir()):
                raise LifecycleError("版本目录含非受管条目，拒绝彻底删除")
        for directory, dirs, _ in os.walk(str(self.root), followlinks=False):
            for name in dirs:
                p = Path(directory) / name
                if os.path.ismount(str(p)):
                    raise LifecycleError("安装目录下存在挂载点，拒绝递归删除")

    def uninstall(self, purge=False, confirmed=False):
        if purge and not confirmed:
            raise LifecycleError("彻底删除需要 --confirm-delete-data 明确确认")
        product = self.selected()
        containers, networks, volumes = self.inventory()
        units, auxiliary, runtime = self.owned_units()
        if purge:
            self.check_delete_tree()
        required = {PROJECT + "_postgres-data", PROJECT + "_runtime-data"}
        if not purge and not required <= {v["Name"] for v in volumes}:
            raise LifecycleError("核心数据卷不完整；不能承诺保留数据复装，请检查或选择彻底删除")
        state = {"schema": 1, "phase": "removing", "product": str(product),
                 "env_sha256": digest(product / ".env"),
                 "volumes": {v["Name"]: v["CreatedAt"] for v in volumes}}
        with self.executor_lock(runtime, volumes):
            self.write_state(state)
            # Disable path watchers before stopping their workers.
            for unit in sorted(units, key=lambda p: (not p.name.endswith(".path"), p.name)):
                self.run(["systemctl", "disable", "--now", unit.name])
            containers.sort(key=lambda c: c.get("Config", {}).get("Labels", {}).get(LABEL + ".service") != "netmgrd")
            ids = [c["Id"] for c in containers]
            if ids:
                self.run(["docker", "stop", "--time", "60", *ids])
                self.run(["docker", "rm", *ids])
            for network in networks:
                self.run(["docker", "network", "rm", network["Id"]])
            for path in units + auxiliary:
                path.unlink()
            if units:
                self.run(["systemctl", "daemon-reload"])
            if purge:
                # Docker refuses to delete any volume that acquired another consumer.
                for volume in volumes:
                    self.run(["docker", "volume", "rm", volume["Name"]])
                shutil.rmtree(str(self.root))
            else:
                state["phase"] = "retained"
                self.write_state(state)
        print("WDSP 已彻底删除（外置证据目录、共享 Docker、镜像缓存和宿主机调优保留）" if purge else
              "WDSP 已卸载；数据卷、账号、密钥、证书和旧版本恢复文件已保留，可重新运行安装包复装")

    def retained(self):
        if self.state_path.is_symlink():
            raise LifecycleError("保留状态不得为符号链接")
        state = json.loads(self.state_path.read_text())
        if state.get("schema") != 1 or state.get("phase") != "retained":
            raise LifecycleError("上次卸载未完成；请重新执行卸载，不可直接复装")
        product = self.product(state["product"])
        if digest(product / ".env") != state["env_sha256"]:
            raise LifecycleError("保留配置发生变化，拒绝复装以避免密钥不一致")
        containers, _, volumes = self.inventory()
        if containers:
            raise LifecycleError("WDSP 容器仍存在，请先执行卸载")
        actual = {v["Name"]: v["CreatedAt"] for v in volumes}
        if actual != state["volumes"]:
            raise LifecycleError("保留的数据卷缺失或已被重建，拒绝复装")
        return product

    def preflight(self):
        if self.state_path.exists():
            self.retained()
            print("retained")
        elif self.root.exists() and any(self.root.iterdir()):
            raise LifecycleError("安装目录已存在；请先 --uninstall（默认保留数据），升级请使用升级通道")
        else:
            # Fresh hosts may not have Docker until prepare installs the bundled RPMs.
            print("fresh")

    def check_empty(self):
        containers, networks, volumes = self.inventory()
        units, auxiliary, _ = self.owned_units()
        if containers or networks or volumes or units or auxiliary:
            raise LifecycleError("已存在 WDSP 项目资源，请先用原安装根目录卸载")

    def restore(self, destination):
        old = self.retained()
        new = Path(destination)
        if not self.inside(new) or new.parent.parent != self.root / "releases":
            raise LifecycleError("复装目标不属于安装目录")
        if (new / ".env").exists() or (new / "runtime").exists() or (new / "runtime").is_symlink():
            raise LifecycleError("复装目标已有配置或数据，拒绝覆盖")
        shutil.copy2(str(old / ".env"), str(new / ".env"))
        os.chmod(str(new / ".env"), 0o600)
        (new / "runtime").symlink_to((old / "runtime").resolve(), target_is_directory=True)
        print("已复用保留配置和 runtime；原账号与加密密钥不变")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "check-empty", "uninstall", "restore", "complete"))
    parser.add_argument("--install-root", required=True)
    parser.add_argument("--destination")
    parser.add_argument("--purge-data", action="store_true")
    parser.add_argument("--confirm-delete-data", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("请以 root 运行")
    try:
        lifecycle = Lifecycle(args.install_root)
        if args.action == "uninstall":
            lifecycle.uninstall(args.purge_data, args.confirm_delete_data)
        elif args.action == "preflight":
            lifecycle.preflight()
        elif args.action == "check-empty":
            lifecycle.check_empty()
        elif args.action == "restore":
            if not args.destination:
                raise LifecycleError("缺少复装目标目录")
            lifecycle.restore(args.destination)
        else:
            lifecycle.state_path.unlink(missing_ok=True)
    except (LifecycleError, OSError, ValueError, KeyError) as exc:
        # JSON decoder errors and filesystem errors do not include file contents.
        print("[WDSP lifecycle] ERROR: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
