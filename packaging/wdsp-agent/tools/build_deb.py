#!/usr/bin/env python3
"""
纯标准库构建符合 Debian dpkg 2.0 规范的 wdsp-agent .deb 包（零外部依赖）。
生成的 .deb 包含标准 ar 归档：
  - debian-binary (2.0)
  - control.tar.gz (control, md5sums, postinst, prerm, postrm)
  - data.tar.gz (/usr/local/bin/wdsp-agent, /lib/systemd/system/wdsp-agent.service,
                 /etc/wdsp-agent/, /var/lib/wdsp-agent/)
"""

import argparse
import gzip
import hashlib
import io
import os
import stat
import tarfile
import time


SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=JiuZhang WDSP Distributed Traffic Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wdsp-agent run --config /etc/wdsp-agent/agent.json --state-dir /var/lib/wdsp-agent
Restart=always
RestartSec=5
TimeoutStopSec=15
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

POSTINST_SCRIPT = """#!/bin/sh
set -e
install -d -m 0700 /etc/wdsp-agent /var/lib/wdsp-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ -s /etc/wdsp-agent/agent.json ] && systemctl is-active --quiet wdsp-agent; then
        systemctl restart wdsp-agent >/dev/null 2>&1 || true
    fi
fi
exit 0
"""

PRERM_SCRIPT = """#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop wdsp-agent >/dev/null 2>&1 || true
        systemctl disable wdsp-agent >/dev/null 2>&1 || true
    fi
fi
exit 0
"""

POSTRM_SCRIPT = """#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = "purge" ]; then
    rm -rf /etc/wdsp-agent /var/lib/wdsp-agent
fi
exit 0
"""


def make_tar_gz(entries, mtime):
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for item in entries:
            ti = tarfile.TarInfo(name=item["name"])
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            ti.mtime = mtime
            ti.mode = item["mode"]
            if item.get("dir"):
                ti.type = tarfile.DIRTYPE
                ti.size = 0
                tf.addfile(ti)
            else:
                data = item["data"]
                ti.type = tarfile.REGTYPE
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=mtime) as gz:
        gz.write(raw_tar.getvalue())
    return out.getvalue()


def ar_member(name: str, data: bytes, mtime: int) -> bytes:
    header = (
        f"{name:<16}"
        f"{mtime:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{'100644':<8}"
        f"{len(data):<10}"
        "`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise RuntimeError(f"invalid ar header length: {len(header)}")
    pad = b"\n" if (len(data) % 2 == 1) else b""
    return header + data + pad


def build_deb(binary_path: str, version: str, arch: str, output_path: str):
    if arch not in ("amd64", "arm64"):
        raise ValueError(f"unsupported deb arch: {arch}")
    with open(binary_path, "rb") as f:
        bin_data = f.read()
    unit_data = SYSTEMD_UNIT_TEMPLATE.encode("utf-8")
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", int(time.time())))

    data_entries = [
        {"name": "./", "dir": True, "mode": 0o755},
        {"name": "./usr/", "dir": True, "mode": 0o755},
        {"name": "./usr/local/", "dir": True, "mode": 0o755},
        {"name": "./usr/local/bin/", "dir": True, "mode": 0o755},
        {"name": "./usr/local/bin/wdsp-agent", "data": bin_data, "mode": 0o755},
        {"name": "./lib/", "dir": True, "mode": 0o755},
        {"name": "./lib/systemd/", "dir": True, "mode": 0o755},
        {"name": "./lib/systemd/system/", "dir": True, "mode": 0o755},
        {"name": "./lib/systemd/system/wdsp-agent.service", "data": unit_data, "mode": 0o644},
        {"name": "./etc/", "dir": True, "mode": 0o755},
        {"name": "./etc/wdsp-agent/", "dir": True, "mode": 0o700},
        {"name": "./var/", "dir": True, "mode": 0o755},
        {"name": "./var/lib/", "dir": True, "mode": 0o755},
        {"name": "./var/lib/wdsp-agent/", "dir": True, "mode": 0o700},
    ]
    data_tar_gz = make_tar_gz(data_entries, mtime)

    installed_kb = max(1, (len(bin_data) + len(unit_data) + 1023) // 1024)
    control_text = (
        f"Package: wdsp-agent\n"
        f"Version: {version}\n"
        f"Section: net\n"
        f"Priority: optional\n"
        f"Architecture: {arch}\n"
        f"Installed-Size: {installed_kb}\n"
        f"Maintainer: JiuZhang WDSP Team <ops@jiuzhang.local>\n"
        f"Description: JiuZhang WDSP Distributed Traffic Agent\n"
        f" Passive read-only traffic and API observation edge sensor for JiuZhang WDSP.\n"
    ).encode("utf-8")

    md5sums_text = (
        f"{hashlib.md5(bin_data).hexdigest()}  usr/local/bin/wdsp-agent\n"
        f"{hashlib.md5(unit_data).hexdigest()}  lib/systemd/system/wdsp-agent.service\n"
    ).encode("utf-8")

    control_entries = [
        {"name": "./", "dir": True, "mode": 0o755},
        {"name": "./control", "data": control_text, "mode": 0o644},
        {"name": "./md5sums", "data": md5sums_text, "mode": 0o644},
        {"name": "./postinst", "data": POSTINST_SCRIPT.encode("utf-8"), "mode": 0o755},
        {"name": "./prerm", "data": PRERM_SCRIPT.encode("utf-8"), "mode": 0o755},
        {"name": "./postrm", "data": POSTRM_SCRIPT.encode("utf-8"), "mode": 0o755},
    ]
    control_tar_gz = make_tar_gz(control_entries, mtime)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as out:
        out.write(b"!<arch>\n")
        out.write(ar_member("debian-binary", b"2.0\n", mtime))
        out.write(ar_member("control.tar.gz", control_tar_gz, mtime))
        out.write(ar_member("data.tar.gz", data_tar_gz, mtime))
    os.chmod(output_path, 0o644)


def main():
    p = argparse.ArgumentParser(description="Build Debian .deb package for wdsp-agent")
    p.add_argument("--binary", required=True, help="Path to linux wdsp-agent ELF binary")
    p.add_argument("--version", required=True, help="SemVer version (e.g. 2.4.0)")
    p.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    p.add_argument("--output", required=True, help="Output .deb file path")
    args = p.parse_args()
    build_deb(args.binary, args.version, args.arch, args.output)


if __name__ == "__main__":
    main()
