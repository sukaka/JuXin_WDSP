#!/usr/bin/env python3
"""
纯标准库构建符合 RPM v4 规范的 wdsp-agent .rpm 包（零外部依赖，兼容 CentOS 7/8/9、
Rocky、AlmaLinux、RHEL、openEuler、Anolis 与 Alibaba Cloud Linux）。

结构：
  1. RPM Lead (96 bytes)
  2. Signature Header (SHA256HEADER, SHA1HEADER, SIZE, PAYLOADSIZE, MD5, HEADERSIGNATURES)
  3. Main Header (Header Immutable Region + 完整标准元数据 + 文件表 + SHA256 文件摘要 + postin/preun/postun 脚本)
  4. Gzip 压缩的 NewC (070701) CPIO Payload
"""

import argparse
import gzip
import hashlib
import io
import os
import struct
import time


# RPM Header data types
RPM_CHAR_TYPE = 1
RPM_INT8_TYPE = 2
RPM_INT16_TYPE = 3
RPM_INT32_TYPE = 4
RPM_INT64_TYPE = 5
RPM_STRING_TYPE = 6
RPM_BIN_TYPE = 7
RPM_STRING_ARRAY_TYPE = 8
RPM_I18NSTRING_TYPE = 9

# Signature tags
RPMSIGTAG_HEADERSIGNATURES = 62
RPMSIGTAG_SHA1 = 269
RPMSIGTAG_SHA256 = 273
RPMSIGTAG_SIZE = 1000
RPMSIGTAG_MD5 = 1004
RPMSIGTAG_PAYLOADSIZE = 1007

# Main header tags
RPMTAG_HEADERIMMUTABLE = 63
RPMTAG_HEADERI18NTABLE = 100
RPMTAG_NAME = 1000
RPMTAG_VERSION = 1001
RPMTAG_RELEASE = 1002
RPMTAG_SUMMARY = 1004
RPMTAG_DESCRIPTION = 1005
RPMTAG_BUILDTIME = 1006
RPMTAG_BUILDHOST = 1007
RPMTAG_SIZE = 1009
RPMTAG_VENDOR = 1011
RPMTAG_LICENSE = 1014
RPMTAG_GROUP = 1016
RPMTAG_OS = 1021
RPMTAG_ARCH = 1022
RPMTAG_PREIN = 1023
RPMTAG_POSTIN = 1024
RPMTAG_PREUN = 1025
RPMTAG_POSTUN = 1026
RPMTAG_FILESIZES = 1028
RPMTAG_FILEMODES = 1030
RPMTAG_FILERDEVS = 1033
RPMTAG_FILEMTIMES = 1034
RPMTAG_FILEDIGESTS = 1035
RPMTAG_FILELINKTOS = 1036
RPMTAG_FILEFLAGS = 1037
RPMTAG_FILEUSERNAME = 1039
RPMTAG_FILEGROUPNAME = 1040
RPMTAG_PROVIDENAME = 1047
RPMTAG_REQUIREFLAGS = 1048
RPMTAG_REQUIRENAME = 1049
RPMTAG_REQUIREVERSION = 1050
RPMTAG_RPMVERSION = 1064
RPMTAG_POSTINPROG = 1086
RPMTAG_PREUNPROG = 1087
RPMTAG_POSTUNPROG = 1088
RPMTAG_FILEINODES = 1096
RPMTAG_FILELANGS = 1097
RPMTAG_PROVIDEFLAGS = 1112
RPMTAG_PROVIDEVERSION = 1113
RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_PAYLOADFORMAT = 1124
RPMTAG_PAYLOADCOMPRESSOR = 1125
RPMTAG_PAYLOADFLAGS = 1126
RPMTAG_FILEDIGESTALGO = 5011

RPMSENSE_EQUAL = 0x08
RPMSENSE_RPMLIB = 0x1000000
RPMSENSE_LESS = 0x02
PGPHASHALGO_SHA256 = 8

RPM_ARCH_LEAD = {
    "x86_64": 1,
    "aarch64": 19,
}

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

POSTIN_SCRIPT = """install -d -m 0700 /etc/wdsp-agent /var/lib/wdsp-agent
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [ "$1" -ge 2 ] && [ -s /etc/wdsp-agent/agent.json ] && systemctl is-active --quiet wdsp-agent; then
        systemctl restart wdsp-agent >/dev/null 2>&1 || true
    fi
fi
"""

PREUN_SCRIPT = """if [ "$1" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl stop wdsp-agent >/dev/null 2>&1 || true
        systemctl disable wdsp-agent >/dev/null 2>&1 || true
    fi
fi
"""

POSTUN_SCRIPT = """if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
"""


def align_up(buf: bytearray, alignment: int):
    rem = len(buf) % alignment
    if rem:
        buf.extend(b"\x00" * (alignment - rem))


def encode_header(entries, region_tag=None) -> bytes:
    """
    编码 RPM Header（可选带 Immutable Region Tag 62/63）。
    entries: list of (tag, dtype, value)
    """
    sorted_entries = sorted(entries, key=lambda x: x[0])
    index_records = []
    store = bytearray()

    for tag, dtype, val in sorted_entries:
        if dtype == RPM_INT16_TYPE:
            align_up(store, 2)
            offset = len(store)
            items = val if isinstance(val, (list, tuple)) else [val]
            for v in items:
                store.extend(struct.pack(">H", v))
            count = len(items)
        elif dtype == RPM_INT32_TYPE:
            align_up(store, 4)
            offset = len(store)
            items = val if isinstance(val, (list, tuple)) else [val]
            for v in items:
                store.extend(struct.pack(">I", v))
            count = len(items)
        elif dtype == RPM_INT64_TYPE:
            align_up(store, 8)
            offset = len(store)
            items = val if isinstance(val, (list, tuple)) else [val]
            for v in items:
                store.extend(struct.pack(">Q", v))
            count = len(items)
        elif dtype == RPM_STRING_TYPE:
            offset = len(store)
            store.extend(val.encode("utf-8") + b"\x00")
            count = 1
        elif dtype in (RPM_STRING_ARRAY_TYPE, RPM_I18NSTRING_TYPE):
            offset = len(store)
            items = val if isinstance(val, (list, tuple)) else [val]
            for s in items:
                store.extend(s.encode("utf-8") + b"\x00")
            count = len(items)
        elif dtype == RPM_BIN_TYPE:
            offset = len(store)
            store.extend(val)
            count = len(val)
        else:
            raise ValueError(f"unsupported RPM tag type: {dtype}")
        index_records.append((tag, dtype, offset, count))

    if region_tag is not None:
        # Region trailer 位于 store 尾部，16 字节，内容为指向自身区域的负偏移 index 记录
        region_offset = len(store)
        num_entries = len(index_records) + 1
        trailer_neg_offset = -(num_entries * 16)
        trailer = struct.pack(">IIiI", region_tag, RPM_BIN_TYPE, trailer_neg_offset, 16)
        store.extend(trailer)
        # Region tag 必须排在 index 最前（标签 62/63）
        index_records.insert(0, (region_tag, RPM_BIN_TYPE, region_offset, 16))

    header = bytearray()
    header.extend(b"\x8e\xad\xe8\x01\x00\x00\x00\x00")
    header.extend(struct.pack(">II", len(index_records), len(store)))
    for tag, dtype, offset, count in index_records:
        header.extend(struct.pack(">IIII", tag, dtype, offset, count))
    header.extend(store)
    return bytes(header)


def build_cpio_newc(files, mtime: int) -> bytes:
    """
    构造 NewC (070701) CPIO 归档。
    files: list of dict {path, mode, data, is_dir, ino}
    """
    out = bytearray()
    for f in files:
        # RPM cpio 内部路径以 "./" 开头（如 "./usr/local/bin/wdsp-agent"）
        cpio_name = ("." + f["path"]).encode("utf-8") + b"\x00"
        data = b"" if f["is_dir"] else f["data"]
        nlink = 2 if f["is_dir"] else 1
        hdr = (
            "070701"
            f"{f['ino']:08x}"
            f"{f['mode']:08x}"
            f"{0:08x}"  # uid
            f"{0:08x}"  # gid
            f"{nlink:08x}"
            f"{mtime:08x}"
            f"{len(data):08x}"
            f"{0:08x}"  # devmajor
            f"{0:08x}"  # devminor
            f"{0:08x}"  # rdevmajor
            f"{0:08x}"  # rdevminor
            f"{len(cpio_name):08x}"
            f"{0:08x}"  # check
        ).encode("ascii")
        out.extend(hdr)
        out.extend(cpio_name)
        align_up(out, 4)
        out.extend(data)
        align_up(out, 4)

    trailer_name = b"TRAILER!!!\x00"
    trailer_hdr = (
        "070701"
        f"{0:08x}{0:08x}{0:08x}{0:08x}{1:08x}{0:08x}{0:08x}"
        f"{0:08x}{0:08x}{0:08x}{0:08x}{len(trailer_name):08x}{0:08x}"
    ).encode("ascii")
    out.extend(trailer_hdr)
    out.extend(trailer_name)
    align_up(out, 4)
    return bytes(out)


def build_rpm(binary_path: str, version: str, release: str, arch: str, output_path: str):
    if arch not in RPM_ARCH_LEAD:
        raise ValueError(f"unsupported rpm arch: {arch}")
    with open(binary_path, "rb") as f:
        bin_data = f.read()
    unit_data = SYSTEMD_UNIT_TEMPLATE.encode("utf-8")
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", int(time.time())))

    # 仅打包本包专属目录和文件，绝不声称拥有 /usr、/etc、/var 等系统公用目录，防止 RPM 冲突
    files = [
        {
            "path": "/etc/wdsp-agent",
            "dir": "/etc/",
            "base": "wdsp-agent",
            "mode": 0o040700,
            "data": b"",
            "is_dir": True,
            "ino": 1,
        },
        {
            "path": "/usr/lib/systemd/system/wdsp-agent.service",
            "dir": "/usr/lib/systemd/system/",
            "base": "wdsp-agent.service",
            "mode": 0o100644,
            "data": unit_data,
            "is_dir": False,
            "ino": 2,
        },
        {
            "path": "/usr/local/bin/wdsp-agent",
            "dir": "/usr/local/bin/",
            "base": "wdsp-agent",
            "mode": 0o100755,
            "data": bin_data,
            "is_dir": False,
            "ino": 3,
        },
        {
            "path": "/var/lib/wdsp-agent",
            "dir": "/var/lib/",
            "base": "wdsp-agent",
            "mode": 0o040700,
            "data": b"",
            "is_dir": True,
            "ino": 4,
        },
    ]

    # 构建唯一 dirnames + dirindexes
    dirnames = []
    dir_map = {}
    dirindexes = []
    basenames = []
    filesizes = []
    filemodes = []
    filerdevs = []
    filemtimes = []
    filedigests = []
    filelinktos = []
    fileflags = []
    fileusers = []
    filegroups = []
    fileinodes = []
    filelangs = []
    total_size = 0

    for item in files:
        d = item["dir"]
        if d not in dir_map:
            dir_map[d] = len(dirnames)
            dirnames.append(d)
        dirindexes.append(dir_map[d])
        basenames.append(item["base"])
        size = 0 if item["is_dir"] else len(item["data"])
        total_size += size
        filesizes.append(size)
        filemodes.append(item["mode"])
        filerdevs.append(0)
        filemtimes.append(mtime)
        filedigests.append("" if item["is_dir"] else hashlib.sha256(item["data"]).hexdigest())
        filelinktos.append("")
        fileflags.append(0)
        fileusers.append("root")
        filegroups.append("root")
        fileinodes.append(item["ino"])
        filelangs.append("")

    cpio_raw = build_cpio_newc(files, mtime)
    payload_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=payload_buf, mtime=mtime) as gz:
        gz.write(cpio_raw)
    payload_gz = payload_buf.getvalue()

    name = "wdsp-agent"
    nevra_evr = f"{version}-{release}"
    main_entries = [
        (RPMTAG_HEADERI18NTABLE, RPM_STRING_ARRAY_TYPE, ["C"]),
        (RPMTAG_NAME, RPM_STRING_TYPE, name),
        (RPMTAG_VERSION, RPM_STRING_TYPE, version),
        (RPMTAG_RELEASE, RPM_STRING_TYPE, release),
        (RPMTAG_SUMMARY, RPM_I18NSTRING_TYPE, ["JiuZhang WDSP Distributed Traffic Agent"]),
        (RPMTAG_DESCRIPTION, RPM_I18NSTRING_TYPE, ["Passive read-only traffic and API observation edge sensor for JiuZhang WDSP."]),
        (RPMTAG_BUILDTIME, RPM_INT32_TYPE, mtime),
        (RPMTAG_BUILDHOST, RPM_STRING_TYPE, "jiuzhang-build"),
        (RPMTAG_SIZE, RPM_INT32_TYPE, total_size),
        (RPMTAG_VENDOR, RPM_STRING_TYPE, "JiuZhang WDSP"),
        (RPMTAG_LICENSE, RPM_STRING_TYPE, "Proprietary"),
        (RPMTAG_GROUP, RPM_I18NSTRING_TYPE, ["Applications/System"]),
        (RPMTAG_OS, RPM_STRING_TYPE, "linux"),
        (RPMTAG_ARCH, RPM_STRING_TYPE, arch),
        (RPMTAG_POSTIN, RPM_STRING_TYPE, POSTIN_SCRIPT),
        (RPMTAG_PREUN, RPM_STRING_TYPE, PREUN_SCRIPT),
        (RPMTAG_POSTUN, RPM_STRING_TYPE, POSTUN_SCRIPT),
        (RPMTAG_POSTINPROG, RPM_STRING_TYPE, "/bin/sh"),
        (RPMTAG_PREUNPROG, RPM_STRING_TYPE, "/bin/sh"),
        (RPMTAG_POSTUNPROG, RPM_STRING_TYPE, "/bin/sh"),
        (RPMTAG_FILESIZES, RPM_INT32_TYPE, filesizes),
        (RPMTAG_FILEMODES, RPM_INT16_TYPE, filemodes),
        (RPMTAG_FILERDEVS, RPM_INT16_TYPE, filerdevs),
        (RPMTAG_FILEMTIMES, RPM_INT32_TYPE, filemtimes),
        (RPMTAG_FILEDIGESTS, RPM_STRING_ARRAY_TYPE, filedigests),
        (RPMTAG_FILELINKTOS, RPM_STRING_ARRAY_TYPE, filelinktos),
        (RPMTAG_FILEFLAGS, RPM_INT32_TYPE, fileflags),
        (RPMTAG_FILEUSERNAME, RPM_STRING_ARRAY_TYPE, fileusers),
        (RPMTAG_FILEGROUPNAME, RPM_STRING_ARRAY_TYPE, filegroups),
        (RPMTAG_FILEINODES, RPM_INT32_TYPE, fileinodes),
        (RPMTAG_FILELANGS, RPM_STRING_ARRAY_TYPE, filelangs),
        (RPMTAG_DIRINDEXES, RPM_INT32_TYPE, dirindexes),
        (RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE, basenames),
        (RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, dirnames),
        (RPMTAG_PROVIDENAME, RPM_STRING_ARRAY_TYPE, [name, f"{name}({arch})"]),
        (RPMTAG_PROVIDEFLAGS, RPM_INT32_TYPE, [RPMSENSE_EQUAL, RPMSENSE_EQUAL]),
        (RPMTAG_PROVIDEVERSION, RPM_STRING_ARRAY_TYPE, [nevra_evr, nevra_evr]),
        (RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, [
            "/bin/sh",
            "rpmlib(CompressedFileNames)",
            "rpmlib(FileDigests)",
            "rpmlib(PayloadFilesHavePrefix)",
        ]),
        (RPMTAG_REQUIREFLAGS, RPM_INT32_TYPE, [
            0,
            RPMSENSE_RPMLIB | RPMSENSE_LESS | RPMSENSE_EQUAL,
            RPMSENSE_RPMLIB | RPMSENSE_LESS | RPMSENSE_EQUAL,
            RPMSENSE_RPMLIB | RPMSENSE_LESS | RPMSENSE_EQUAL,
        ]),
        (RPMTAG_REQUIREVERSION, RPM_STRING_ARRAY_TYPE, [
            "",
            "3.0.4-1",
            "4.6.0-1",
            "4.0-1",
        ]),
        (RPMTAG_RPMVERSION, RPM_STRING_TYPE, "4.18.0"),
        (RPMTAG_PAYLOADFORMAT, RPM_STRING_TYPE, "cpio"),
        (RPMTAG_PAYLOADCOMPRESSOR, RPM_STRING_TYPE, "gzip"),
        (RPMTAG_PAYLOADFLAGS, RPM_STRING_TYPE, "9"),
        (RPMTAG_FILEDIGESTALGO, RPM_INT32_TYPE, PGPHASHALGO_SHA256),
    ]
    main_header = encode_header(main_entries, region_tag=RPMTAG_HEADERIMMUTABLE)

    header_and_payload = main_header + payload_gz
    sig_entries = [
        (RPMSIGTAG_SHA1, RPM_STRING_TYPE, hashlib.sha1(main_header).hexdigest()),
        (RPMSIGTAG_SHA256, RPM_STRING_TYPE, hashlib.sha256(main_header).hexdigest()),
        (RPMSIGTAG_SIZE, RPM_INT32_TYPE, len(header_and_payload)),
        (RPMSIGTAG_MD5, RPM_BIN_TYPE, hashlib.md5(header_and_payload).digest()),
        (RPMSIGTAG_PAYLOADSIZE, RPM_INT32_TYPE, len(cpio_raw)),
    ]
    sig_header = bytearray(encode_header(sig_entries, region_tag=RPMSIGTAG_HEADERSIGNATURES))
    align_up(sig_header, 8)

    # Lead (96 bytes): magic(4) + major(1)=3 + minor(1)=0 + type(2)=0(bin) + archnum(2) +
    #                  name(66) + osnum(2)=1(linux) + sigtype(2)=5 + reserved(16)
    lead_name = f"{name}-{version}-{release}".encode("ascii")[:65].ljust(66, b"\x00")
    lead = struct.pack(
        ">4sBBHH66sHH16s",
        b"\xed\xab\xee\xdb",
        3,
        0,
        0,
        RPM_ARCH_LEAD[arch],
        lead_name,
        1,
        5,
        b"\x00" * 16,
    )
    if len(lead) != 96:
        raise RuntimeError(f"invalid RPM lead size: {len(lead)}")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as out:
        out.write(lead)
        out.write(sig_header)
        out.write(main_header)
        out.write(payload_gz)
    os.chmod(output_path, 0o644)


def main():
    p = argparse.ArgumentParser(description="Build RPM v4 package for wdsp-agent")
    p.add_argument("--binary", required=True, help="Path to linux wdsp-agent ELF binary")
    p.add_argument("--version", required=True, help="SemVer version (e.g. 2.4.0)")
    p.add_argument("--release", default="1", help="RPM release number (default 1)")
    p.add_argument("--arch", required=True, choices=["x86_64", "aarch64"])
    p.add_argument("--output", required=True, help="Output .rpm file path")
    args = p.parse_args()
    build_rpm(args.binary, args.version, args.release, args.arch, args.output)


if __name__ == "__main__":
    main()
