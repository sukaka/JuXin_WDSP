#!/usr/bin/env python3
"""Render the first 30 and final 30 pages of source, with 50 lines per page."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from fontTools.ttLib import TTFont as FontToolsFont
from fontTools.varLib.instancer import instantiateVariableFont
from pypdf import PdfReader
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist"
PDF_PATH = OUTPUT / "九章API安全系统.pdf"
HTML_PATH = OUTPUT / "九章API安全系统.html"
MANIFEST_PATH = OUTPUT / "九章API安全系统-源码清单.json"
FONT_PATH = ROOT.parent / "server/assets/fonts/NotoSansCJKsc-VF.ttf"
PAGE_COUNT = 60
LINES_PER_PAGE = 50
LINES_PER_SIDE = PAGE_COUNT // 2 * LINES_PER_PAGE
SOURCE_FILES = (
    "src/main/java/com/jiuzhang/apisecurity/Main.java",
    "src/main/java/com/jiuzhang/apisecurity/Models.java",
    "src/main/java/com/jiuzhang/apisecurity/GatewayConfig.java",
    "src/main/java/com/jiuzhang/apisecurity/ApiClassifier.java",
    "src/main/java/com/jiuzhang/apisecurity/PathNormalizer.java",
    "src/main/java/com/jiuzhang/apisecurity/Json.java",
    "src/main/java/com/jiuzhang/apisecurity/PayloadParser.java",
    "src/main/java/com/jiuzhang/apisecurity/Fingerprints.java",
    "src/main/java/com/jiuzhang/apisecurity/IdentityExtractor.java",
    "src/main/java/com/jiuzhang/apisecurity/SchemaRegistry.java",
    "src/main/java/com/jiuzhang/apisecurity/SensitiveDataDetector.java",
    "src/main/java/com/jiuzhang/apisecurity/AuthorizationPolicy.java",
    "src/main/java/com/jiuzhang/apisecurity/BehaviorTracker.java",
    "src/main/java/com/jiuzhang/apisecurity/DecisionEngine.java",
    "src/main/java/com/jiuzhang/apisecurity/ResponseGuard.java",
    "src/main/java/com/jiuzhang/apisecurity/EventStore.java",
    "src/main/java/com/jiuzhang/apisecurity/ApiGateway.java",
    "src/main/java/com/jiuzhang/apisecurity/AdminServer.java",
    "src/test/java/com/jiuzhang/apisecurity/JsonTests.java",
    "src/test/java/com/jiuzhang/apisecurity/CoreTests.java",
    "src/test/java/com/jiuzhang/apisecurity/SchemaTests.java",
    "src/test/java/com/jiuzhang/apisecurity/SecurityTests.java",
    "src/test/java/com/jiuzhang/apisecurity/GatewayIntegrationTest.java",
    "src/test/java/com/jiuzhang/apisecurity/TestSupport.java",
    "src/test/java/com/jiuzhang/apisecurity/TestMain.java",
    "scripts/build.sh",
    "scripts/test.sh",
    "scripts/run.sh",
    "config.example.properties",
    "schemas.example.json",
    "authz.example.json",
    "packaging/jiuzhang-api-security.service",
)


@dataclass(frozen=True)
class SourceLine:
    path: str
    number: int
    text: str


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str
    sha256: str
    line_count: int


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_sources() -> tuple[list[SourceFile], list[SourceLine], str]:
    files: list[SourceFile] = []
    lines: list[SourceLine] = []
    aggregate = hashlib.sha256()
    for relative in SOURCE_FILES:
        raw = (ROOT / relative).read_bytes()
        text = raw.decode("utf-8")
        if "\r" in text:
            raise ValueError(f"{relative}: expected LF line endings")
        source_lines = text.splitlines()
        files.append(SourceFile(relative, text, digest(raw), len(source_lines)))
        aggregate.update(relative.encode("utf-8") + b"\0" + raw + b"\0")
        lines.extend(
            SourceLine(relative, number, line.expandtabs(4))
            for number, line in enumerate(source_lines, start=1)
        )
    required = PAGE_COUNT * LINES_PER_PAGE
    if len(lines) < required:
        raise ValueError(f"need at least {required} real source lines, found {len(lines)}")
    return files, lines, aggregate.hexdigest()


def paginate(lines: list[SourceLine]) -> list[list[SourceLine]]:
    selected = lines[:LINES_PER_SIDE] + lines[-LINES_PER_SIDE:]
    pages = [
        selected[offset : offset + LINES_PER_PAGE]
        for offset in range(0, len(selected), LINES_PER_PAGE)
    ]
    assert len(pages) == PAGE_COUNT
    assert all(len(page) == LINES_PER_PAGE for page in pages)
    return pages


def page_segments(page: Iterable[SourceLine]) -> list[dict[str, object]]:
    segments: list[dict[str, object]] = []
    for line in page:
        if not segments or segments[-1]["path"] != line.path:
            segments.append(
                {
                    "path": line.path,
                    "start_line": line.number,
                    "end_line": line.number,
                }
            )
        else:
            segments[-1]["end_line"] = line.number
    return segments


def page_title(page: list[SourceLine]) -> str:
    paths = list(dict.fromkeys(line.path for line in page))
    if len(paths) == 1:
        return paths[0]
    return f"{paths[0]}  →  {paths[-1]}"


def prepare_font(source: Path) -> Path:
    font = FontToolsFont(str(source))
    if "fvar" not in font:
        return source
    axes = {axis.axisTag: (axis.minValue, axis.maxValue) for axis in font["fvar"].axes}
    if "wght" not in axes:
        raise ValueError("variable font has no weight axis")
    minimum, maximum = axes["wght"]
    if not minimum <= 400 <= maximum:
        raise ValueError("font does not provide regular weight 400")
    target = ROOT / ".venv-source-book" / "NotoSansCJKsc-Regular-subset.ttf"
    instantiated = instantiateVariableFont(font, {"wght": 400}, updateFontNames=True)
    instantiated.save(str(target))
    return target


def render_pdf(pages: list[list[SourceLine]], source_hash: str, font: Path) -> None:
    font = prepare_font(font)
    pdfmetrics.registerFont(TTFont("SourceBookFont", str(font)))
    page_width, page_height = A4
    document = canvas.Canvas(str(PDF_PATH), pagesize=A4, invariant=1)
    document.setTitle("九章API安全系统")
    document.setAuthor("聚信得仁")
    document.setSubject("Java API security source code and native deployment configuration")
    document.setCreator("Offline source book renderer")

    for page_number, page in enumerate(pages, start=1):
        document.setFillColor(HexColor("#15263a"))
        document.setFont("SourceBookFont", 12)
        document.drawString(34, page_height - 34, "九章API安全系统 · 源码")
        document.setFillColor(HexColor("#536477"))
        document.setFont("SourceBookFont", 7.5)
        document.drawString(34, page_height - 49, page_title(page))
        document.drawRightString(
            page_width - 34,
            page_height - 34,
            f"第 {page_number} / {PAGE_COUNT} 页",
        )
        document.setStrokeColor(HexColor("#b7c3cf"))
        document.setLineWidth(0.5)
        document.line(34, page_height - 57, page_width - 34, page_height - 57)

        row_top = page_height - 72
        row_height = 14.0
        previous_path = None
        for row, line in enumerate(page):
            baseline = row_top - row * row_height
            if row % 2:
                document.setFillColor(HexColor("#f5f7f9"))
                document.rect(34, baseline - 4.5, page_width - 68, 11.5, fill=1, stroke=0)
            if line.path != previous_path:
                document.setFillColor(HexColor("#176a83"))
                document.setFont("SourceBookFont", 5.8)
                document.drawRightString(page_width - 36, baseline + 5.8, line.path)
                previous_path = line.path

            document.setFillColor(HexColor("#8793a1"))
            document.setFont("SourceBookFont", 6.4)
            document.drawRightString(61, baseline, str(line.number))
            stripped = line.text.strip()
            color = "#617363" if stripped.startswith(("//", "#")) else "#17232e"
            if line.path.endswith(".toml") and stripped.startswith("["):
                color = "#175c83"
            document.setFillColor(HexColor(color))
            size = fitting_font_size(line.text)
            document.setFont("SourceBookFont", size)
            document.drawString(69, baseline, line.text)

        document.setStrokeColor(HexColor("#d0d7de"))
        document.line(34, 46, page_width - 34, 46)
        document.setFillColor(HexColor("#6c7885"))
        document.setFont("SourceBookFont", 6.5)
        document.drawString(34, 33, f"源码指纹 {source_hash[:16]} · 前后连续摘录 · 每页50行")
        document.drawRightString(page_width - 34, 33, "Java 21 · Native API Security")
        document.showPage()
    document.save()


def fitting_font_size(text: str) -> float:
    if not text:
        return 8.2
    width = pdfmetrics.stringWidth(text, "SourceBookFont", 8.2)
    available = A4[0] - 105
    if width <= available:
        return 8.2
    size = max(5.4, 8.2 * available / width)
    if pdfmetrics.stringWidth(text, "SourceBookFont", size) > available + 0.1:
        raise ValueError("a source line cannot be fitted without truncation")
    return size


def render_html(pages: list[list[SourceLine]], source_hash: str) -> None:
    parts = [
        "<!doctype html>",
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>九章API安全系统 · 60页源码</title>",
        """<style>
:root {
  color-scheme: light;
  --ink: #17232e;
  --muted: #6c7885;
  --line: #d0d7de;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: #e8edf1;
  color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", sans-serif;
}
.page {
  width: 210mm;
  height: 297mm;
  margin: 12px auto;
  padding: 10mm 10mm 14mm;
  background: white;
  box-shadow: 0 2px 12px #60708030;
  position: relative;
  overflow: visible;
}
header {
  border-bottom: 1px solid #b7c3cf;
  padding-bottom: 2mm;
  margin-bottom: 2mm;
}
h1 { font-size: 15px; margin: 0 0 2mm; }
.path { font-size: 10px; color: #536477; word-break: break-all; }
.number { float: right; color: #536477; font-size: 11px; }
.lines {
  font: 9px/1.5 SFMono-Regular, Menlo, Consolas, "Noto Sans CJK SC", monospace;
}
.line {
  height: 14px;
  white-space: pre;
  overflow: visible;
}
.line:nth-child(even) { background: #f5f7f9; }
.no {
  display: inline-block;
  width: 34px;
  text-align: right;
  margin-right: 12px;
  color: #8793a1;
  user-select: none;
}
.comment { color: #617363; }
.file-start { color: #176a83; }
footer {
  position: absolute;
  left: 10mm;
  right: 10mm;
  bottom: 6mm;
  border-top: 1px solid var(--line);
  padding-top: 2mm;
  color: var(--muted);
  font-size: 9px;
}
.fingerprint { font-family: monospace; }
@page { size: A4; margin: 0; }
@media print {
  body { background: white; }
  .page {
    margin: 0;
    box-shadow: none;
    break-after: page;
    page-break-after: always;
  }
  .page:last-child { break-after: auto; page-break-after: auto; }
}
</style></head><body>""",
    ]
    for page_number, page in enumerate(pages, start=1):
        parts.append('<section class="page">')
        parts.append(
            f'<header><span class="number">第 {page_number} / {PAGE_COUNT} 页</span>'
            f"<h1>九章API安全系统 · 源码</h1>"
            f'<div class="path">{html.escape(page_title(page))}</div></header>'
        )
        parts.append('<div class="lines">')
        previous_path = None
        for line in page:
            stripped = line.text.strip()
            class_name = "comment" if stripped.startswith(("//", "#")) else ""
            if line.path != previous_path:
                class_name = f"{class_name} file-start".strip()
                previous_path = line.path
            parts.append(
                f'<div class="line {class_name}" data-file="{html.escape(line.path)}" '
                f'data-line="{line.number}"><span class="no">{line.number}</span>'
                f'<span class="code">{html.escape(line.text)}</span></div>'
            )
        parts.append("</div>")
        parts.append(
            f'<footer><span class="fingerprint">源码指纹 {source_hash[:16]}</span>'
            " · 前后连续摘录 · 每页50行</footer></section>"
        )
    parts.append("</body></html>")
    HTML_PATH.write_text("\n".join(parts), encoding="utf-8")


def build_manifest(
    files: list[SourceFile], pages: list[list[SourceLine]], source_hash: str
) -> dict[str, object]:
    file_pages: dict[str, set[int]] = {source.path: set() for source in files}
    page_entries = []
    for page_number, page in enumerate(pages, start=1):
        segments = page_segments(page)
        for segment in segments:
            file_pages[str(segment["path"])].add(page_number)
        page_entries.append(
            {"page": page_number, "source_line_count": len(page), "segments": segments}
        )
    total_lines = sum(source.line_count for source in files)
    return {
        "document": "jiuzhang-api-java-source-front30-back30",
        "page_count": PAGE_COUNT,
        "lines_per_page": LINES_PER_PAGE,
        "source_sha256": source_hash,
        "source_line_count": total_lines,
        "included_line_count": PAGE_COUNT * LINES_PER_PAGE,
        "selection_rule": "The first 1500 lines and final 1500 lines of the ordered source sequence, without filler.",
        "omitted_global_line_range": {
            "start_line": LINES_PER_SIDE + 1,
            "end_line": total_lines - LINES_PER_SIDE,
        } if total_lines > PAGE_COUNT * LINES_PER_PAGE else None,
        "files": [
            {
                "path": source.path,
                "sha256": source.sha256,
                "line_count": source.line_count,
                "pages": sorted(file_pages[source.path]),
            }
            for source in files
        ],
        "pages": page_entries,
        "artifacts": {
            "pdf": {"name": PDF_PATH.name, "sha256": digest(PDF_PATH.read_bytes())},
            "html": {"name": HTML_PATH.name, "sha256": digest(HTML_PATH.read_bytes())},
        },
    }


def verify_pdf(source_hash: str) -> None:
    reader = PdfReader(str(PDF_PATH))
    if len(reader.pages) != PAGE_COUNT:
        raise AssertionError(f"PDF has {len(reader.pages)} pages instead of {PAGE_COUNT}")
    expected_pages = paginate(load_sources()[1])
    for number, (page, expected_lines) in enumerate(
        zip(reader.pages, expected_pages), start=1
    ):
        text = page.extract_text() or ""
        if f"第 {number} / {PAGE_COUNT} 页" not in text:
            raise AssertionError(f"page {number} lacks its page marker")
        if source_hash[:16] not in text:
            raise AssertionError(f"page {number} lacks the source fingerprint")
        for line in expected_lines:
            if line.text.strip() and line.text not in text:
                raise AssertionError(
                    f"PDF page {number} omitted {line.path}:{line.number}"
                )
    first = reader.pages[0].extract_text() or ""
    last = reader.pages[-1].extract_text() or ""
    if "public final class Main" not in first:
        raise AssertionError("first page does not contain the expected first Java source file")
    if "WantedBy=multi-user.target" not in last:
        raise AssertionError("last page does not contain the expected final configuration")

    html_document = HTML_PATH.read_text(encoding="utf-8")
    html_pages = html_document.split('<section class="page">')[1:]
    if len(html_pages) != PAGE_COUNT:
        raise AssertionError(f"HTML has {len(html_pages)} pages instead of {PAGE_COUNT}")
    for number, (page, expected_lines) in enumerate(
        zip(html_pages, expected_pages), start=1
    ):
        for line in expected_lines:
            if line.text.strip() and html.escape(line.text) not in page:
                raise AssertionError(
                    f"HTML page {number} omitted {line.path}:{line.number}"
                )


def check_existing(files: list[SourceFile], source_hash: str) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest["source_sha256"] != source_hash:
        raise AssertionError("source fingerprint differs from the manifest")
    current_files = {source.path: source.sha256 for source in files}
    listed_files = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    if current_files != listed_files:
        raise AssertionError("one or more selected files changed after rendering")
    for artifact in manifest["artifacts"].values():
        path = OUTPUT / artifact["name"]
        if digest(path.read_bytes()) != artifact["sha256"]:
            raise AssertionError(f"artifact hash mismatch: {path.name}")
    verify_pdf(source_hash)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify existing artifacts")
    parser.add_argument("--font", type=Path, default=FONT_PATH, help="embeddable Unicode TTF")
    arguments = parser.parse_args()
    files, lines, source_hash = load_sources()
    if arguments.check:
        check_existing(files, source_hash)
        print(f"verified: {PAGE_COUNT} pages, {len(lines)} source lines, hashes match")
        return
    if not arguments.font.is_file():
        raise FileNotFoundError(f"Unicode font not found: {arguments.font}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    pages = paginate(lines)
    render_pdf(pages, source_hash, arguments.font)
    render_html(pages, source_hash)
    manifest = build_manifest(files, pages, source_hash)
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    verify_pdf(source_hash)
    check_existing(files, source_hash)
    print(
        json.dumps(
            {
                "pages": PAGE_COUNT,
                "source_lines": len(lines),
                "files": len(files),
                "source_sha256": source_hash,
                "pdf": str(PDF_PATH.relative_to(ROOT)),
                "html": str(HTML_PATH.relative_to(ROOT)),
                "manifest": str(MANIFEST_PATH.relative_to(ROOT)),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
