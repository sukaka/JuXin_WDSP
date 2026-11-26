#!/usr/bin/env python3
"""JiuZhang WDSP Phase 9C-2 Local Offline Semantic Firewall Sidecar.

Listens strictly on a local Unix Domain Socket (AF_UNIX — zero TCP/UDP ports),
implementing:
  - GET /healthz
  - POST /v1/classify

Backend modes:
  1. Verified INT8 ONNX Runtime backend (when SEMANTIC_GUARD_MODEL_MANIFEST is set):
     Enforces mandatory SHA-256 verification against model-manifest.json before
     loading the model (fail-closed on tamper, path traversal, or missing runtime).
     Reports backend="onnxruntime" with exact model_id and verified model_sha256.
  2. Deterministic zero-dependency lexical/heuristic fallback backend (when no
     manifest is configured):
     Honestly reports backend="heuristic_fallback" (never falsely claims "onnxruntime").

Security invariants:
  - Never binds TCP/UDP sockets.
  - Rejects oversized request bodies (> 64 KiB) with HTTP 413.
  - Never logs raw prompt, MCP argument, or request body text.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import http.server
import json
import math
import os
import re
import signal
import socket
import socketserver
import stat
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

MAX_REQUEST_BYTES = 64 * 1024  # 64 KiB hard upper bound on /v1/classify request body
MAX_TEXT_RUNES = 8192
DEFAULT_SOCKET_PATH = "/var/run/caddy/sidecars/semantic.sock"
ALLOWED_CHANNELS = frozenset({"llm_prompt", "mcp_content", "web_grayzone"})
DEFAULT_LABELS = (
    "safe",
    "prompt_injection",
    "jailbreak",
    "indirect_injection",
    "web_payload",
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ModelVerificationError(RuntimeError):
    """Raised fail-closed whenever model manifest or SHA-256 verification fails."""


@dataclasses.dataclass(frozen=True)
class VerifiedManifest:
    model_id: str
    model_path: str
    model_sha256: str
    max_sequence_length: int
    labels: Tuple[str, ...]
    tokenizer_path: Optional[str] = None
    tokenizer_sha256: str = ""


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def _safe_manifest_member_path(base_dir: str, rel_name: str, field_name: str) -> str:
    if not isinstance(rel_name, str) or not rel_name.strip():
        raise ModelVerificationError(f"manifest field {field_name!r} must be a non-empty string")
    if _has_control_chars(rel_name) or "\\" in rel_name or rel_name.startswith("/"):
        raise ModelVerificationError(f"manifest field {field_name!r} must be a safe relative path")
    parts = rel_name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ModelVerificationError(f"manifest field {field_name!r} contains forbidden traversal segment")
    base_real = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base_real, rel_name))
    if not candidate.startswith(base_real + os.sep):
        raise ModelVerificationError(f"manifest field {field_name!r} escapes manifest directory")
    if not os.path.isfile(candidate):
        raise ModelVerificationError(f"manifest target {field_name!r} does not exist: {rel_name}")
    return candidate


def verify_model_manifest(manifest_path: str) -> VerifiedManifest:
    """Strictly parse model-manifest.json and verify SHA-256 digests fail-closed."""
    if not manifest_path or not os.path.isfile(manifest_path):
        raise ModelVerificationError(f"model manifest not found: {manifest_path!r}")
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        raise ModelVerificationError(f"failed to parse model manifest JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ModelVerificationError("model manifest root must be a JSON object")
    if data.get("schema_version") != 1:
        raise ModelVerificationError(f"unsupported manifest schema_version: {data.get('schema_version')!r}")

    model_id = data.get("model_id")
    if not isinstance(model_id, str) or not model_id.strip() or len(model_id) > 128 or _has_control_chars(model_id):
        raise ModelVerificationError("manifest model_id is missing or invalid")
    model_id = model_id.strip()

    expected_sha = data.get("sha256")
    if not isinstance(expected_sha, str) or not HEX64_RE.match(expected_sha.strip().lower()):
        raise ModelVerificationError("manifest sha256 must be a 64-char hex digest")
    expected_sha = expected_sha.strip().lower()

    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    model_path = _safe_manifest_member_path(manifest_dir, data.get("model_file", ""), "model_file")

    actual_sha = _sha256_file(model_path)
    if not hmac.compare_digest(actual_sha, expected_sha):
        raise ModelVerificationError(
            f"model SHA-256 mismatch (fail-closed): expected {expected_sha[:12]}..., got {actual_sha[:12]}..."
        )

    tokenizer_path: Optional[str] = None
    tokenizer_sha = ""
    if data.get("tokenizer_file"):
        expected_tok_sha = data.get("tokenizer_sha256")
        if not isinstance(expected_tok_sha, str) or not HEX64_RE.match(expected_tok_sha.strip().lower()):
            raise ModelVerificationError("manifest tokenizer_sha256 must be a 64-char hex digest when tokenizer_file is set")
        expected_tok_sha = expected_tok_sha.strip().lower()
        tokenizer_path = _safe_manifest_member_path(manifest_dir, data["tokenizer_file"], "tokenizer_file")
        actual_tok_sha = _sha256_file(tokenizer_path)
        if not hmac.compare_digest(actual_tok_sha, expected_tok_sha):
            raise ModelVerificationError("tokenizer SHA-256 mismatch (fail-closed)")
        tokenizer_sha = actual_tok_sha

    max_seq = data.get("max_sequence_length", 512)
    if not isinstance(max_seq, int) or max_seq < 16 or max_seq > 8192:
        raise ModelVerificationError("manifest max_sequence_length out of range [16, 8192]")

    raw_labels = data.get("labels", list(DEFAULT_LABELS))
    if not isinstance(raw_labels, list) or not raw_labels or not all(
        isinstance(x, str) and x.strip() and not _has_control_chars(x) for x in raw_labels
    ):
        raise ModelVerificationError("manifest labels must be a non-empty list of strings")
    labels = tuple(x.strip().lower() for x in raw_labels)

    return VerifiedManifest(
        model_id=model_id,
        model_path=model_path,
        model_sha256=actual_sha,
        max_sequence_length=max_seq,
        labels=labels,
        tokenizer_path=tokenizer_path,
        tokenizer_sha256=tokenizer_sha,
    )


class ClassifierBackend:
    backend_name: str = ""
    model_id: str = ""
    model_sha256: str = ""

    def classify(self, channel: str, text: str) -> Tuple[str, float]:
        raise NotImplementedError


class ONNXClassifierBackend(ClassifierBackend):
    """Offline INT8 ONNX Runtime backend with mandatory SHA-256 verification."""

    backend_name = "onnxruntime"

    def __init__(self, manifest_path: str, ort_module: Any = None) -> None:
        verified = verify_model_manifest(manifest_path)
        if ort_module is None:
            try:
                import onnxruntime as ort_module  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ModelVerificationError(
                    "onnxruntime is required when SEMANTIC_GUARD_MODEL_MANIFEST is configured (fail-closed)"
                ) from exc

        self._manifest = verified
        self.model_id = verified.model_id
        self.model_sha256 = verified.model_sha256
        self._vocab: Dict[str, int] = {}
        if verified.tokenizer_path and verified.tokenizer_path.endswith(".json"):
            with open(verified.tokenizer_path, "r", encoding="utf-8") as fh:
                tok_data = json.load(fh)
            if isinstance(tok_data, dict):
                vocab_obj = tok_data.get("model", {}).get("vocab", tok_data) if isinstance(tok_data.get("model"), dict) else tok_data
                if isinstance(vocab_obj, dict):
                    self._vocab = {str(k): int(v) for k, v in vocab_obj.items() if isinstance(v, int)}

        self._session = ort_module.InferenceSession(
            verified.model_path,
            providers=["CPUExecutionProvider"],
        )
        self._input_names = [inp.name for inp in self._session.get_inputs()]

    def _encode_tokens(self, text: str) -> Tuple[List[int], List[int]]:
        max_len = self._manifest.max_sequence_length
        tokens = re.findall(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]|[^\s]", text.lower())
        ids: List[int] = [101]  # [CLS]
        for tok in tokens[: max(1, max_len - 2)]:
            if tok in self._vocab:
                ids.append(self._vocab[tok])
            else:
                # Deterministic vocab-independent fallback token ID in [1000, 30000)
                digest = hashlib.blake2b(tok.encode("utf-8"), digest_size=4).digest()
                ids.append(1000 + (int.from_bytes(digest, "big") % 29000))
        ids.append(102)  # [SEP]
        mask = [1] * len(ids)
        return ids, mask

    def classify(self, channel: str, text: str) -> Tuple[str, float]:
        ids, mask = self._encode_tokens(f"[{channel}] {text}")
        feeds: Dict[str, Any] = {}
        for name in self._input_names:
            if "mask" in name:
                feeds[name] = [mask]
            elif "type" in name:
                feeds[name] = [[0] * len(ids)]
            else:
                feeds[name] = [ids]
        outputs = self._session.run(None, feeds)
        if not outputs:
            return "safe", 0.0
        raw_logits = outputs[0]
        if isinstance(raw_logits, (list, tuple)) and raw_logits and isinstance(raw_logits[0], (list, tuple)):
            logits = [float(x) for x in raw_logits[0]]
        elif hasattr(raw_logits, "tolist"):
            as_list = raw_logits.tolist()
            row = as_list[0] if as_list and isinstance(as_list[0], list) else as_list
            logits = [float(x) for x in row]
        else:
            logits = [float(x) for x in raw_logits]
        if not logits:
            return "safe", 0.0
        max_v = max(logits)
        exps = [math.exp(v - max_v) for v in logits]
        denom = sum(exps) or 1.0
        probs = [v / denom for v in exps]
        best_idx = max(range(len(probs)), key=lambda i: probs[i])
        label = self._manifest.labels[best_idx] if best_idx < len(self._manifest.labels) else "prompt_injection"
        return label, round(min(max(probs[best_idx], 0.0), 1.0), 4)


# Linear-time deterministic pattern sets for zero-dependency heuristic fallback.
_PROMPT_INJECTION_RULES: Tuple[Tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"(?i)\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?)\b"), 0.92),
    (re.compile(r"(?i)\bdisregard\s+(all\s+|any\s+|the\s+)?(previous\s+|prior\s+|above\s+)?(instructions?|prompts?|rules?)\b"), 0.90),
    (re.compile(r"(?i)\b(reveal|show|print|repeat|dump|leak|output)\s+(me\s+|your\s+|the\s+)?(system|initial|original|full|hidden)\s+(prompt|instructions?|rules?)\b"), 0.91),
    (re.compile(r"(?i)<\|\s*(im_start|system|endoftext)\s*\|>|###\s*(system|instruction)\s*:"), 0.88),
    (re.compile(r"忽略(你)?(之前|以前|上述|以上|所有|全部|先前).{0,8}(指令|指示|命令|要求|设定|规则)"), 0.92),
    (re.compile(r"(泄露|透露|输出|打印|重复|展示).{0,8}(系统提示词|系统指令|初始指令|隐藏提示词)"), 0.91),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(a|an)\s+(unrestricted|unfiltered|evil|malicious)\b"), 0.87),
    (re.compile(r"(?i)\bnew\s+system\s+instructions?\s*:"), 0.86),
)

_JAILBREAK_RULES: Tuple[Tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"(?i)\bdo\s+anything\s+now\b|\bdan\s+(mode|jailbreak|prompt)\b"), 0.94),
    (re.compile(r"(?i)\b(jail\s?break|developer\s+mode|god\s+mode)\b"), 0.90),
    (re.compile(r"(?i)\b(bypass|disable|override|forget)\s+(all\s+|your\s+|the\s+)?(safety|ethical|content|security)\s+(filters?|guardrails?|restrictions?|policies?)\b"), 0.91),
    (re.compile(r"(?i)\bpretend\s+(you\s+)?(have\s+no|without\s+any)\s+(rules|restrictions|limits|guardrails)\b"), 0.86),
    (re.compile(r"(越狱模式|解除所有限制|无视安全限制|开发者模式)"), 0.91),
)

_INDIRECT_INJECTION_RULES: Tuple[Tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"(?i)(assistant|agent|model)\s*:\s*(ignore|override|execute|call\s+tool|exfiltrate|send)"), 0.92),
    (re.compile(r"(?i)\b(exfiltrate|steal|forward|upload)\b.{0,40}\b(secret|token|credential|api[_ -]?key|password|env|ssh)\b"), 0.91),
    (re.compile(r"(?i)!\[[^\]]*\]\(https?://[^)\s]+(\?[^)\s]*(secret|token|key|data|leak|exfil)|#[a-z0-9_=-]{8,})"), 0.93),
    (re.compile(r"(?i)\b(hidden\s+instruction|important\s+system\s+override|tool\s+output\s+override)\b"), 0.89),
    (re.compile(r"(?i)\bignore\s+(the\s+)?(user|previous|prior)\b.{0,40}\b(send|post|fetch|curl|read\s+/etc/)\b"), 0.92),
    (re.compile(r"(隐藏指令|窃取密钥|外发敏感数据|忽略用户指令)"), 0.91),
)

_WEB_PAYLOAD_RULES: Tuple[Tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"(?i)\bunion\b.{0,20}\bselect\b.{0,40}\bfrom\b|\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d+\s*\)"), 0.91),
    (re.compile(r"(?i)<\s*script\b|javascript\s*:|\bon(error|load|mouseover|focus)\s*="), 0.89),
    (re.compile(r"(\{\{.{1,80}(__class__|__mro__|__subclasses__|config|lipsum|cycler).{0,40}\}\}|\$\{jndi:(ldap|rmi|dns)://)"), 0.94),
    (re.compile(r"(?i)<!\s*(doctype|entity)\b.{0,60}\b(system|public)\b"), 0.92),
    (re.compile(r"(?i)(\.\./){2,}(etc/passwd|etc/shadow|windows/win\.ini)|;\s*(cat|id|whoami|curl|wget|bash|sh)\s+"), 0.90),
    (re.compile(r"(?i)169\.254\.169\.254/latest/meta-data|metadata\.google\.internal"), 0.90),
)

_SUSPICIOUS_SOFT_RULES: Tuple[Tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"(?i)\bsystem\s+prompt\b"), "prompt_injection", 0.58),
    (re.compile(r"(?i)\bignore\s+instructions?\b"), "prompt_injection", 0.62),
    (re.compile(r"(?i)\bact\s+as\s+(root|admin|system)\b"), "jailbreak", 0.60),
    (re.compile(r"(?i)\bbase64\s+decode\b.{0,40}\b(exec|eval|system)\b"), "web_payload", 0.68),
)


def _has_unicode_smuggling(text: str) -> bool:
    """Detect invisible Unicode tag characters (U+E0000-U+E007F) or excessive BiDi/zero-width overrides."""
    tag_chars = 0
    bidi_chars = 0
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            tag_chars += 1
            if tag_chars >= 4:
                return True
        elif cp in (0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            bidi_chars += 1
            if bidi_chars >= 2:
                return True
    return False


class HeuristicFallbackBackend(ClassifierBackend):
    """Deterministic, zero-dependency stdlib fallback backend.

    Honestly reports backend="heuristic_fallback" (never falsely claims "onnxruntime").
    """

    backend_name = "heuristic_fallback"
    model_id = "heuristic-fallback-v1"
    model_sha256 = ""

    def classify(self, channel: str, text: str) -> Tuple[str, float]:
        best_label = "safe"
        best_score = 0.02

        def consider(label: str, score: float) -> None:
            nonlocal best_label, best_score
            if score > best_score:
                best_label = label
                best_score = score

        if _has_unicode_smuggling(text):
            consider("indirect_injection" if channel == "mcp_content" else "prompt_injection", 0.90)

        for pat, score in _JAILBREAK_RULES:
            if pat.search(text):
                consider("jailbreak", score)

        for pat, score in _PROMPT_INJECTION_RULES:
            if pat.search(text):
                target = "indirect_injection" if channel == "mcp_content" else "prompt_injection"
                consider(target, score)

        for pat, score in _INDIRECT_INJECTION_RULES:
            if pat.search(text):
                consider("indirect_injection", score)

        for pat, score in _WEB_PAYLOAD_RULES:
            if pat.search(text):
                consider("web_payload", score)

        if best_score < 0.50:
            for pat, label, score in _SUSPICIOUS_SOFT_RULES:
                if pat.search(text):
                    if channel == "mcp_content" and label == "prompt_injection":
                        label = "indirect_injection"
                    consider(label, score)

        return best_label, round(min(max(best_score, 0.0), 0.99), 4)


def build_backend(manifest_path: Optional[str] = None, ort_module: Any = None) -> ClassifierBackend:
    """Create the configured classifier backend.

    If manifest_path is non-empty, fail-closed SHA-256 verification + ONNX loading is mandatory.
    Only when no manifest is configured does this return HeuristicFallbackBackend.
    """
    mp = (manifest_path or "").strip()
    if mp:
        return ONNXClassifierBackend(mp, ort_module=ort_module)
    return HeuristicFallbackBackend()


class UnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str, backend: ClassifierBackend, socket_mode: int = 0o660) -> None:
        self.backend = backend
        self.socket_mode = socket_mode
        self._socket_path = socket_path
        self._cleanup_stale_socket()
        super().__init__(socket_path, SemanticRequestHandler)

    def _cleanup_stale_socket(self) -> None:
        parent = os.path.dirname(self._socket_path)
        if parent:
            os.makedirs(parent, mode=0o770, exist_ok=True)
        if os.path.lexists(self._socket_path):
            st = os.lstat(self._socket_path)
            if not stat.S_ISSOCK(st.st_mode):
                raise RuntimeError(f"refusing to unlink non-socket path: {self._socket_path}")
            os.unlink(self._socket_path)

    def server_bind(self) -> None:
        self.socket.bind(self.server_address)
        os.chmod(self.server_address, self.socket_mode)
        self.server_name = "unix"
        self.server_port = 0

    def server_close(self) -> None:
        super().server_close()
        try:
            if os.path.lexists(self._socket_path):
                st = os.lstat(self._socket_path)
                if stat.S_ISSOCK(st.st_mode):
                    os.unlink(self._socket_path)
        except OSError:
            pass


class SemanticRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def address_string(self) -> str:
        return "unix"

    def log_message(self, format: str, *args: Any) -> None:
        # Never log raw prompts or request payloads.
        return

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/healthz":
            self._send_json(404, {"error": "not_found"})
            return
        backend: ClassifierBackend = self.server.backend  # type: ignore[attr-defined]
        self._send_json(
            200,
            {
                "status": "ok",
                "model_id": backend.model_id,
                "model_sha256": backend.model_sha256,
                "backend": backend.backend_name,
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/v1/classify":
            self._send_json(404, {"error": "not_found"})
            return

        if "transfer-encoding" in self.headers:
            self._send_json(411, {"error": "content_length_required"})
            return

        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._send_json(411, {"error": "content_length_required"})
            return
        try:
            content_len = int(raw_len.strip())
        except ValueError:
            self._send_json(400, {"error": "invalid_content_length"})
            return
        if content_len <= 0:
            self._send_json(400, {"error": "empty_body"})
            return
        if content_len > MAX_REQUEST_BYTES:
            self._send_json(413, {"error": "payload_too_large", "max_bytes": MAX_REQUEST_BYTES})
            return

        raw_body = self.rfile.read(content_len)
        try:
            req = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "invalid_json"})
            return
        if not isinstance(req, dict):
            self._send_json(400, {"error": "json_object_required"})
            return

        channel = req.get("channel", "llm_prompt")
        if not isinstance(channel, str) or channel not in ALLOWED_CHANNELS:
            self._send_json(400, {"error": "invalid_channel"})
            return
        text = req.get("text")
        if not isinstance(text, str):
            self._send_json(400, {"error": "text_must_be_string"})
            return
        if len(text) > MAX_TEXT_RUNES:
            text = text[:MAX_TEXT_RUNES]

        backend: ClassifierBackend = self.server.backend  # type: ignore[attr-defined]
        t0 = time.monotonic()
        label, score = backend.classify(channel, text)
        latency_ms = max(0, int(round((time.monotonic() - t0) * 1000)))
        self._send_json(
            200,
            {
                "label": label,
                "score": score,
                "model_id": backend.model_id,
                "latency_ms": latency_ms,
            },
        )

    def do_PUT(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "method_not_allowed"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "method_not_allowed"})

    def do_PATCH(self) -> None:  # noqa: N802
        self._send_json(405, {"error": "method_not_allowed"})


def main() -> int:
    socket_path = os.environ.get("SEMANTIC_GUARD_SOCKET", DEFAULT_SOCKET_PATH).strip() or DEFAULT_SOCKET_PATH
    manifest_path = os.environ.get("SEMANTIC_GUARD_MODEL_MANIFEST", "").strip()
    try:
        backend = build_backend(manifest_path=manifest_path)
    except ModelVerificationError as exc:
        sys.stderr.write(f"[semantic-guard] fatal fail-closed startup error: {exc}\n")
        sys.stderr.flush()
        return 2

    srv = UnixHTTPServer(socket_path, backend)

    def _handle_signal(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    sys.stderr.write(
        f"[semantic-guard] listening on unix://{socket_path} backend={backend.backend_name} model_id={backend.model_id}\n"
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
