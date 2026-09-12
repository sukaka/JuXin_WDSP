"""JWT-18 配对实验的本地测试密钥与令牌工具（P0-03/S3 交付后接线）。

纪律：
- 测试密钥由运行器在 run 目录现场生成（0600），不入库、不入 git、不引用生产凭据；
- 私钥与已签发 Token 只写 run 目录临时文件，运行结束由 run.sh 删除（证据不含密钥材料）；
- RS256 签名经 `openssl dgst -sha256 -sign` 完成，签名输入走 stdin 不上命令行；
  纯 Python 标准库 + openssl，不引入新依赖；
- 这里只产出基准语料所需的确定形态：有效 Token（iss/aud/sub/exp 合法）与
  篡改签名 Token（header/payload 原样、签名末字节翻转，确定性损坏）。

网关真实行为（gateway/modules/jiuzhang_guard/jwt_trust.go + dynamic_security/jwtverify）：
VERIFIED 继续后续检测且不产生事件；INVALID 在 PROTECT 下 401（规范 Bearer challenge，
事件 JWT_AUTH_FAILED 落 access_control_events）；缺失且非必需为 NOT_PRESENT 原样继续。
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from pathlib import Path

ALG = "RS256"

_EXPONENT_RE = re.compile(r"Exponent:\s*(\d+)")


class JWTToolError(Exception):
    """测试密钥/JWKS/Token 生成失败。"""


def b64url(data: bytes) -> str:
    """JWS 约定 base64url（无填充）。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    # 严格模式：非法字符直接报错（基准工具对畸形输入 fail-fast，不静默吞错）
    return base64.b64decode((text + pad).replace("-", "+").replace("_", "/"), validate=True)


def _compact(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_signing_input(
    *, kid: str, issuer: str, audience: str, subject: str, iat: int, exp: int
) -> bytes:
    """构造 RS256 签名输入（header.payload，紧凑 JSON、键序固定，确定性）。"""
    if exp <= iat:
        raise JWTToolError(f"exp 必须大于 iat（iat={iat}, exp={exp}）")
    header = {"alg": ALG, "kid": kid, "typ": "JWT"}
    payload = {"aud": audience, "exp": exp, "iat": iat, "iss": issuer, "sub": subject}
    return b64url(_compact(header)).encode() + b"." + b64url(_compact(payload)).encode()


def _openssl_sign_rs256(key_path: str | Path, signing_input: bytes) -> bytes:
    try:
        p = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
            input=signing_input,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise JWTToolError("openssl 不可用（JWT 配对实验需要 openssl 生成/签名测试密钥）") from exc
    if p.returncode != 0 or not p.stdout:
        raise JWTToolError(f"openssl 签名失败: {p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout


def mint_token(
    key_path: str | Path,
    *,
    kid: str,
    issuer: str,
    audience: str,
    subject: str = "p0bench-user",
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """用本 run 专用测试私钥现场签发有效 RS256 Token。"""
    if ttl_seconds < 60:
        raise JWTToolError("token_ttl_seconds 必须 >= 60（过短的 TTL 会在回放窗口内过期）")
    iat = int(time.time()) if now is None else int(now)
    signing_input = build_signing_input(
        kid=kid, issuer=issuer, audience=audience, subject=subject, iat=iat, exp=iat + ttl_seconds
    )
    sig = _openssl_sign_rs256(key_path, signing_input)
    return signing_input.decode() + "." + b64url(sig)


def tamper_token(token: str) -> str:
    """确定性篡改：header/payload 原样保留（iss/aud/exp 均合法），仅签名末字节翻转。

    签名损坏 → 网关验签 INVALID（PROTECT 下 401）；结构仍合法三段，
    不走格式错误分支，精确命中「篡改签名」语义。
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTToolError("Token 必须为三段 JWS 紧凑序列")
    try:
        sig = bytearray(b64url_decode(parts[2]))
    except Exception as exc:
        raise JWTToolError(f"Token 签名段不是合法 base64url: {exc}") from exc
    if not sig:
        raise JWTToolError("Token 签名段为空")
    sig[-1] ^= 0xFF
    return ".".join(parts[:2]) + "." + b64url(bytes(sig))


def rsa_public_numbers(key_path: str | Path) -> tuple[str, int]:
    """从 PEM 私钥提取 RSA 公钥参数（modulus 十六进制大写串, exponent）。"""
    try:
        p = subprocess.run(
            ["openssl", "rsa", "-in", str(key_path), "-noout", "-modulus"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise JWTToolError("openssl 不可用") from exc
    if p.returncode != 0 or "Modulus=" not in p.stdout:
        raise JWTToolError(f"openssl 读取模数失败: {p.stderr.strip()}")
    modulus = p.stdout.strip().split("Modulus=", 1)[1].strip().upper()
    p2 = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-text"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if p2.returncode != 0:
        raise JWTToolError(f"openssl 读取公钥指数失败: {p2.stderr.strip()}")
    m = _EXPONENT_RE.search(p2.stdout)
    if not m:
        raise JWTToolError("openssl 输出中未找到 RSA 公钥指数（Exponent 行）")
    return modulus, int(m.group(1))


def build_jwk(modulus_hex: str, exponent: int, kid: str) -> dict:
    """由 RSA 公钥参数构造 JWK（仅公钥字段；n/e 为无符号大端 base64url）。"""
    if not kid:
        raise JWTToolError("kid 不能为空")
    try:
        n_bytes = bytes.fromhex(modulus_hex)
    except ValueError as exc:
        raise JWTToolError(f"模数不是合法十六进制: {exc}") from exc
    if len(n_bytes) * 8 < 2048:
        raise JWTToolError(f"RSA 公钥至少 2048 位，实际 {len(n_bytes) * 8} 位")
    if not isinstance(exponent, int) or exponent < 3 or exponent % 2 == 0:
        raise JWTToolError(f"非法 RSA 公钥指数: {exponent!r}")
    e_bytes = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": ALG,
        "n": b64url(n_bytes),
        "e": b64url(e_bytes),
    }


def build_jwks(key_path: str | Path, kid: str) -> dict:
    """由本 run 私钥导出静态 JWKS（仅公钥；服务端 jwttrust.ValidateJWKS 可校验）。"""
    modulus, exponent = rsa_public_numbers(key_path)
    return {"keys": [build_jwk(modulus, exponent, kid)]}


def write_header_file(path: str | Path, token: str) -> None:
    """写 `Authorization: Bearer <token>` 头文件（0600；供 curl -H @file 注入，
    Token 不上命令行、不进入任何输出）。"""
    p = Path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"Authorization: Bearer {token}\n")
    finally:
        os.chmod(p, 0o600)
