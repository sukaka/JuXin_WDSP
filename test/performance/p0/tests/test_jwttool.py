"""JWT-18 配对实验工具测试（jwttool：JWKS 构造 / Token 签发 / 篡改 / 头文件）。

openssl 集成用例在本机无 openssl 时跳过（preflight 在真实运行前已强制检查）。
"""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

P0_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P0_DIR))

from p0bench import cli, jwttool  # noqa: E402
from p0bench.jwttool import JWTToolError  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None

# 2048 位 RSA 模数占位（仅结构测试用，非真实密钥材料）
MODULUS_HEX_2048 = "C1" + "AB" * 255


class TestB64url(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(jwttool.b64url(b""), "")
        self.assertEqual(jwttool.b64url(b"hello"), "aGVsbG8")
        self.assertEqual(jwttool.b64url(b"\xfb\xff\xfe"), "-__-")  # url 安全字符

    def test_roundtrip(self):
        for raw in (b"\x00", b"\x01\x02\x03", bytes(range(256))):
            self.assertEqual(jwttool.b64url_decode(jwttool.b64url(raw)), raw)


class TestSigningInput(unittest.TestCase):
    def test_deterministic_and_decodable(self):
        a = jwttool.build_signing_input(kid="k1", issuer="iss", audience="aud", subject="s", iat=100, exp=200)
        b = jwttool.build_signing_input(kid="k1", issuer="iss", audience="aud", subject="s", iat=100, exp=200)
        self.assertEqual(a, b)
        h, p = a.decode().split(".")
        header = json.loads(jwttool.b64url_decode(h))
        payload = json.loads(jwttool.b64url_decode(p))
        self.assertEqual(header, {"alg": "RS256", "kid": "k1", "typ": "JWT"})
        self.assertEqual(
            payload,
            {"aud": "aud", "exp": 200, "iat": 100, "iss": "iss", "sub": "s"},
        )

    def test_exp_not_after_iat_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.build_signing_input(kid="k", issuer="i", audience="a", subject="s", iat=200, exp=200)


class TestTamperToken(unittest.TestCase):
    def _token(self, sig: bytes) -> str:
        si = jwttool.build_signing_input(kid="k", issuer="i", audience="a", subject="s", iat=1, exp=2)
        return si.decode() + "." + jwttool.b64url(sig)

    def test_tamper_preserves_header_payload_flips_signature(self):
        tok = self._token(b"\x10\x20\x30\x40")
        t = jwttool.tamper_token(tok)
        p_orig, p_new = tok.split("."), t.split(".")
        self.assertEqual(p_orig[:2], p_new[:2], "header/payload 必须原样保留")
        self.assertNotEqual(p_orig[2], p_new[2])
        self.assertEqual(jwttool.b64url_decode(p_new[2]), b"\x10\x20\x30\xbf")  # 0x40^0xFF

    def test_tamper_deterministic(self):
        tok = self._token(b"\xaa" * 16)
        self.assertEqual(jwttool.tamper_token(tok), jwttool.tamper_token(tok))

    def test_malformed_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.tamper_token("only.two")
        with self.assertRaises(JWTToolError):
            jwttool.tamper_token("a.b.!!!not-b64!!!")


class TestBuildJwk(unittest.TestCase):
    def test_known_vector(self):
        jwk = jwttool.build_jwk(MODULUS_HEX_2048, 65537, "kid-1")
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["kid"], "kid-1")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertEqual(jwk["use"], "sig")
        self.assertEqual(jwk["e"], "AQAB")
        self.assertEqual(jwttool.b64url_decode(jwk["n"]), bytes.fromhex(MODULUS_HEX_2048))
        # 无私钥/对称/URL 参数（服务端 ValidateJWKS 红线）
        for banned in ("d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5u", "jku"):
            self.assertNotIn(banned, jwk)

    def test_short_modulus_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.build_jwk("AABB", 65537, "kid-1")  # 远小于 2048 位

    def test_bad_exponent_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.build_jwk(MODULUS_HEX_2048, 4, "kid-1")  # 偶数指数非法

    def test_empty_kid_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.build_jwk(MODULUS_HEX_2048, 65537, "")


class TestHeaderFile(unittest.TestCase):
    def test_mode_0600_and_content(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "authorization.header"
            jwttool.write_header_file(f, "TOKEN-VALUE")
            self.assertEqual(f.read_text(encoding="utf-8"), "Authorization: Bearer TOKEN-VALUE\n")
            mode = stat.S_IMODE(os.stat(f).st_mode)
            self.assertEqual(mode, 0o600)


@unittest.skipUnless(HAS_OPENSSL, "openssl 不可用")
class TestOpenSSLIntegration(unittest.TestCase):
    """真实 RSA 密钥 + RS256 签名/验签回环（openssl 外部验证，不引入新依赖）。"""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.key = self.dir / "key.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(self.key)],
            check=True, capture_output=True, timeout=60,
        )
        self.pub = self.dir / "pub.pem"
        subprocess.run(
            ["openssl", "rsa", "-in", str(self.key), "-pubout", "-out", str(self.pub)],
            check=True, capture_output=True, timeout=60,
        )

    def _verify(self, token: str) -> int:
        h, p, s = token.split(".")
        sig = self.dir / "sig.bin"
        sig.write_bytes(jwttool.b64url_decode(s))
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(self.pub), "-signature", str(sig)],
            input=f"{h}.{p}".encode(),
            capture_output=True, timeout=60,
        ).returncode

    def test_public_numbers(self):
        modulus, exponent = jwttool.rsa_public_numbers(self.key)
        self.assertEqual(len(modulus), 512)  # 2048 位 = 256 字节 = 512 十六进制字符
        self.assertEqual(exponent, 65537)

    def test_jwks_from_real_key(self):
        jwks = jwttool.build_jwks(self.key, "run-kid")
        self.assertEqual(len(jwks["keys"]), 1)
        self.assertEqual(jwks["keys"][0]["kid"], "run-kid")
        # 模数与 openssl 导出一致
        modulus, _ = jwttool.rsa_public_numbers(self.key)
        self.assertEqual(jwttool.b64url_decode(jwks["keys"][0]["n"]), bytes.fromhex(modulus))

    def test_mint_valid_token_verifies(self):
        tok = jwttool.mint_token(self.key, kid="k", issuer="iss", audience="aud",
                                 subject="u", ttl_seconds=3600, now=1_700_000_000)
        self.assertEqual(self._verify(tok), 0, "有效 Token 必须通过 openssl 验签")
        payload = json.loads(jwttool.b64url_decode(tok.split(".")[1]))
        self.assertEqual(payload["iss"], "iss")
        self.assertEqual(payload["aud"], "aud")
        self.assertEqual(payload["sub"], "u")
        self.assertEqual(payload["exp"] - payload["iat"], 3600)

    def test_tampered_token_fails_verify(self):
        tok = jwttool.mint_token(self.key, kid="k", issuer="iss", audience="aud", now=1_700_000_000)
        self.assertNotEqual(self._verify(jwttool.tamper_token(tok)), 0,
                            "篡改签名 Token 必须验签失败（对应网关 INVALID → PROTECT 401）")

    def test_short_ttl_rejected(self):
        with self.assertRaises(JWTToolError):
            jwttool.mint_token(self.key, kid="k", issuer="i", audience="a", ttl_seconds=30)


@unittest.skipUnless(HAS_OPENSSL, "openssl 不可用")
class TestCliJwt(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.key = self.dir / "key.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(self.key)],
            check=True, capture_output=True, timeout=60,
        )

    def test_jwt_jwks_cli(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["jwt-jwks", "--key", str(self.key), "--kid", "cli-kid"])
        self.assertEqual(rc, 0)
        jwks = json.loads(buf.getvalue())
        self.assertEqual(jwks["keys"][0]["kid"], "cli-kid")
        self.assertNotIn("d", jwks["keys"][0], "JWKS 不得含私钥参数")

    def test_jwt_mint_cli_writes_0600_headers_without_token_leak(self):
        valid = self.dir / "authorization.header"
        tampered = self.dir / "authorization-tampered.header"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main([
                "jwt-mint", "--key", str(self.key), "--kid", "k",
                "--issuer", "iss", "--audience", "aud", "--ttl", "3600",
                "--out-header", str(valid), "--tamper-out-header", str(tampered),
            ])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertNotIn("Bearer", out, "CLI 输出不得含 Token")
        for f in (valid, tampered):
            self.assertTrue(f.read_text(encoding="utf-8").startswith("Authorization: Bearer "))
            self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        v_tok = valid.read_text().split("Bearer ", 1)[1].strip()
        t_tok = tampered.read_text().split("Bearer ", 1)[1].strip()
        self.assertEqual(v_tok.split(".")[:2], t_tok.split(".")[:2], "篡改版 header/payload 与有效版一致")
        self.assertNotEqual(v_tok.split(".")[2], t_tok.split(".")[2])

    def test_jwt_mint_cli_missing_key_fails(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main([
                "jwt-mint", "--key", str(self.dir / "nope.pem"), "--kid", "k",
                "--issuer", "i", "--audience", "a",
                "--out-header", str(self.dir / "x.header"),
            ])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
