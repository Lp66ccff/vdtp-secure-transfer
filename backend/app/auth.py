"""挑战签名、公钥指纹与会话票据。

浏览器用 WebCrypto 生成 ECDSA P-256 密钥对，签名是裸的 r‖s（64 字节）；
这里转成 DER 交给 cryptography 验。票据用服务端密钥签 HMAC-SHA256。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def ub64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_to_public(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("只收 EC P-256 公钥")
    x = int.from_bytes(ub64u(jwk["x"]), "big")
    y = int.from_bytes(ub64u(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def thumbprint(jwk: dict) -> str:
    """公钥指纹：RFC 7638 的键集合，SHA-256，base64url。"""
    canon = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    raw = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(raw).digest())


def raw_to_der(sig: bytes) -> bytes:
    if len(sig) != 64:
        raise ValueError("ECDSA P-256 的裸签名应为 64 字节")
    def enc_int(value: int) -> bytes:
        body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if body[0] & 0x80:
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body
    body = enc_int(int.from_bytes(sig[:32], "big")) + enc_int(int.from_bytes(sig[32:], "big"))
    return b"\x30" + bytes([len(body)]) + body


def verify_signature(jwk: dict, message: bytes, sig_raw: bytes) -> bool:
    try:
        key = jwk_to_public(jwk)
        key.verify(raw_to_der(sig_raw), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


# ---------------------------------------------------------------- 票据
def issue_ticket(secret: bytes, payload: dict) -> str:
    body = b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    mac = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    return f"{body}.{b64u(mac)}"


def verify_ticket(secret: bytes, ticket: str, now: float | None = None) -> dict | None:
    try:
        body, mac = ticket.split(".", 1)
    except ValueError:
        return None
    want = b64u(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(mac, want):
        return None
    try:
        payload = json.loads(ub64u(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if float(payload.get("exp", 0)) < (now or time.time()):
        return None
    return payload
