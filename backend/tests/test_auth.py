"""挑战签名与票据的单元测试。"""

from __future__ import annotations

import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import auth


def make_key():
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": auth.b64u(nums.x.to_bytes(32, "big")),
        "y": auth.b64u(nums.y.to_bytes(32, "big")),
    }
    return key, jwk


def sign_raw(key, message: bytes) -> bytes:
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_verify_roundtrip():
    key, jwk = make_key()
    message = b"\x01" * 32 + b"a1b2c3d4e5f60718"
    assert auth.verify_signature(jwk, message, sign_raw(key, message))


def test_other_message_fails():
    key, jwk = make_key()
    sig = sign_raw(key, b"original")
    assert not auth.verify_signature(jwk, b"tampered", sig)


def test_other_key_fails():
    key, _ = make_key()
    _, jwk2 = make_key()
    sig = sign_raw(key, b"msg")
    assert not auth.verify_signature(jwk2, b"msg", sig)


def test_bad_signature_length():
    _, jwk = make_key()
    assert not auth.verify_signature(jwk, b"msg", b"\x00" * 63)


def test_thumbprint_ignores_key_order():
    _, jwk = make_key()
    shuffled = {k: jwk[k] for k in ("y", "x", "crv", "kty")}
    assert auth.thumbprint(jwk) == auth.thumbprint(shuffled)


def test_ticket_roundtrip():
    secret = b"k" * 32
    ticket = auth.issue_ticket(secret, {"user": "alice", "exp": int(time.time()) + 60})
    payload = auth.verify_ticket(secret, ticket)
    assert payload and payload["user"] == "alice"


def test_ticket_tampered_or_expired():
    secret = b"k" * 32
    ticket = auth.issue_ticket(secret, {"exp": int(time.time()) + 60})
    body, mac = ticket.split(".")
    assert auth.verify_ticket(secret, body + "." + mac[:-2] + "AA") is None
    assert auth.verify_ticket(b"other", ticket) is None
    old = auth.issue_ticket(secret, {"exp": int(time.time()) - 1})
    assert auth.verify_ticket(secret, old) is None
