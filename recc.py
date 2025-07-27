#!/usr/bin/env python3
# ──────────────────────────────
#   Recursive ECC        v1.1.0
#   Author          jts.gg/recc
#   License   r2.jts.gg/license
# ──────────────────────────────

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ────── generate ECC keypair ──────
def keypair(curve: str = 'secp256r1'):
    curve_obj = getattr(ec, curve.upper())() if hasattr(ec, curve.upper()) else ec.SECP256R1()
    priv = ec.generate_private_key(curve_obj)
    pub = priv.public_key()
    return priv, pub

# ────── ECIES-style encryption ──────
def encrypt(pub, plaintext: bytes | str):
    if isinstance(plaintext, str):
        data = plaintext.encode('utf-8')
    elif isinstance(plaintext, (bytes, bytearray)):
        data = bytes(plaintext)
    else:
        raise TypeError("plaintext must be bytes or str")

    # ephemeral key
    eph_priv = ec.generate_private_key(pub.curve)
    shared = eph_priv.exchange(ec.ECDH(), pub)
    # derive symmetric key
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'ecies'
    ).derive(shared)
    # AES-GCM encryption
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    # serialize ephemeral public key
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    header = len(eph_pub_bytes).to_bytes(4, 'big')
    return header + eph_pub_bytes + nonce + ct

# ────── ECIES-style decryption ──────
def decrypt(priv, ciphertext: bytes):
    # parse header
    data = ciphertext
    eplen = int.from_bytes(data[:4], 'big')
    offset = 4
    eph_bytes = data[offset:offset+eplen]
    offset += eplen
    nonce = data[offset:offset+12]
    offset += 12
    ct = data[offset:]

    # rebuild ephemeral public key
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph_bytes)
    shared = priv.exchange(ec.ECDH(), eph_pub)
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'ecies'
    ).derive(shared)
    aesgcm = AESGCM(sym_key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt
