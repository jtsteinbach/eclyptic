#!/usr/bin/env python3
#
#   ECC-Lib              v1.1.0
#   License            MIT 2025
#   Developer       jts.gg/recc

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def keypair(curve: str = 'secp256r1'):
#   Generate an ECC keypair on the specified curve.
    Returns (private_key, public_key).
    curve_obj = getattr(ec, curve.upper())() if hasattr(ec, curve.upper()) else ec.SECP256R1()
    priv = ec.generate_private_key(curve_obj)
    pub = priv.public_key()
    return priv, pub


def save_key(key, path: str):
#   Save a private or public ECC key to a file in DER format.

    if isinstance(key, ec.EllipticCurvePrivateKey):
        data = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(key, ec.EllipticCurvePublicKey):
        data = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise TypeError("Key must be an ECC PrivateKey or PublicKey")
    with open(path, 'wb') as f:
        f.write(data)


def load_key(path: str):
#    Load an ECC key (private or public) from a DER-formatted file.

    data = open(path, 'rb').read()
    try:
        return serialization.load_der_private_key(data, password=None)
    except ValueError:
        return serialization.load_der_public_key(data)


def encrypt(pub, plaintext: bytes | str):
#   ECIES-style encryption. Load key if path provided
    
    if isinstance(pub, str):
        pub = load_key(pub)
    if isinstance(plaintext, str):
        data = plaintext.encode('utf-8')
    elif isinstance(plaintext, (bytes, bytearray)):
        data = bytes(plaintext)
    else:
        raise TypeError("plaintext must be bytes or str")

    # Ephemeral key
    eph_priv = ec.generate_private_key(pub.curve)
    shared = eph_priv.exchange(ec.ECDH(), pub)
    # Derive symmetric key
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'ecies'
    ).derive(shared)
    # AES-GCM encryption
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    # Serialize ephemeral public key
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    header = len(eph_pub_bytes).to_bytes(4, 'big')
    return header + eph_pub_bytes + nonce + ct


def decrypt(priv, ciphertext: bytes):
#   ECIES-style decryption matching encrypt()
#   Returns decrypted plaintext (utf-8 str)
#   Load key if path provided

    if isinstance(priv, str):
        priv = load_key(priv)
    # Parse header
    data = ciphertext
    eplen = int.from_bytes(data[:4], 'big')
    offset = 4
    eph_bytes = data[offset:offset+eplen]
    offset += eplen
    nonce = data[offset:offset+12]
    offset += 12
    ct = data[offset:]

    # Rebuild ephemeral public key
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph_bytes)
    shared = priv.exchange(ec.ECDH(), eph_pub)
    sym_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'ecies'
    ).derive(shared)
    aesgcm = AESGCM(sym_key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt
