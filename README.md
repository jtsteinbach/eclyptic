# ECC-Lib

> **ECC-Lib** is a simple, production-ready Python library implementing ECIES-style encryption (ECDH + AES-GCM) using standard curves. Perfect for applications needing high-performance asymmetric encryption with minimal dependencies.

---

## 🌟 Features

- **Keypair generation** on any NIST/SECG curve (default: `secp256r1`).
- **Save/load** keys in **DER** format (private or public).
- **Encrypt/decrypt** arbitrary data or UTF-8 text via ECIES:
  - Ephemeral key exchange (ECDH)
  - HKDF key derivation (SHA‑256)
  - AES‑GCM authenticated encryption
- **Zero external dependencies** beyond the `cryptography` package.
- **ThreadPoolExecutor** stub in place for easy parallel streaming.

---

## 📦 Installation

```bash
pip install cryptography
# then include ecc.py in your project, or install via:
# pip install path/to/ecc-lib
```


---

## 🚀 Quickstart

```python
import ecc

# 1️⃣ Generate keypair
priv, pub = ecc.keypair(curve='secp256r1')

# 2️⃣ Save keys
ecc.save_key(priv, 'ec_private.der')
ecc.save_key(pub,  'ec_public.der')

# 3️⃣ Load them later
priv2 = ecc.load_key('ec_private.der')
pub2  = ecc.load_key('ec_public.der')

# 4️⃣ Encrypt & decrypt a message
msg = "Hello, ECC!"
ct  = ecc.encrypt(pub2, msg)
pt  = ecc.decrypt(priv2, ct)

assert pt == msg
```

---

## 📚 API Reference

### `keypair(curve: str = 'secp256r1') -> (priv, pub)`

Generate an EC private/public key pair.

- **Parameters**:
  - `curve` – name of curve class (e.g. `secp256r1`, `secp384r1`, `secp521r1`).
- **Returns**: `(EllipticCurvePrivateKey, EllipticCurvePublicKey)`


### `save_key(key, path: str) -> None`

Write an ECC key to disk in DER format.

- **Parameters**:
  - `key` – private or public key object.
  - `path` – output filename (e.g. `key.der`).


### `load_key(path: str) -> key`

Read a DER‐encoded ECC key (private or public).

- **Parameters**:
  - `path` – DER file to read.
- **Returns**: Loaded key object.


### `encrypt(pub, plaintext: str | bytes) -> bytes`

Perform ECIES encryption.

- **Parameters**:
  - `pub` – public key object or path to `.der` file.
  - `plaintext` – UTF-8 string or raw bytes.
- **Returns**: Single ciphertext blob:
  ```text
  [4-byte eph_pub_len] [eph_pub_bytes] [12B nonce] [ciphertext]
  ```


### `decrypt(priv, ciphertext: bytes) -> str`

Reverse the ECIES encryption.

- **Parameters**:
  - `priv` – private key object or path to `.der` file.
  - `ciphertext` – blob from `encrypt()`.
- **Returns**: Decrypted UTF-8 string.


---

## 🔧 File Formats

- **DER**: Binary ASN.1 encoding (PKCS#8 for private, SPKI for public).
- **Ciphertext blob**:
  1. 4‑byte big‑endian length of ephemeral public key
  2. Ephemeral public key bytes
  3. 12‑byte AES-GCM nonce
  4. Encrypted & authenticated ciphertext

---

## 👩‍💻 Examples

- See [example_ecc_usage.py](examples/example_ecc_usage.py) for a full demo
- Round‑trip UTF‑8 text & raw bytes

---

## 🔒 Security Notes

- Always use fresh ephemeral keys per message.
- Protect private `.der` files with filesystem permissions.
- Use a secure random source (`os.urandom`).

---

## 📝 License

Released under the **MIT License**. See [LICENSE](LICENSE).

