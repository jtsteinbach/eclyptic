# Eclyptic Asymmetric Encryption

**Version**: 1.2.0
**License**: [LICENSE](https://r2.jts.gg/license)
**Developer**: [jts.gg/eclyptic](https://jts.gg/eclyptic)

---

Eclyptic is a lightweight Python library that implements a streamlined ECIES‑style encryption scheme utilizing:

* **Elliptic‑Curve Diffie‑Hellman (ECDH)** for key agreement
* **HKDF‑SHA256** for symmetric key derivation
* **AES‑GCM** for authenticated encryption
* **Compressed ECC public keys** with compact **Base64 URL-safe encoding** (no padding)

Designed for ease of use, forward secrecy, and efficiency with arbitrary binary and text payloads.

## Installation

```bash
# Install from PyPI
pip3 install eclyptic
```

## Quick Start

```python
import eclyptic

# 1️⃣ Generate a compact Base64-encoded keypair
priv, pub = eclyptic.keypair()

# 2️⃣ Encrypt data (bytes or UTF-8 string)
data = "secret data"
encrypted_data = eclyptic.encrypt(pub, data)

# 3️⃣ Decrypt back into raw bytes or UTF-8 text
decrypted_bytes = eclyptic.decrypt(priv, encrypted_data)
plaintext = decrypted_bytes.decode('utf-8')
```

## API Reference

### `keypair(curve_name: str = 'secp256r1') -> tuple[str, str]`

Generates a new ECC private/public keypair on the specified curve, returning keys as Base64 URL-safe strings.

* **Parameters**:

  * `curve_name`: ECC curve identifier (`'secp256r1'` by default).
* **Returns**: Tuple `(priv_b64, pub_b64)`:

  * `priv_b64`: Base64-encoded private scalar.
  * `pub_b64`: Base64-encoded compressed public key.

### `encrypt(pub_b64: str, plaintext: bytes | str) -> bytes`

Encrypts a message using ECIES with a compressed ephemeral public key.

* **Parameters**:

  * `pub_b64`: Base64-encoded compressed public key.
  * `plaintext`: Payload to encrypt (`bytes` or UTF‑8 `str`).
* **Returns**: Single `bytes` blob containing:

  1. 2-byte length of ephemeral public key
  2. Compressed ephemeral public key (X9.62)
  3. 12-byte AES‑GCM nonce
  4. AES‑GCM ciphertext with authentication tag

### `decrypt(priv_b64: str, ciphertext: bytes) -> bytes`

Decrypts ciphertext produced by `encrypt()`.

* **Parameters**:

  * `priv_b64`: Base64-encoded private scalar.
  * `ciphertext`: Ciphertext blob from `encrypt()`.
* **Returns**: Decrypted `bytes`. Use `.decode('utf-8')` for text.

