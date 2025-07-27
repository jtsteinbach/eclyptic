# Eclyptic

**Version**: 1.1.0\
**License**: MIT 2025\
**Developer**: [jts.gg/eclyptic](https://jts.gg/eclyptic)

---

Recursive ECC is a lightweight Python library that implements an ECIES‑style encryption scheme using:

- **Elliptic‑Curve Diffie‑Hellman (ECDH)** for key agreement
- **HKDF‑SHA256** for symmetric key derivation
- **AES‑GCM** for authenticated encryption

It’s designed for ease of use, forward secrecy, and support for arbitrary binary payloads.

## Features

- Generate ECC keypairs on common curves (default: `secp256r1`).
- Encrypt data to a recipient’s public key using a fresh ephemeral key per message.
- Decrypt encrypted blobs to recover raw bytes (caller handles UTF‑8 decoding).
- Zero external dependencies beyond `cryptography`.

## Installation

```bash
# Install from PyPI (when published):
pip install recursive-ecc

# Or install directly from GitHub:
git clone https://github.com/jtsteinbach/eclyptic.git
cd eclyptic
pip install .
```

## Quick Start
```
pip3 install eclyptic
```

```python
import eclyptic

data = "secret data"

# 1️⃣ Generate a keypair
priv, pub = eclyptic.keypair()

# 2️⃣ Encrypt some data (bytes or string)
encrypted_data = eclyptic.encrypt(pub, data)

# 3️⃣ Decrypt back into raw bytes
decrypted_data = eclyptic.decrypt(priv, encrypted_data)
# If you need a string:
text_string = decrypted_data.decode('utf-8')
```

## API Reference

### `keypair(curve: str = 'secp256r1') -> (EllipticCurvePrivateKey, EllipticCurvePublicKey)`

Generate a new ECC private/public keypair on the specified curve.

- **Parameters**:
  - `curve`: Name of the curve (e.g. `'secp256r1'`, `'secp384r1'`).
- **Returns**: Tuple `(private_key, public_key)`.

### `encrypt(pub, plaintext: bytes \| str) -> bytes`

Encrypt a message using ECIES:

- **Parameters**:
  - `pub`: An `EllipticCurvePublicKey` object or path to a DER‑encoded public key file.
  - `plaintext`: The payload to encrypt (`bytes` or UTF‑8 `str`).
- **Returns**: A single `bytes` blob containing:
  1. 4‑byte length of the ephemeral public key
  2. Ephemeral public key (X9.62 uncompressed)
  3. 12‑byte AES‑GCM nonce
  4. AES‑GCM ciphertext + authentication tag

### `decrypt(priv, ciphertext: bytes) -> bytes`

Decrypt a blob produced by `encrypt()`:

- **Parameters**:
  - `priv`: An `EllipticCurvePrivateKey` object or path to a DER‑encoded private key file.
  - `ciphertext`: The `bytes` blob returned by `encrypt()`.
- **Returns**: Raw decrypted `bytes`. Use `.decode('utf-8')` if you know the payload was text.

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request on [GitHub](https://github.com/jtsteinbach/eclyptic).

## License

This project is licensed under the MIT License © 2025 JT Steinbach.

