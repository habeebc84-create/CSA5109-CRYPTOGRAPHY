"""
Cryptographic operations for EHR integrity and authentication.

Supported hash algorithms : SHA-256, SHA-512, SHA3-256
Supported signature schemes: RSA-PSS (2048-bit), ECDSA (SECP256R1)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

from ehr_model import EHR


class HashAlgorithm(str, Enum):
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    SHA3_256 = "SHA3-256"


class SignatureScheme(str, Enum):
    RSA_PSS = "RSA-PSS"
    ECDSA = "ECDSA"


@dataclass
class KeyPair:
    private_key: object
    public_key: object
    scheme: SignatureScheme
    key_size_bits: int


@dataclass
class SignatureResult:
    signature: bytes
    hash_algorithm: HashAlgorithm
    scheme: SignatureScheme
    sign_time_ms: float
    digest: bytes
    digest_hex: str


@dataclass
class VerificationResult:
    is_valid: bool
    message: str
    verify_time_ms: float
    received_digest_hex: str


def _get_hash_function(alg: HashAlgorithm):
    mapping = {
        HashAlgorithm.SHA256: hashlib.sha256,
        HashAlgorithm.SHA512: hashlib.sha512,
        HashAlgorithm.SHA3_256: hashlib.sha3_256,
    }
    return mapping[alg]


def _get_crypto_hash(alg: HashAlgorithm):
    mapping = {
        HashAlgorithm.SHA256: hashes.SHA256(),
        HashAlgorithm.SHA512: hashes.SHA512(),
        HashAlgorithm.SHA3_256: hashes.SHA3_256(),
    }
    return mapping[alg]


def compute_hash(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> Tuple[bytes, str]:
    """Compute cryptographic hash of data. Returns (digest_bytes, hex_string)."""
    h = _get_hash_function(algorithm)(data)
    digest = h.digest()
    return digest, digest.hex()


def generate_rsa_keypair(key_size: int = 2048) -> KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return KeyPair(
        private_key=private_key,
        public_key=private_key.public_key(),
        scheme=SignatureScheme.RSA_PSS,
        key_size_bits=key_size,
    )


def generate_ecdsa_keypair(curve=ec.SECP256R1()) -> KeyPair:
    private_key = ec.generate_private_key(curve)
    return KeyPair(
        private_key=private_key,
        public_key=private_key.public_key(),
        scheme=SignatureScheme.ECDSA,
        key_size_bits=256,  # for SECP256R1
    )


def sign_ehr(
    ehr: EHR,
    key_pair: KeyPair,
    hash_alg: HashAlgorithm = HashAlgorithm.SHA256,
) -> SignatureResult:
    """Digitally sign an EHR using the private key."""
    data = ehr.to_canonical_bytes()
    digest, digest_hex = compute_hash(data, hash_alg)
    crypto_hash = _get_crypto_hash(hash_alg)

    start = time.perf_counter()

    if key_pair.scheme == SignatureScheme.RSA_PSS:
        assert isinstance(key_pair.private_key, RSAPrivateKey)
        signature = key_pair.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(crypto_hash),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            crypto_hash,
        )
    elif key_pair.scheme == SignatureScheme.ECDSA:
        assert isinstance(key_pair.private_key, EllipticCurvePrivateKey)
        signature = key_pair.private_key.sign(data, ec.ECDSA(crypto_hash))
    else:
        raise ValueError(f"Unsupported scheme: {key_pair.scheme}")

    elapsed_ms = (time.perf_counter() - start) * 1000

    return SignatureResult(
        signature=signature,
        hash_algorithm=hash_alg,
        scheme=key_pair.scheme,
        sign_time_ms=elapsed_ms,
        digest=digest,
        digest_hex=digest_hex,
    )


def verify_ehr(
    ehr: EHR,
    signature: bytes,
    public_key,
    scheme: SignatureScheme,
    hash_alg: HashAlgorithm = HashAlgorithm.SHA256,
) -> VerificationResult:
    """Verify a digital signature on an EHR using the public key."""
    data = ehr.to_canonical_bytes()
    _, received_digest_hex = compute_hash(data, hash_alg)
    crypto_hash = _get_crypto_hash(hash_alg)

    start = time.perf_counter()
    is_valid = False
    message = ""

    try:
        if scheme == SignatureScheme.RSA_PSS:
            assert isinstance(public_key, RSAPublicKey)
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(crypto_hash),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                crypto_hash,
            )
            is_valid = True
            message = "AUTHENTIC EHR – VERIFICATION SUCCESS"
        elif scheme == SignatureScheme.ECDSA:
            assert isinstance(public_key, EllipticCurvePublicKey)
            public_key.verify(signature, data, ec.ECDSA(crypto_hash))
            is_valid = True
            message = "AUTHENTIC EHR – VERIFICATION SUCCESS"
        else:
            message = f"Unsupported scheme: {scheme}"
    except InvalidSignature:
        is_valid = False
        message = "TAMPERING DETECTED – VERIFICATION FAILED"
    except Exception as exc:
        is_valid = False
        message = f"Verification error: {exc}"

    elapsed_ms = (time.perf_counter() - start) * 1000

    return VerificationResult(
        is_valid=is_valid,
        message=message,
        verify_time_ms=elapsed_ms,
        received_digest_hex=received_digest_hex,
    )


def export_public_key_pem(public_key) -> bytes:
    """Export public key in PEM format (for sharing / storage)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def export_private_key_pem(private_key, password: Optional[bytes] = None) -> bytes:
    """Export private key in PEM format (password-protected recommended)."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
