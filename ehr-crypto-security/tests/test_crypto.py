"""
Basic unit tests for the EHR cryptographic operations.
Run with:  python -m pytest tests/  (or simply python tests/test_crypto.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ehr_model import EHR
from crypto_ops import (
    HashAlgorithm,
    SignatureScheme,
    generate_rsa_keypair,
    generate_ecdsa_keypair,
    sign_ehr,
    verify_ehr,
    compute_hash,
)


def test_hash_deterministic():
    ehr = EHR()
    d1, h1 = compute_hash(ehr.to_canonical_bytes(), HashAlgorithm.SHA256)
    d2, h2 = compute_hash(ehr.to_canonical_bytes(), HashAlgorithm.SHA256)
    assert h1 == h2
    assert d1 == d2


def test_hash_sensitivity():
    ehr = EHR()
    ehr_mod = ehr.copy()
    ehr_mod.prescription = "Amlodipine 50 mg"
    _, h1 = compute_hash(ehr.to_canonical_bytes(), HashAlgorithm.SHA256)
    _, h2 = compute_hash(ehr_mod.to_canonical_bytes(), HashAlgorithm.SHA256)
    assert h1 != h2


def test_rsa_sign_verify_original():
    ehr = EHR()
    kp = generate_rsa_keypair(2048)
    sig = sign_ehr(ehr, kp, HashAlgorithm.SHA256)
    ver = verify_ehr(ehr, sig.signature, kp.public_key, SignatureScheme.RSA_PSS)
    assert ver.is_valid is True


def test_rsa_detects_tampering():
    ehr = EHR()
    kp = generate_rsa_keypair(2048)
    sig = sign_ehr(ehr, kp, HashAlgorithm.SHA256)

    ehr_mod = ehr.copy()
    ehr_mod.prescription = "Amlodipine 50 mg"
    ver = verify_ehr(ehr_mod, sig.signature, kp.public_key, SignatureScheme.RSA_PSS)
    assert ver.is_valid is False


def test_ecdsa_sign_verify_original():
    ehr = EHR()
    kp = generate_ecdsa_keypair()
    sig = sign_ehr(ehr, kp, HashAlgorithm.SHA256)
    ver = verify_ehr(ehr, sig.signature, kp.public_key, SignatureScheme.ECDSA)
    assert ver.is_valid is True


def test_ecdsa_detects_tampering():
    ehr = EHR()
    kp = generate_ecdsa_keypair()
    sig = sign_ehr(ehr, kp, HashAlgorithm.SHA3_256)

    ehr_mod = ehr.copy()
    ehr_mod.diagnosis = "Diabetes"
    ver = verify_ehr(ehr_mod, sig.signature, kp.public_key, SignatureScheme.ECDSA, HashAlgorithm.SHA3_256)
    assert ver.is_valid is False


if __name__ == "__main__":
    # Simple runner without pytest
    tests = [
        test_hash_deterministic,
        test_hash_sensitivity,
        test_rsa_sign_verify_original,
        test_rsa_detects_tampering,
        test_ecdsa_sign_verify_original,
        test_ecdsa_detects_tampering,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"[PASS] {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
        except Exception as e:
            print(f"[ERROR] {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed.")
