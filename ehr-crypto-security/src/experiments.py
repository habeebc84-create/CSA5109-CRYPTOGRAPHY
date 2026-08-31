"""
Experimental evaluation of cryptographic hash functions and digital signatures
for Electronic Health Record (EHR) security.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from ehr_model import EHR, TAMPERING_SCENARIOS
from crypto_ops import (
    HashAlgorithm,
    SignatureScheme,
    KeyPair,
    SignatureResult,
    VerificationResult,
    compute_hash,
    generate_rsa_keypair,
    generate_ecdsa_keypair,
    sign_ehr,
    verify_ehr,
)


@dataclass
class ExperimentResult:
    config_name: str
    hash_alg: str
    scheme: str
    original_valid: bool
    tamper_results: Dict[str, bool]
    hash_time_ms: float
    sign_time_ms: float
    verify_time_ms: float
    signature_size: int
    original_digest: str
    modified_digest: str  # for prescription change


CONFIGURATIONS = [
    ("C1", HashAlgorithm.SHA256, SignatureScheme.RSA_PSS),
    ("C2", HashAlgorithm.SHA512, SignatureScheme.RSA_PSS),
    ("C3", HashAlgorithm.SHA3_256, SignatureScheme.RSA_PSS),
    ("C4", HashAlgorithm.SHA256, SignatureScheme.ECDSA),
    ("C5", HashAlgorithm.SHA512, SignatureScheme.ECDSA),
    ("C6", HashAlgorithm.SHA3_256, SignatureScheme.ECDSA),
]


def _benchmark_hash(ehr: EHR, alg: HashAlgorithm, runs: int = 100) -> float:
    data = ehr.to_canonical_bytes()
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        compute_hash(data, alg)
        times.append((time.perf_counter() - start) * 1000)
    return statistics.mean(times)


def run_single_config(
    config_id: str,
    hash_alg: HashAlgorithm,
    scheme: SignatureScheme,
    verbose: bool = True,
) -> ExperimentResult:
    """Run the full experiment for one (hash, signature) configuration."""
    ehr = EHR()

    if verbose:
        print("\n" + "=" * 60)
        print(f"CONFIGURATION {config_id}: {hash_alg.value} + {scheme.value}")
        print("=" * 60)
        print(ehr)

    # Key generation
    if scheme == SignatureScheme.RSA_PSS:
        key_pair = generate_rsa_keypair(2048)
    else:
        key_pair = generate_ecdsa_keypair()

    # Hash timing
    hash_time = _benchmark_hash(ehr, hash_alg)

    # Sign original
    sig_result = sign_ehr(ehr, key_pair, hash_alg)
    if verbose:
        print(f"\n[{hash_alg.value}] Digest : {sig_result.digest_hex[:48]}...")
        print(f"Signature size       : {len(sig_result.signature)} bytes")
        print(f"Sign time            : {sig_result.sign_time_ms:.4f} ms")

    # Verify original
    ver_original = verify_ehr(
        ehr, sig_result.signature, key_pair.public_key, scheme, hash_alg
    )
    if verbose:
        print(f"Original verification: {ver_original.message}")
        print(f"Verify time          : {ver_original.verify_time_ms:.4f} ms")

    # Tampering experiments
    tamper_results: Dict[str, bool] = {}
    modified_digest = ""

    for scenario_name, changes in TAMPERING_SCENARIOS.items():
        ehr_mod = ehr.copy()
        for field, value in changes.items():
            setattr(ehr_mod, field, value)

        ver = verify_ehr(
            ehr_mod, sig_result.signature, key_pair.public_key, scheme, hash_alg
        )
        tamper_results[scenario_name] = ver.is_valid

        if scenario_name == "T3_prescription":
            _, modified_digest = compute_hash(ehr_mod.to_canonical_bytes(), hash_alg)

        if verbose and scenario_name != "T1_original":
            status = "VALID (unexpected)" if ver.is_valid else "INVALID (expected)"
            print(f"  {scenario_name:20s} → {status}")

    return ExperimentResult(
        config_name=config_id,
        hash_alg=hash_alg.value,
        scheme=scheme.value,
        original_valid=ver_original.is_valid,
        tamper_results=tamper_results,
        hash_time_ms=hash_time,
        sign_time_ms=sig_result.sign_time_ms,
        verify_time_ms=ver_original.verify_time_ms,
        signature_size=len(sig_result.signature),
        original_digest=sig_result.digest_hex,
        modified_digest=modified_digest,
    )


def run_all_experiments(verbose: bool = True) -> List[ExperimentResult]:
    """Execute the complete experimental suite."""
    results: List[ExperimentResult] = []
    for config_id, hash_alg, scheme in CONFIGURATIONS:
        res = run_single_config(config_id, hash_alg, scheme, verbose=verbose)
        results.append(res)
    return results


def print_summary_table(results: List[ExperimentResult]) -> None:
    """Pretty-print a performance & security summary table."""
    try:
        from tabulate import tabulate
    except ImportError:
        # Fallback without tabulate
        print("\n{:<8} {:<12} {:<10} {:>10} {:>10} {:>10} {:>8} {:>8}".format(
            "Config", "Hash", "Scheme", "Hash(ms)", "Sign(ms)", "Verify(ms)", "Sig(B)", "OrigOK"
        ))
        print("-" * 80)
        for r in results:
            print("{:<8} {:<12} {:<10} {:>10.4f} {:>10.4f} {:>10.4f} {:>8} {:>8}".format(
                r.config_name, r.hash_alg, r.scheme,
                r.hash_time_ms, r.sign_time_ms, r.verify_time_ms,
                r.signature_size, "YES" if r.original_valid else "NO"
            ))
        return

    headers = ["Config", "Hash", "Scheme", "Hash (ms)", "Sign (ms)", "Verify (ms)", "Sig Size", "Original OK"]
    rows = []
    for r in results:
        rows.append([
            r.config_name,
            r.hash_alg,
            r.scheme,
            f"{r.hash_time_ms:.4f}",
            f"{r.sign_time_ms:.4f}",
            f"{r.verify_time_ms:.4f}",
            r.signature_size,
            "YES" if r.original_valid else "NO",
        ])
    print("\n" + tabulate(rows, headers=headers, tablefmt="grid"))

    # Tamper detection summary
    print("\nTamper Detection (all configurations should detect changes):")
    for r in results:
        detected = all(not v for k, v in r.tamper_results.items() if k != "T1_original")
        print(f"  {r.config_name}: {'ALL TAMPERS DETECTED' if detected else 'SOME MISSED'}")


def print_hash_sensitivity(results: List[ExperimentResult]) -> None:
    """Show that a single-character dosage change produces completely different hashes."""
    print("\n" + "=" * 60)
    print("HASH SENSITIVITY – Prescription: 5 mg → 50 mg")
    print("=" * 60)
    for r in results:
        if r.hash_alg in ("SHA-256", "SHA-512", "SHA3-256"):
            print(f"\n{r.hash_alg}")
            print(f"  Original : {r.original_digest}")
            print(f"  Modified : {r.modified_digest}")
            print(f"  Match    : {'YES' if r.original_digest == r.modified_digest else 'NO'}")
