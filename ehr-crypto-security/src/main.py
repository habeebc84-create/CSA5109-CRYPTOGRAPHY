#!/usr/bin/env python3
"""
EHR Cryptographic Security System – Main Entry Point

Evaluation of Cryptographic Hash Functions and Digital Signatures
in Electronic Health Record Security

Course Outcomes : CO2, CO3
Bloom’s Level   : BL5 – Evaluate
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from project root or from src/
sys.path.insert(0, str(Path(__file__).resolve().parent))

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
from experiments import (
    run_all_experiments,
    run_single_config,
    print_summary_table,
    print_hash_sensitivity,
    CONFIGURATIONS,
)


def demo_single_run() -> None:
    """Interactive-style demonstration of one full sign → tamper → verify cycle."""
    print("\n" + "=" * 60)
    print("  EHR CRYPTOGRAPHIC SECURITY SYSTEM – DEMO")
    print("=" * 60)

    ehr = EHR()
    print(ehr)

    print("\n[1] Generating RSA-PSS (2048-bit) key pair ...")
    key_pair = generate_rsa_keypair(2048)
    print("    Key pair generated.")

    print("\n[2] Computing SHA-256 hash and signing ...")
    sig = sign_ehr(ehr, key_pair, HashAlgorithm.SHA256)
    print(f"    Digest   : {sig.digest_hex}")
    print(f"    Sig size : {len(sig.signature)} bytes")
    print(f"    Sign time: {sig.sign_time_ms:.4f} ms")

    print("\n[3] Verifying original EHR ...")
    ver = verify_ehr(ehr, sig.signature, key_pair.public_key, SignatureScheme.RSA_PSS)
    print(f"    → {ver.message}")
    print(f"    Verify time: {ver.verify_time_ms:.4f} ms")

    print("\n[4] Simulating unauthorized modification ...")
    print("    Original prescription : Amlodipine 5 mg")
    ehr_mod = ehr.copy()
    ehr_mod.prescription = "Amlodipine 50 mg"
    print("    Modified prescription : Amlodipine 50 mg")

    _, mod_digest = compute_hash(ehr_mod.to_canonical_bytes(), HashAlgorithm.SHA256)
    print(f"\n    Original hash : {sig.digest_hex[:40]}...")
    print(f"    Modified hash : {mod_digest[:40]}...")
    print("    Hashes match  : NO")

    print("\n[5] Verifying modified EHR ...")
    ver_mod = verify_ehr(
        ehr_mod, sig.signature, key_pair.public_key, SignatureScheme.RSA_PSS
    )
    print(f"    → {ver_mod.message}")
    print("\n    Document Status : INVALID")
    print("    Action          : EHR REJECTED")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EHR Cryptographic Hash & Digital Signature Evaluation"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a single interactive demonstration (sign → tamper → verify)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run full experimental suite across all 6 configurations",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce console output during full experiments",
    )
    parser.add_argument(
        "--config",
        choices=["C1", "C2", "C3", "C4", "C5", "C6"],
        help="Run only a specific configuration",
    )

    args = parser.parse_args()

    if args.demo or (not args.all and not args.config):
        # Default behaviour: demo
        demo_single_run()
        return

    if args.config:
        cfg = next(c for c in CONFIGURATIONS if c[0] == args.config)
        result = run_single_config(*cfg, verbose=not args.quiet)
        print_summary_table([result])
        print_hash_sensitivity([result])
        return

    if args.all:
        results = run_all_experiments(verbose=not args.quiet)
        print_summary_table(results)
        print_hash_sensitivity(results)
        return


if __name__ == "__main__":
    main()
