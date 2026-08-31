# Evaluation of Cryptographic Hash Functions and Digital Signatures in Electronic Health Record Security

**Academic Assignment Report & Implementation**  
Course Outcomes: **CO2**, **CO3** | Bloom’s Taxonomy: **BL5 – Evaluate**  
SDG Mapping: **SDG 3**, **SDG 9**, **SDG 16**

---

## Overview

This project experimentally evaluates cryptographic hash functions and digital signature schemes for protecting the **integrity** and **authenticity** of Electronic Health Records (EHRs).

Synthetic EHR records are created, digitally signed, and then deliberately tampered with. Signature verification is used to detect unauthorized modifications (e.g., changing a prescription from `Amlodipine 5 mg` to `Amlodipine 50 mg`).

### Algorithms Evaluated

| Configuration | Hash Algorithm | Signature Scheme |
|---------------|----------------|------------------|
| C1            | SHA-256        | RSA-PSS (2048)   |
| C2            | SHA-512        | RSA-PSS (2048)   |
| C3            | SHA3-256       | RSA-PSS (2048)   |
| C4            | SHA-256        | ECDSA (P-256)    |
| C5            | SHA-512        | ECDSA (P-256)    |
| C6            | SHA3-256       | ECDSA (P-256)    |

### Security Properties Demonstrated

- **Data Integrity** – any change to the signed EHR produces a different hash → verification fails
- **Source Authentication** – only the holder of the private key can produce a valid signature
- **Non-repudiation** – with proper key management the signer cannot deny having signed the record
- **Tamper Detection** – controlled experiments on diagnosis, prescription, doctor ID, patient ID, lab results

> **Note:** Hashing + digital signatures do **not** provide confidentiality. Encryption (e.g. AES) would be required for that.

---

## Project Structure

```
ehr-crypto-security/
├── src/
│   ├── ehr_model.py      # Synthetic EHR data model + tampering scenarios
│   ├── crypto_ops.py     # Hash, key generation, sign, verify
│   ├── experiments.py    # Full experimental suite & benchmarks
│   └── main.py           # CLI entry point
├── assets/               # Architecture diagrams & result figures
├── results/              # (optional) output logs / CSV
├── docs/                 # Additional documentation
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Demo (sign → modify → detect)

```bash
cd src
python main.py --demo
```

Example output:

```
[3] Verifying original EHR ...
    → AUTHENTIC EHR – VERIFICATION SUCCESS

[4] Simulating unauthorized modification ...
    Original prescription : Amlodipine 5 mg
    Modified prescription : Amlodipine 50 mg

[5] Verifying modified EHR ...
    → TAMPERING DETECTED – VERIFICATION FAILED
    Document Status : INVALID
    Action          : EHR REJECTED
```

### 2. Full experimental suite (all 6 configurations)

```bash
python main.py --all
```

### 3. Single configuration

```bash
python main.py --config C4          # SHA-256 + ECDSA
python main.py --config C1 --quiet  # quieter output
```

---

## Methodology

1. **EHR Creation** – synthetic patient record
2. **Hash Generation** – SHA-256 / SHA-512 / SHA3-256
3. **Key Generation** – RSA-PSS (2048-bit) or ECDSA (SECP256R1)
4. **Digital Signature** – sign with private key
5. **Transmission** – simulated
6. **Tampering** – modify selected fields
7. **Verification** – verify with public key → Accept / Reject

---

## Sample Performance (illustrative)

| Configuration       | Hash (ms) | Sign (ms) | Verify (ms) | Sig Size |
|---------------------|-----------|-----------|-------------|----------|
| SHA-256 + RSA-PSS   | ~0.001    | ~0.52     | ~0.49       | 256 B    |
| SHA-512 + RSA-PSS   | ~0.0013   | ~0.53     | ~0.50       | 256 B    |
| SHA3-256 + RSA-PSS  | ~0.0017   | ~0.54     | ~0.51       | 256 B    |
| SHA-256 + ECDSA     | ~0.001    | ~0.04     | ~0.13       | ~70 B    |
| SHA-512 + ECDSA     | ~0.0013   | ~0.04     | ~0.13       | ~70 B    |
| SHA3-256 + ECDSA    | ~0.0017   | ~0.04     | ~0.13       | ~70 B    |

*Values depend on hardware and Python version. Run the experiments on your machine for accurate numbers.*

---

## Important Academic Notes

- **Synthetic data only** – no real patient information is used.
- Private keys are generated in-memory and never persisted in the demo.
- This is a **prototype** focused on integrity & authentication. A production healthcare system also needs encryption, PKI, access control, audit logging, etc.

---

## References

1. NIST FIPS 180-4 – Secure Hash Standard (SHS)
2. NIST FIPS 202 – SHA-3 Standard
3. NIST FIPS 186-5 – Digital Signature Standard (DSS)
4. RFC 8017 – PKCS #1: RSA Cryptography Specifications
5. Python `cryptography` library documentation

---

## License

This project is released for **academic / educational purposes**.
