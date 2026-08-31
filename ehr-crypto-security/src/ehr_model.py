"""
Synthetic Electronic Health Record (EHR) model.

All data is fictional and used only for academic experimentation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict


@dataclass
class EHR:
    """Represents a synthetic Electronic Health Record."""

    patient_id: str = "P1001"
    patient_name: str = "Sample Patient"
    age: int = 46
    diagnosis: str = "Hypertension"
    prescription: str = "Amlodipine 5 mg"
    doctor_id: str = "DOC204"
    hospital: str = "SecureCare Telemedicine Centre"
    lab_result: str = "Blood Pressure 150/95"
    record_date: str = "31-08-2026"

    def to_dict(self) -> Dict[str, Any]:
        """Return a sorted dictionary representation for consistent hashing."""
        return asdict(self)

    def to_canonical_bytes(self) -> bytes:
        """
        Serialize the EHR into a deterministic byte string.
        Using sorted keys guarantees the same hash for the same content.
        """
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def copy(self) -> "EHR":
        """Return a deep-ish copy of the record."""
        return EHR(**self.to_dict())

    def __str__(self) -> str:
        lines = [
            "==================================================",
            "ELECTRONIC HEALTH RECORD",
            "==================================================",
            f"Patient ID        : {self.patient_id}",
            f"Patient Name      : {self.patient_name}",
            f"Age               : {self.age}",
            f"Diagnosis         : {self.diagnosis}",
            f"Prescription      : {self.prescription}",
            f"Doctor ID         : {self.doctor_id}",
            f"Hospital          : {self.hospital}",
            f"Laboratory Result : {self.lab_result}",
            f"Record Date       : {self.record_date}",
            "==================================================",
        ]
        return "\n".join(lines)


# Pre-defined tampering scenarios used in experiments
TAMPERING_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "T1_original": {},  # no change
    "T2_diagnosis": {"diagnosis": "Diabetes"},
    "T3_prescription": {"prescription": "Amlodipine 50 mg"},
    "T4_doctor_id": {"doctor_id": "DOC999"},
    "T5_patient_id": {"patient_id": "P9001"},
    "T6_lab_result": {"lab_result": "Blood Pressure 120/80"},
}
