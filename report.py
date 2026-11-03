"""
report.py
=========

Report generation and export functionality for password analysis
results. Supports building a human-readable summary and exporting
results as both ``.txt`` and ``.json`` files.

No plaintext passwords are ever written to disk by this module — only
masked representations and the analysis metadata.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import List

from src.checker import PasswordAnalysis
from src.utils import REPORTS_DIR, mask_password, readable_timestamp, timestamp


def _analysis_to_dict(password: str, analysis: PasswordAnalysis) -> dict:
    """Convert a ``PasswordAnalysis`` into a JSON-serializable dictionary.

    Args:
        password: The original password (used only to compute a masked
            representation; never stored in full).
        analysis: The analysis result to serialize.

    Returns:
        A dictionary representation safe for JSON export.
    """
    return {
        "masked_password": mask_password(password),
        "length": analysis.length,
        "score": analysis.score,
        "rating": analysis.rating.value,
        "compliance": asdict(analysis.compliance),
        "entropy": {
            "bits": analysis.entropy.bits,
            "pool_size": analysis.entropy.pool_size,
            "estimated_crack_time": analysis.entropy.crack_time_human,
        },
        "patterns": {
            "is_common_password": analysis.patterns.is_common_password,
            "has_repeated_chars": analysis.patterns.has_repeated_chars,
            "repeated_examples": analysis.patterns.repeated_examples,
            "has_sequential_pattern": analysis.patterns.has_sequential_pattern,
            "sequential_examples": analysis.patterns.sequential_examples,
            "has_keyboard_walk": analysis.patterns.has_keyboard_walk,
            "keyboard_examples": analysis.patterns.keyboard_examples,
            "has_dictionary_word": analysis.patterns.has_dictionary_word,
            "dictionary_examples": analysis.patterns.dictionary_examples,
        },
        "reasons": analysis.reasons,
        "suggestions": analysis.suggestions,
    }


def build_text_report(password: str, analysis: PasswordAnalysis, index: int = 1) -> str:
    """Build a formatted, human-readable text report for one password.

    Args:
        password: The original password (masked before display).
        analysis: The analysis result to report on.
        index: The 1-based index of this password within a batch report.

    Returns:
        A formatted multi-line string report.
    """
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append(f"PASSWORD #{index} ANALYSIS")
    lines.append("=" * 60)
    lines.append(f"Masked Password : {mask_password(password)}")
    lines.append(f"Length          : {analysis.length}")
    lines.append(f"Score           : {analysis.score}/100")
    lines.append(f"Rating          : {analysis.rating.value}")
    lines.append("-" * 60)
    lines.append("COMPOSITION CHECKS")
    lines.append(f"  Minimum length (8+)      : {'PASS' if analysis.compliance.min_length else 'FAIL'}")
    lines.append(f"  Recommended length (12+) : {'PASS' if analysis.compliance.recommended_length else 'FAIL'}")
    lines.append(f"  Uppercase letters        : {'PASS' if analysis.compliance.has_uppercase else 'FAIL'}")
    lines.append(f"  Lowercase letters        : {'PASS' if analysis.compliance.has_lowercase else 'FAIL'}")
    lines.append(f"  Numbers                  : {'PASS' if analysis.compliance.has_digit else 'FAIL'}")
    lines.append(f"  Special characters       : {'PASS' if analysis.compliance.has_special else 'FAIL'}")
    lines.append("-" * 60)
    lines.append("ENTROPY ANALYSIS")
    lines.append(f"  Estimated entropy        : {analysis.entropy.bits} bits")
    lines.append(f"  Character pool size      : {analysis.entropy.pool_size}")
    lines.append(f"  Estimated crack time     : {analysis.entropy.crack_time_human}")
    lines.append("-" * 60)
    lines.append("PATTERN DETECTION")
    lines.append(f"  Common password          : {'YES' if analysis.patterns.is_common_password else 'no'}")
    lines.append(f"  Repeated characters      : {'YES' if analysis.patterns.has_repeated_chars else 'no'}")
    lines.append(f"  Sequential pattern       : {'YES' if analysis.patterns.has_sequential_pattern else 'no'}")
    lines.append(f"  Keyboard walk pattern    : {'YES' if analysis.patterns.has_keyboard_walk else 'no'}")
    lines.append(f"  Dictionary word found    : {'YES' if analysis.patterns.has_dictionary_word else 'no'}")
    lines.append("-" * 60)
    lines.append("REASONS")
    for reason in analysis.reasons:
        lines.append(f"  - {reason}")
    lines.append("-" * 60)
    lines.append("SUGGESTIONS")
    for suggestion in analysis.suggestions:
        lines.append(f"  - {suggestion}")
    lines.append("=" * 60)
    lines.append("")
    return "\n".join(lines)


def export_txt_report(entries: List[tuple], filename: str | None = None) -> str:
    """Export a batch of password analyses as a formatted ``.txt`` report.

    Args:
        entries: A list of (password, PasswordAnalysis) tuples.
        filename: Optional explicit filename. If omitted, a timestamped
            filename is generated automatically.

    Returns:
        The full path to the written report file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if filename is None:
        filename = f"password_report_{timestamp()}.txt"

    filepath = os.path.join(REPORTS_DIR, filename)

    header = (
        "PASSWORD STRENGTH CHECKER - SECURITY REPORT\n"
        f"Generated: {readable_timestamp()}\n"
        f"Total passwords analyzed: {len(entries)}\n"
    )

    body = "\n".join(
        build_text_report(password, analysis, index=i + 1)
        for i, (password, analysis) in enumerate(entries)
    )

    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write(header + "\n" + body)

    return filepath


def export_json_report(entries: List[tuple], filename: str | None = None) -> str:
    """Export a batch of password analyses as a structured ``.json`` report.

    Args:
        entries: A list of (password, PasswordAnalysis) tuples.
        filename: Optional explicit filename. If omitted, a timestamped
            filename is generated automatically.

    Returns:
        The full path to the written report file.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if filename is None:
        filename = f"password_report_{timestamp()}.json"

    filepath = os.path.join(REPORTS_DIR, filename)

    payload = {
        "generated_at": readable_timestamp(),
        "total_passwords_analyzed": len(entries),
        "results": [
            _analysis_to_dict(password, analysis) for password, analysis in entries
        ],
    }

    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return filepath
