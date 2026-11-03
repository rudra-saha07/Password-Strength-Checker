"""
checker.py
==========

Core business logic for password strength evaluation. Combines character
composition checks, entropy analysis, and weak-pattern detection into a
single weighted score and a Weak / Medium / Strong rating.

This module contains no UI or I/O code (no ``print`` or ``input``) so it
can be reused by the CLI, tests, or any future interface (e.g., a web API)
without modification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List

from src.entropy import EntropyResult, analyze_entropy
from src.patterns import PatternFindings, analyze_patterns
from src.utils import character_pools_present

MIN_RECOMMENDED_LENGTH = 12
ABSOLUTE_MIN_LENGTH = 8


class StrengthRating(str, Enum):
    """Enumeration of possible password strength ratings."""

    WEAK = "Weak"
    MEDIUM = "Medium"
    STRONG = "Strong"


@dataclass
class ComplianceChecks:
    """Boolean results for each core composition requirement.

    Attributes:
        min_length: True if the password meets the absolute minimum length.
        recommended_length: True if the password meets the recommended length.
        has_uppercase: True if at least one uppercase letter is present.
        has_lowercase: True if at least one lowercase letter is present.
        has_digit: True if at least one digit is present.
        has_special: True if at least one special character is present.
    """

    min_length: bool
    recommended_length: bool
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_special: bool

    @property
    def passed_count(self) -> int:
        """Return how many of the six composition checks passed."""
        return sum(
            (
                self.min_length,
                self.recommended_length,
                self.has_uppercase,
                self.has_lowercase,
                self.has_digit,
                self.has_special,
            )
        )


@dataclass
class PasswordAnalysis:
    """Full result of analyzing a single password.

    Attributes:
        length: The length of the password.
        score: Overall strength score from 0-100.
        rating: The final ``StrengthRating`` (Weak/Medium/Strong).
        compliance: The ``ComplianceChecks`` breakdown.
        entropy: The ``EntropyResult`` from the entropy module.
        patterns: The ``PatternFindings`` from the patterns module.
        reasons: Human-readable explanations for the rating.
        suggestions: Actionable suggestions to improve the password.
    """

    length: int
    score: int
    rating: StrengthRating
    compliance: ComplianceChecks
    entropy: EntropyResult
    patterns: PatternFindings
    reasons: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


def _run_compliance_checks(password: str) -> ComplianceChecks:
    """Run the six core composition checks against a password.

    Args:
        password: The password string to evaluate.

    Returns:
        A populated ``ComplianceChecks`` dataclass.
    """
    pools = character_pools_present(password)
    return ComplianceChecks(
        min_length=len(password) >= ABSOLUTE_MIN_LENGTH,
        recommended_length=len(password) >= MIN_RECOMMENDED_LENGTH,
        has_uppercase=pools["uppercase"],
        has_lowercase=pools["lowercase"],
        has_digit=pools["digits"],
        has_special=pools["special"],
    )


def _calculate_score(
    password: str,
    compliance: ComplianceChecks,
    entropy: EntropyResult,
    patterns: PatternFindings,
) -> int:
    """Calculate a 0-100 password strength score.

    The score is a weighted composite of:
        - Length (up to 25 points)
        - Character variety (up to 25 points)
        - Entropy (up to 30 points)
        - Weak-pattern penalties (subtracted, up to -60 points)

    Args:
        password: The password string being scored.
        compliance: Result of the composition checks.
        entropy: Result of the entropy analysis.
        patterns: Result of the weak-pattern detection.

    Returns:
        An integer score clamped to the range [0, 100].
    """
    score = 0.0

    # --- Length score (max 25) ---
    length = len(password)
    if length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 12
    elif length > 0:
        score += 4

    # --- Character variety score (max 25) ---
    variety_points = {
        "has_uppercase": 6,
        "has_lowercase": 6,
        "has_digit": 6,
        "has_special": 7,
    }
    for attr, points in variety_points.items():
        if getattr(compliance, attr):
            score += points

    # --- Entropy score (max 30) ---
    if entropy.bits >= 100:
        score += 30
    elif entropy.bits >= 80:
        score += 25
    elif entropy.bits >= 60:
        score += 18
    elif entropy.bits >= 40:
        score += 10
    elif entropy.bits > 0:
        score += 4

    # --- Bonus for hitting the recommended length threshold (max 20) ---
    if compliance.recommended_length:
        score += 20

    # --- Weak-pattern penalties ---
    if patterns.is_common_password:
        score -= 40
    if patterns.has_repeated_chars:
        score -= 10
    if patterns.has_sequential_pattern:
        score -= 10
    if patterns.has_keyboard_walk:
        score -= 10
    if patterns.has_dictionary_word:
        score -= 8

    return max(0, min(100, round(score)))


def _determine_rating(score: int, patterns: PatternFindings, compliance: ComplianceChecks) -> StrengthRating:
    """Map a numeric score (with pattern context) to a strength rating.

    A known common password is always rated Weak regardless of score,
    since it offers no real protection against dictionary/credential
    stuffing attacks.

    Args:
        score: The computed 0-100 score.
        patterns: The weak-pattern detection results.
        compliance: The composition check results.

    Returns:
        The final ``StrengthRating``.
    """
    if patterns.is_common_password or not compliance.min_length:
        return StrengthRating.WEAK

    if score >= 75:
        return StrengthRating.STRONG
    if score >= 45:
        return StrengthRating.MEDIUM
    return StrengthRating.WEAK


def _build_reasons(
    compliance: ComplianceChecks,
    entropy: EntropyResult,
    patterns: PatternFindings,
    rating: StrengthRating,
) -> List[str]:
    """Build a list of human-readable reasons explaining the rating.

    Args:
        compliance: The composition check results.
        entropy: The entropy analysis results.
        patterns: The weak-pattern detection results.
        rating: The final computed rating.

    Returns:
        A list of explanatory strings.
    """
    reasons: List[str] = []

    if not compliance.min_length:
        reasons.append(
            f"Password is shorter than the minimum recommended {ABSOLUTE_MIN_LENGTH} characters."
        )
    elif not compliance.recommended_length:
        reasons.append(
            f"Password meets the minimum length but is shorter than the ideal "
            f"{MIN_RECOMMENDED_LENGTH}+ characters."
        )
    else:
        reasons.append(f"Password meets or exceeds the recommended {MIN_RECOMMENDED_LENGTH}-character length.")

    missing = []
    if not compliance.has_uppercase:
        missing.append("uppercase letters")
    if not compliance.has_lowercase:
        missing.append("lowercase letters")
    if not compliance.has_digit:
        missing.append("numbers")
    if not compliance.has_special:
        missing.append("special characters")

    if missing:
        reasons.append("Missing character types: " + ", ".join(missing) + ".")
    else:
        reasons.append("Contains a healthy mix of uppercase, lowercase, digits, and special characters.")

    reasons.append(
        f"Estimated entropy is {entropy.bits} bits "
        f"(estimated brute-force crack time: {entropy.crack_time_human})."
    )

    if patterns.is_common_password:
        reasons.append("This password appears in a well-known list of commonly breached/used passwords.")
    if patterns.has_repeated_chars:
        reasons.append(
            "Contains repeated character sequences (e.g., "
            + ", ".join(patterns.repeated_examples) + "), which reduce unpredictability."
        )
    if patterns.has_sequential_pattern:
        reasons.append(
            "Contains sequential patterns (e.g., "
            + ", ".join(patterns.sequential_examples) + "), which are easy to guess."
        )
    if patterns.has_keyboard_walk:
        reasons.append(
            "Contains a keyboard-walk pattern (e.g., "
            + ", ".join(patterns.keyboard_examples) + "), common in weak passwords."
        )
    if patterns.has_dictionary_word:
        reasons.append(
            "Contains dictionary word(s) (e.g., "
            + ", ".join(patterns.dictionary_examples) + ") that weaken resistance to dictionary attacks."
        )

    if rating == StrengthRating.STRONG:
        reasons.append("Overall, this password demonstrates strong resistance to common cracking techniques.")

    return reasons


def _build_suggestions(
    compliance: ComplianceChecks,
    patterns: PatternFindings,
    rating: StrengthRating,
) -> List[str]:
    """Build a list of actionable suggestions to improve the password.

    Args:
        compliance: The composition check results.
        patterns: The weak-pattern detection results.
        rating: The final computed rating.

    Returns:
        A list of suggestion strings. Empty if the password is already Strong.
    """
    if rating == StrengthRating.STRONG:
        return ["No changes required — this password meets strong security standards."]

    suggestions: List[str] = []

    if not compliance.recommended_length:
        suggestions.append(f"Increase length to at least {MIN_RECOMMENDED_LENGTH} characters, ideally 16+.")
    if not compliance.has_uppercase:
        suggestions.append("Add one or more uppercase letters (A-Z).")
    if not compliance.has_lowercase:
        suggestions.append("Add one or more lowercase letters (a-z).")
    if not compliance.has_digit:
        suggestions.append("Add one or more numeric digits (0-9).")
    if not compliance.has_special:
        suggestions.append("Add special characters such as !, @, #, $, %, or &.")
    if patterns.is_common_password:
        suggestions.append("Avoid this password entirely — it is publicly known and used in credential-stuffing attacks.")
    if patterns.has_repeated_chars:
        suggestions.append("Avoid repeating the same character multiple times in a row.")
    if patterns.has_sequential_pattern:
        suggestions.append("Avoid sequential runs like '1234' or 'abcd'.")
    if patterns.has_keyboard_walk:
        suggestions.append("Avoid keyboard-adjacent patterns like 'qwerty' or 'asdfgh'.")
    if patterns.has_dictionary_word:
        suggestions.append("Avoid embedding common dictionary words; consider a passphrase of unrelated words instead.")

    suggestions.append(
        "Consider using a passphrase of 4-5 random, unrelated words combined with digits and symbols "
        "(e.g., 'Correct-Horse7-Battery!Staple')."
    )
    suggestions.append("Use a password manager to generate and store unique, high-entropy passwords.")

    return suggestions


def evaluate_password(password: str) -> PasswordAnalysis:
    """Run a complete strength evaluation on a single password.

    This is the main entry point for the checker module. It orchestrates
    compliance checks, entropy analysis, and pattern detection, then
    produces a final score, rating, reasons, and suggestions.

    Args:
        password: The plaintext password to evaluate. Never logged or
            persisted by this function.

    Returns:
        A fully populated ``PasswordAnalysis`` dataclass.

    Raises:
        ValueError: If the password is empty.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    compliance = _run_compliance_checks(password)
    entropy = analyze_entropy(password)
    patterns = analyze_patterns(password)

    score = _calculate_score(password, compliance, entropy, patterns)
    rating = _determine_rating(score, patterns, compliance)
    reasons = _build_reasons(compliance, entropy, patterns, rating)
    suggestions = _build_suggestions(compliance, patterns, rating)

    return PasswordAnalysis(
        length=len(password),
        score=score,
        rating=rating,
        compliance=compliance,
        entropy=entropy,
        patterns=patterns,
        reasons=reasons,
        suggestions=suggestions,
    )
