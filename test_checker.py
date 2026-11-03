"""
test_checker.py
================

Pytest unit tests covering the core modules of the Password Strength
Checker: composition checks, entropy estimation, pattern detection,
scoring/rating logic, and report generation.

Run with:
    pytest -v
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.checker import (
    StrengthRating,
    evaluate_password,
)
from src.entropy import analyze_entropy, calculate_entropy_bits, humanize_seconds
from src.patterns import (
    analyze_patterns,
    check_common_password,
    detect_dictionary_words,
    detect_keyboard_walks,
    detect_repeated_characters,
    detect_sequential_patterns,
)
from src.report import build_text_report, export_json_report, export_txt_report
from src.utils import character_pools_present, estimated_pool_size, mask_password


# ---------------------------------------------------------------------------
# Composition / character pool tests
# ---------------------------------------------------------------------------

class TestCharacterPools:
    """Tests for character pool detection in utils.py."""

    def test_detects_all_categories(self):
        pools = character_pools_present("Abc123!@#")
        assert pools["uppercase"] is True
        assert pools["lowercase"] is True
        assert pools["digits"] is True
        assert pools["special"] is True

    def test_detects_missing_categories(self):
        pools = character_pools_present("abcdefgh")
        assert pools["uppercase"] is False
        assert pools["lowercase"] is True
        assert pools["digits"] is False
        assert pools["special"] is False

    def test_empty_string(self):
        pools = character_pools_present("")
        assert all(value is False for value in pools.values())

    def test_pool_size_scales_with_categories(self):
        assert estimated_pool_size("abc") == 26
        assert estimated_pool_size("ABC") == 26
        assert estimated_pool_size("abcABC123") == 62
        assert estimated_pool_size("abcABC123!@#") == 94


# ---------------------------------------------------------------------------
# Entropy tests
# ---------------------------------------------------------------------------

class TestEntropy:
    """Tests for entropy.py."""

    def test_empty_password_zero_entropy(self):
        assert calculate_entropy_bits("") == 0.0

    def test_longer_password_has_more_entropy(self):
        short = calculate_entropy_bits("abcd")
        long = calculate_entropy_bits("abcdefghijkl")
        assert long > short

    def test_more_diverse_charset_increases_entropy(self):
        simple = calculate_entropy_bits("aaaaaaaa")
        diverse = calculate_entropy_bits("aB3!kL9@")
        assert diverse > simple

    def test_humanize_seconds_instant(self):
        assert humanize_seconds(0.5) == "instantly"

    def test_humanize_seconds_large_value(self):
        result = humanize_seconds(60 * 60 * 24 * 365 * 1000)
        assert "centuries" in result or "uncrackable" in result

    def test_analyze_entropy_returns_full_result(self):
        result = analyze_entropy("Str0ng!Passw0rd")
        assert result.bits > 0
        assert result.pool_size > 0
        assert isinstance(result.crack_time_human, str)


# ---------------------------------------------------------------------------
# Pattern detection tests
# ---------------------------------------------------------------------------

class TestPatterns:
    """Tests for patterns.py."""

    def test_common_password_detected(self):
        assert check_common_password("password") is True
        assert check_common_password("123456") is True

    def test_uncommon_password_not_flagged(self):
        assert check_common_password("Xk9#mQ2$vLp7!zR4") is False

    def test_repeated_characters_detected(self):
        matches = detect_repeated_characters("aaaa1111bcd")
        assert "aaaa" in matches
        assert "1111" in matches

    def test_repeated_characters_not_flagged_below_threshold(self):
        matches = detect_repeated_characters("aaa111bcd")
        assert matches == []

    def test_sequential_ascending_detected(self):
        matches = detect_sequential_patterns("test12345end")
        assert any("12345" in m or m in "12345" for m in matches)

    def test_sequential_alpha_detected(self):
        matches = detect_sequential_patterns("myabcdepass")
        assert any(len(m) >= 4 for m in matches)

    def test_no_sequential_pattern_in_random_string(self):
        matches = detect_sequential_patterns("Xk9mQ2vLp7zR")
        assert matches == []

    def test_keyboard_walk_detected(self):
        matches = detect_keyboard_walks("myqwertypass")
        assert any("qwert" in m or "qwerty" in m for m in matches)

    def test_dictionary_word_detected(self):
        words = detect_dictionary_words("mypassword99")
        assert "password" in words

    def test_no_dictionary_word_in_random_string(self):
        words = detect_dictionary_words("Xk9mQ2vLp7zR")
        assert words == []

    def test_analyze_patterns_full_findings(self):
        findings = analyze_patterns("password1234")
        assert findings.total_flags >= 1


# ---------------------------------------------------------------------------
# Core checker / scoring tests
# ---------------------------------------------------------------------------

class TestEvaluatePassword:
    """Tests for the main evaluate_password orchestration function."""

    def test_empty_password_raises(self):
        with pytest.raises(ValueError):
            evaluate_password("")

    def test_common_password_is_weak(self):
        analysis = evaluate_password("password")
        assert analysis.rating == StrengthRating.WEAK

    def test_short_password_is_weak(self):
        analysis = evaluate_password("Ab1!")
        assert analysis.rating == StrengthRating.WEAK
        assert analysis.compliance.min_length is False

    def test_medium_password(self):
        analysis = evaluate_password("Passw0rd123")
        assert analysis.rating in (StrengthRating.WEAK, StrengthRating.MEDIUM)

    def test_strong_password(self):
        analysis = evaluate_password("Xk9#mQ2$vLp7!zR4wT")
        assert analysis.rating == StrengthRating.STRONG
        assert analysis.score >= 75

    def test_score_within_bounds(self):
        for pwd in ["a", "password", "Xk9#mQ2$vLp7!zR4wT", "1234567890123456"]:
            analysis = evaluate_password(pwd)
            assert 0 <= analysis.score <= 100

    def test_reasons_and_suggestions_present_for_weak(self):
        analysis = evaluate_password("weak")
        assert len(analysis.reasons) > 0
        assert len(analysis.suggestions) > 0

    def test_strong_password_has_minimal_suggestions(self):
        analysis = evaluate_password("Xk9#mQ2$vLp7!zR4wT")
        assert "No changes required" in analysis.suggestions[0]

    def test_missing_character_types_reflected_in_compliance(self):
        analysis = evaluate_password("alllowercaseletters")
        assert analysis.compliance.has_uppercase is False
        assert analysis.compliance.has_digit is False
        assert analysis.compliance.has_special is False

    def test_length_thresholds(self):
        short = evaluate_password("Ab1!Ab1!")  # exactly 8 chars
        assert short.compliance.min_length is True
        assert short.compliance.recommended_length is False

        long_pw = evaluate_password("Ab1!Ab1!Ab1!")  # 12 chars
        assert long_pw.compliance.recommended_length is True


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtils:
    """Tests for helper utilities."""

    def test_mask_password_short(self):
        assert mask_password("ab") == "**"

    def test_mask_password_normal(self):
        masked = mask_password("password123")
        assert masked.startswith("p")
        assert masked.endswith("3")
        assert "*" in masked
        assert len(masked) == len("password123")

    def test_mask_password_empty(self):
        assert mask_password("") == ""


# ---------------------------------------------------------------------------
# Report generation tests
# ---------------------------------------------------------------------------

class TestReport:
    """Tests for report.py generation and export."""

    def test_build_text_report_contains_key_sections(self):
        analysis = evaluate_password("Xk9#mQ2$vLp7!zR4wT")
        text = build_text_report("Xk9#mQ2$vLp7!zR4wT", analysis)
        assert "PASSWORD #1 ANALYSIS" in text
        assert "COMPOSITION CHECKS" in text
        assert "ENTROPY ANALYSIS" in text
        assert "PATTERN DETECTION" in text
        assert "SUGGESTIONS" in text

    def test_export_txt_report_creates_file(self, tmp_path, monkeypatch):
        import src.report as report_module

        monkeypatch.setattr(report_module, "REPORTS_DIR", str(tmp_path))
        analysis = evaluate_password("Xk9#mQ2$vLp7!zR4wT")
        path = export_txt_report([("Xk9#mQ2$vLp7!zR4wT", analysis)], filename="test_report.txt")
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert "PASSWORD STRENGTH CHECKER" in content

    def test_export_json_report_creates_valid_json(self, tmp_path, monkeypatch):
        import src.report as report_module

        monkeypatch.setattr(report_module, "REPORTS_DIR", str(tmp_path))
        analysis = evaluate_password("Xk9#mQ2$vLp7!zR4wT")
        path = export_json_report([("Xk9#mQ2$vLp7!zR4wT", analysis)], filename="test_report.json")
        assert os.path.isfile(path)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        assert data["total_passwords_analyzed"] == 1
        assert data["results"][0]["rating"] == "Strong"
        # Ensure the plaintext password is never stored in the report.
        assert "Xk9#mQ2$vLp7!zR4wT" not in json.dumps(data)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
