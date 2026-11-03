"""
patterns.py
===========

Detection of weak password patterns commonly exploited by attackers:

    - Repeated characters (e.g. "aaaa", "1111")
    - Sequential patterns (e.g. "12345", "abcde", "zyxw")
    - Keyboard-walk patterns (e.g. "qwerty", "asdfgh", "1qaz2wsx")
    - Embedded dictionary words (e.g. "mypassword99")
    - Membership in a known common-password list
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from src.utils import DICTIONARY_WORDS, KEYBOARD_ROWS, load_common_passwords

MIN_SEQUENCE_LENGTH = 4
MIN_REPEAT_LENGTH = 4
MIN_KEYBOARD_WALK_LENGTH = 4
MIN_DICTIONARY_WORD_LENGTH = 4


@dataclass
class PatternFindings:
    """Container for all pattern-detection results for a password.

    Attributes:
        is_common_password: True if the password appears in the common
            password wordlist.
        has_repeated_chars: True if 4+ consecutive repeated characters
            were found.
        repeated_examples: Example substrings that triggered the repeat check.
        has_sequential_pattern: True if an ascending/descending numeric or
            alphabetic sequence of length 4+ was found.
        sequential_examples: Example substrings that triggered the check.
        has_keyboard_walk: True if a keyboard-adjacent walk of length 4+
            was found (e.g. "qwerty", "asdf").
        keyboard_examples: Example substrings that triggered the check.
        has_dictionary_word: True if a known dictionary word of length 4+
            was found embedded in the password.
        dictionary_examples: Dictionary words found in the password.
    """

    is_common_password: bool = False
    has_repeated_chars: bool = False
    repeated_examples: List[str] = field(default_factory=list)
    has_sequential_pattern: bool = False
    sequential_examples: List[str] = field(default_factory=list)
    has_keyboard_walk: bool = False
    keyboard_examples: List[str] = field(default_factory=list)
    has_dictionary_word: bool = False
    dictionary_examples: List[str] = field(default_factory=list)

    @property
    def total_flags(self) -> int:
        """Return the total number of distinct weak-pattern categories triggered."""
        return sum(
            (
                self.is_common_password,
                self.has_repeated_chars,
                self.has_sequential_pattern,
                self.has_keyboard_walk,
                self.has_dictionary_word,
            )
        )


def check_common_password(password: str) -> bool:
    """Check whether a password appears in the known common-password list.

    Args:
        password: The password string to check.

    Returns:
        True if the password (case-insensitive) is a known common password.
    """
    common = load_common_passwords()
    return password.lower() in common


def detect_repeated_characters(password: str) -> List[str]:
    """Detect runs of 4 or more identical consecutive characters.

    Examples:
        "aaaa1111" -> ["aaaa", "1111"]

    Args:
        password: The password string to inspect.

    Returns:
        A list of matched repeated-character substrings (deduplicated).
    """
    matches = re.findall(r"(.)\1{" + str(MIN_REPEAT_LENGTH - 1) + r",}", password)
    examples = []
    for char in matches:
        run = re.search(re.escape(char) + r"{" + str(MIN_REPEAT_LENGTH) + r",}", password)
        if run and run.group() not in examples:
            examples.append(run.group())
    return examples


def _is_sequential_run(chars: str, ascending: bool) -> bool:
    """Check whether a string of characters forms a strictly sequential run.

    Args:
        chars: The substring to check.
        ascending: If True, checks for an ascending sequence; otherwise
            checks for a descending sequence.

    Returns:
        True if every character is exactly one step from the previous one.
    """
    codes = [ord(c) for c in chars.lower()]
    step = 1 if ascending else -1
    return all(codes[i + 1] - codes[i] == step for i in range(len(codes) - 1))


def detect_sequential_patterns(password: str) -> List[str]:
    """Detect ascending or descending alphanumeric sequences of length 4+.

    Examples:
        "12345" -> ["12345"]
        "abcde" -> ["abcde"]
        "9876"  -> ["9876"]

    Args:
        password: The password string to inspect.

    Returns:
        A list of matched sequential substrings (deduplicated).
    """
    examples: List[str] = []
    length = len(password)

    for start in range(length):
        for end in range(start + MIN_SEQUENCE_LENGTH, length + 1):
            chunk = password[start:end]
            if not chunk.isalnum():
                continue
            if _is_sequential_run(chunk, ascending=True) or _is_sequential_run(chunk, ascending=False):
                if chunk not in examples:
                    examples.append(chunk)

    # Keep only the longest, non-overlapping-ish matches for readability.
    examples.sort(key=len, reverse=True)
    return examples[:3]


def detect_keyboard_walks(password: str) -> List[str]:
    """Detect substrings that correspond to adjacent keys on a QWERTY keyboard.

    Examples:
        "qwerty" -> ["qwerty"]
        "asdfgh" -> ["asdfgh"]
        "1qaz2wsx" -> partial matches detected via row adjacency

    Args:
        password: The password string to inspect.

    Returns:
        A list of matched keyboard-walk substrings (deduplicated).
    """
    lowered = password.lower()
    examples: List[str] = []

    for row in KEYBOARD_ROWS:
        for start in range(len(row) - MIN_KEYBOARD_WALK_LENGTH + 1):
            for length in range(MIN_KEYBOARD_WALK_LENGTH, min(8, len(row) - start) + 1):
                segment = row[start:start + length]
                reversed_segment = segment[::-1]
                if segment in lowered and segment not in examples:
                    examples.append(segment)
                if reversed_segment in lowered and reversed_segment not in examples:
                    examples.append(reversed_segment)

    return examples[:3]


def detect_dictionary_words(password: str) -> List[str]:
    """Detect known dictionary words embedded within the password.

    Args:
        password: The password string to inspect.

    Returns:
        A list of dictionary words found within the password (lowercased,
        deduplicated), limited to words of length 4 or more.
    """
    lowered = password.lower()
    found = [
        word for word in DICTIONARY_WORDS
        if len(word) >= MIN_DICTIONARY_WORD_LENGTH and word in lowered
    ]
    found.sort(key=len, reverse=True)
    return found[:5]


def analyze_patterns(password: str) -> PatternFindings:
    """Run the full suite of weak-pattern detectors against a password.

    Args:
        password: The password string to analyze.

    Returns:
        A populated ``PatternFindings`` dataclass.
    """
    repeated = detect_repeated_characters(password)
    sequential = detect_sequential_patterns(password)
    keyboard = detect_keyboard_walks(password)
    dictionary = detect_dictionary_words(password)
    common = check_common_password(password)

    return PatternFindings(
        is_common_password=common,
        has_repeated_chars=bool(repeated),
        repeated_examples=repeated,
        has_sequential_pattern=bool(sequential),
        sequential_examples=sequential,
        has_keyboard_walk=bool(keyboard),
        keyboard_examples=keyboard,
        has_dictionary_word=bool(dictionary),
        dictionary_examples=dictionary,
    )
