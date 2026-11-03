"""
entropy.py
==========

Password entropy estimation and brute-force crack-time approximation.

Entropy here is calculated using the classical formula:

    H = L * log2(N)

Where:
    L = length of the password
    N = size of the character pool the password draws from

This is a well-known, industry-standard approximation used by tools such
as zxcvbn and the NIST password guidance (SP 800-63B) as a starting point
for measuring password unpredictability.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from src.utils import estimated_pool_size

# Assumed offline attack speed (guesses per second) for a modern GPU rig.
# This is a conservative, widely cited estimate used for illustrative
# crack-time reporting (not a guarantee).
ASSUMED_GUESSES_PER_SECOND = 10_000_000_000  # 10 billion guesses/sec


@dataclass(frozen=True)
class EntropyResult:
    """Container for entropy and crack-time estimation results.

    Attributes:
        bits: Estimated entropy in bits.
        pool_size: Estimated character pool size used in the calculation.
        crack_time_seconds: Estimated average seconds to brute-force crack.
        crack_time_human: Human-readable crack-time estimate.
    """

    bits: float
    pool_size: int
    crack_time_seconds: float
    crack_time_human: str


def calculate_entropy_bits(password: str) -> float:
    """Calculate the Shannon-style entropy of a password in bits.

    Args:
        password: The password string to evaluate.

    Returns:
        Entropy in bits. Returns 0.0 for an empty password.
    """
    if not password:
        return 0.0

    pool_size = estimated_pool_size(password)
    if pool_size == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def humanize_seconds(seconds: float) -> str:
    """Convert a number of seconds into a human-readable duration string.

    Args:
        seconds: A duration in seconds.

    Returns:
        A human-friendly string such as ``"3 hours"``, ``"2 centuries"``,
        or ``"instantly"``.
    """
    if seconds < 1:
        return "instantly"

    intervals = (
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("months", 60 * 60 * 24 * 30),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    )

    for name, unit_seconds in intervals:
        value = seconds / unit_seconds
        if value >= 1:
            rounded = round(value, 1)
            if rounded >= 1000 and name == "centuries":
                return "essentially uncrackable (billions of years)"
            return f"{rounded:g} {name}"

    return "instantly"


def estimate_crack_time(entropy_bits: float) -> tuple[float, str]:
    """Estimate the average brute-force crack time for a given entropy.

    Assumes an attacker needs, on average, half of the total keyspace
    (2^bits) guesses, at a fixed guesses-per-second rate.

    Args:
        entropy_bits: The password's estimated entropy in bits.

    Returns:
        A tuple of (seconds_to_crack, human_readable_string).
    """
    if entropy_bits <= 0:
        return 0.0, "instantly"

    keyspace = 2 ** entropy_bits
    average_guesses = keyspace / 2
    seconds = average_guesses / ASSUMED_GUESSES_PER_SECOND
    return seconds, humanize_seconds(seconds)


def analyze_entropy(password: str) -> EntropyResult:
    """Run a full entropy and crack-time analysis on a password.

    Args:
        password: The password string to evaluate.

    Returns:
        An ``EntropyResult`` dataclass with entropy bits, pool size, and
        crack-time estimates.
    """
    bits = calculate_entropy_bits(password)
    pool_size = estimated_pool_size(password)
    seconds, human = estimate_crack_time(bits)
    return EntropyResult(
        bits=bits,
        pool_size=pool_size,
        crack_time_seconds=seconds,
        crack_time_human=human,
    )
