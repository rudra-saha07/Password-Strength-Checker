"""
utils.py
========

Shared helper utilities used across the Password Strength Checker
application: file loading, path resolution, timestamp formatting, and
small text-processing helpers.
"""

from __future__ import annotations

import os
import string
from datetime import datetime
from functools import lru_cache
from typing import FrozenSet, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
PASSWORDS_DIR = os.path.join(PROJECT_ROOT, "passwords")
COMMON_PASSWORDS_FILE = os.path.join(DATA_DIR, "common_passwords.txt")

# A small, curated set of English dictionary words commonly found embedded
# in weak passwords. This is intentionally lightweight (no external
# dictionary dependency) so the project runs fully offline.
DICTIONARY_WORDS: FrozenSet[str] = frozenset(
    {
        "password", "welcome", "admin", "login", "master", "shadow",
        "dragon", "monkey", "football", "baseball", "soccer", "hockey",
        "sunshine", "princess", "superman", "batman", "letmein", "freedom",
        "trust", "access", "flower", "summer", "winter", "spring", "autumn",
        "love", "hate", "money", "secret", "computer", "internet", "server",
        "system", "network", "security", "hacker", "matrix", "phoenix",
        "dolphin", "tiger", "eagle", "falcon", "wizard", "ninja", "pirate",
        "cookie", "chocolate", "coffee", "guitar", "music", "movie",
        "family", "friend", "school", "college", "university", "office",
        "hello", "world", "test", "demo", "sample", "example", "default",
        "guest", "user", "root", "temp", "change", "reset",
    }
)

# Keyboard rows used for adjacency-based keyboard-walk detection.
KEYBOARD_ROWS: List[str] = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]


def ensure_directories() -> None:
    """Ensure that all required project directories exist.

    Creates the ``data``, ``reports``, and ``passwords`` directories if
    they are missing. Safe to call multiple times.
    """
    for directory in (DATA_DIR, REPORTS_DIR, PASSWORDS_DIR):
        os.makedirs(directory, exist_ok=True)


@lru_cache(maxsize=1)
def load_common_passwords() -> FrozenSet[str]:
    """Load the common-password wordlist from disk into memory.

    The result is cached (``lru_cache``) so the file is only read once
    per process, since the checker may be invoked many times in an
    interactive session.

    Returns:
        A frozenset of lowercase common passwords for O(1) lookups.
        Returns an empty frozenset if the file cannot be found or read.
    """
    if not os.path.isfile(COMMON_PASSWORDS_FILE):
        return frozenset()

    try:
        with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as handle:
            return frozenset(
                line.strip().lower() for line in handle if line.strip()
            )
    except OSError:
        return frozenset()


def timestamp() -> str:
    """Return the current local timestamp formatted for filenames.

    Returns:
        A string like ``2026-08-02_14-30-05``.
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def readable_timestamp() -> str:
    """Return the current local timestamp formatted for human display.

    Returns:
        A string like ``2026-08-02 14:30:05``.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mask_password(password: str) -> str:
    """Mask a password for safe display or logging purposes.

    Shows only the first and last character (if the password is long
    enough) with asterisks in between, e.g. ``h******3``. Never logs or
    displays the full password.

    Args:
        password: The raw password string.

    Returns:
        A masked representation of the password.
    """
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"


def character_pools_present(password: str) -> dict:
    """Determine which character categories are present in a password.

    Args:
        password: The password string to inspect.

    Returns:
        A dictionary with boolean flags for ``lowercase``, ``uppercase``,
        ``digits``, and ``special`` character categories.
    """
    return {
        "lowercase": any(c in string.ascii_lowercase for c in password),
        "uppercase": any(c in string.ascii_uppercase for c in password),
        "digits": any(c in string.digits for c in password),
        "special": any(c not in string.ascii_letters + string.digits for c in password),
    }


def estimated_pool_size(password: str) -> int:
    """Estimate the size of the character pool a password draws from.

    Used for entropy calculations. Adds up the sizes of each character
    category actually present in the password (lowercase=26, uppercase=26,
    digits=10, special=32 printable symbols).

    Args:
        password: The password string to inspect.

    Returns:
        The estimated size of the character pool.
    """
    pools = character_pools_present(password)
    pool_size = 0
    if pools["lowercase"]:
        pool_size += 26
    if pools["uppercase"]:
        pool_size += 26
    if pools["digits"]:
        pool_size += 10
    if pools["special"]:
        pool_size += 32
    return pool_size


def safe_write_text(path: str, content: str) -> None:
    """Write text content to a file, creating parent directories as needed.

    Args:
        path: Destination file path.
        content: Text content to write.

    Raises:
        OSError: If the file cannot be written.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
