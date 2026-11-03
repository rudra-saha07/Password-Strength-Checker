"""
logger.py
=========

Centralized logging configuration for the Password Strength Checker
application. Provides a single, reusable logger instance that writes
to both a rotating log file and (optionally) the console.

Security note:
    Passwords or any sensitive user input must NEVER be written to the
    log file. Only metadata (e.g., "password checked", "report exported")
    should be logged.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

_LOGGER_NAME = "password_strength_checker"


def get_logger(name: str = _LOGGER_NAME) -> logging.Logger:
    """Create and return a configured logger instance.

    The logger writes rotating log files (max 1 MB, 3 backups) to the
    ``reports`` directory and also streams warnings/errors to the console.
    Calling this function multiple times returns the same configured
    logger without duplicating handlers.

    Args:
        name: The name of the logger to create or retrieve.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        # Logger already configured; avoid duplicate handlers.
        return logger

    logger.setLevel(logging.DEBUG)

    os.makedirs(LOG_DIR, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # If the file system is not writable, fall back to console-only logging.
        pass

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.propagate = False
    return logger


logger = get_logger()
