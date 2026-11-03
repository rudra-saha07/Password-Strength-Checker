#!/usr/bin/env python3
"""
app.py
======

Password Strength Checker - Interactive CLI Entry Point

A professional-grade command-line tool for analyzing password strength,
built for the Code Orbit Tech Cyber Security Internship program.

Features:
    - Secure, hidden password input (getpass)
    - Weighted 0-100 strength scoring with Weak/Medium/Strong rating
    - Shannon entropy and brute-force crack-time estimation
    - Detection of common passwords, repeated/sequential/keyboard patterns,
      and embedded dictionary words
    - Colorized terminal output (Colorama)
    - Interactive menu with repeat checks, batch file analysis, and
      report export (TXT / JSON)

Run with:
    python app.py
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import List, Tuple

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:  # pragma: no cover - defensive fallback
    print("Missing dependency 'colorama'. Install it with: pip install -r requirements.txt")
    sys.exit(1)

from src.checker import PasswordAnalysis, StrengthRating, evaluate_password
from src.logger import get_logger
from src.report import export_json_report, export_txt_report
from src.utils import ensure_directories, mask_password

colorama_init(autoreset=True)
logger = get_logger()

RATING_COLORS = {
    StrengthRating.WEAK: Fore.RED,
    StrengthRating.MEDIUM: Fore.YELLOW,
    StrengthRating.STRONG: Fore.GREEN,
}

BANNER = r"""
  ____                                     _  __  _____ _                  _   _
 |  _ \ __ _ ___ _____      _____  _ __ __| | \ \/ / ____| |_ _ __ ___  ___| |_(_) __ _
 | |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |  \  /|  _| | __| '__/ _ \/ __| __| |/ _` |
 |  __/ (_| \__ \__ \ V  V / (_) | | | (_| |  /  \| |___| |_| | |  __/ (__| |_| | (_| |
 |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_| /_/\_\_____|\__|_|  \___|\___|\__|_|\__, |
                                                                                    |___/
                     C H E C K E R   -   Cyber Security Toolkit
"""


def print_banner() -> None:
    """Print the application banner and short description."""
    print(Fore.CYAN + Style.BRIGHT + BANNER)
    print(Fore.WHITE + "  A professional password security analysis tool")
    print(Fore.WHITE + "  Code Orbit Tech - Cyber Security Internship\n")


def print_menu() -> None:
    """Print the interactive main menu options."""
    print(Fore.CYAN + Style.BRIGHT + "\n" + "-" * 45)
    print(Fore.CYAN + Style.BRIGHT + "  MAIN MENU")
    print(Fore.CYAN + Style.BRIGHT + "-" * 45)
    print(Fore.WHITE + "  [1] Check a single password")
    print(Fore.WHITE + "  [2] Analyze passwords from a text file")
    print(Fore.WHITE + "  [3] Export session report (TXT + JSON)")
    print(Fore.WHITE + "  [4] View session summary")
    print(Fore.WHITE + "  [5] Exit")
    print(Fore.CYAN + Style.BRIGHT + "-" * 45)


def _bool_icon(value: bool) -> str:
    """Return a colorized check/cross icon for a boolean value.

    Args:
        value: The boolean to represent.

    Returns:
        A colorized string: a green check mark or a red cross.
    """
    return f"{Fore.GREEN}✔{Style.RESET_ALL}" if value else f"{Fore.RED}✘{Style.RESET_ALL}"


def display_analysis(password: str, analysis: PasswordAnalysis) -> None:
    """Print a colorized, formatted analysis result to the terminal.

    Args:
        password: The original password (used only for masked display).
        analysis: The computed ``PasswordAnalysis`` result.
    """
    color = RATING_COLORS[analysis.rating]

    print("\n" + Fore.CYAN + "=" * 55)
    print(Fore.WHITE + Style.BRIGHT + f"  Password Analyzed : {mask_password(password)}")
    print(Fore.WHITE + f"  Length             : {analysis.length}")
    print(color + Style.BRIGHT + f"  Rating             : {analysis.rating.value}")
    print(Fore.WHITE + f"  Score              : {analysis.score}/100")
    print(Fore.CYAN + "=" * 55)

    print(Fore.WHITE + Style.BRIGHT + "\n  Composition Checks:")
    print(f"    {_bool_icon(analysis.compliance.min_length)} Minimum length (8+ characters)")
    print(f"    {_bool_icon(analysis.compliance.recommended_length)} Recommended length (12+ characters)")
    print(f"    {_bool_icon(analysis.compliance.has_uppercase)} Uppercase letters (A-Z)")
    print(f"    {_bool_icon(analysis.compliance.has_lowercase)} Lowercase letters (a-z)")
    print(f"    {_bool_icon(analysis.compliance.has_digit)} Numbers (0-9)")
    print(f"    {_bool_icon(analysis.compliance.has_special)} Special characters (!@#$...)")

    print(Fore.WHITE + Style.BRIGHT + "\n  Entropy Analysis:")
    print(f"    Estimated entropy      : {Fore.MAGENTA}{analysis.entropy.bits} bits{Style.RESET_ALL}")
    print(f"    Character pool size    : {analysis.entropy.pool_size}")
    print(f"    Est. brute-force time  : {Fore.MAGENTA}{analysis.entropy.crack_time_human}{Style.RESET_ALL}")

    print(Fore.WHITE + Style.BRIGHT + "\n  Pattern Detection:")
    print(f"    {_bool_icon(not analysis.patterns.is_common_password)} Not a known common password")
    print(f"    {_bool_icon(not analysis.patterns.has_repeated_chars)} No repeated character runs")
    print(f"    {_bool_icon(not analysis.patterns.has_sequential_pattern)} No sequential patterns")
    print(f"    {_bool_icon(not analysis.patterns.has_keyboard_walk)} No keyboard-walk patterns")
    print(f"    {_bool_icon(not analysis.patterns.has_dictionary_word)} No embedded dictionary words")

    print(Fore.WHITE + Style.BRIGHT + "\n  Why this rating:")
    for reason in analysis.reasons:
        print(Fore.WHITE + f"    - {reason}")

    if analysis.rating != StrengthRating.STRONG:
        print(Fore.YELLOW + Style.BRIGHT + "\n  Suggestions for improvement:")
        for suggestion in analysis.suggestions:
            print(Fore.YELLOW + f"    - {suggestion}")

    print(Fore.CYAN + "=" * 55 + "\n")


def prompt_password(prompt_text: str = "Enter password to analyze: ") -> str:
    """Securely prompt the user for a password using getpass.

    Falls back to a visible ``input()`` prompt only if getpass fails
    (e.g., in some non-interactive/IDE environments), with a clear warning.

    Args:
        prompt_text: The prompt message to display.

    Returns:
        The entered password string.
    """
    try:
        return getpass.getpass(Fore.CYAN + prompt_text + Style.RESET_ALL)
    except (getpass.GetPassWarning, Exception):  # pragma: no cover
        print(Fore.YELLOW + "Warning: secure input unavailable in this environment; input will be visible.")
        return input(prompt_text)


def handle_single_check(session_results: List[Tuple[str, PasswordAnalysis]]) -> None:
    """Handle the 'check a single password' menu option.

    Prompts for a password, evaluates it, displays the result, and
    appends it to the session results list for later export.

    Args:
        session_results: The running list of (password, analysis) tuples
            for the current session; mutated in place.
    """
    password = prompt_password()

    if not password:
        print(Fore.RED + "No password entered. Please try again.")
        return

    try:
        analysis = evaluate_password(password)
    except ValueError as exc:
        print(Fore.RED + f"Error: {exc}")
        return

    display_analysis(password, analysis)
    session_results.append((password, analysis))
    logger.info("Password checked. Rating=%s Score=%d", analysis.rating.value, analysis.score)


def handle_file_analysis(session_results: List[Tuple[str, PasswordAnalysis]]) -> None:
    """Handle the 'analyze passwords from a text file' menu option.

    Reads a newline-separated list of passwords from a user-specified
    file, evaluates each one, and appends results to the session list.

    Args:
        session_results: The running list of (password, analysis) tuples
            for the current session; mutated in place.
    """
    filepath = input(Fore.CYAN + "Enter path to a text file (one password per line): " + Style.RESET_ALL).strip()

    if not filepath:
        print(Fore.RED + "No file path provided.")
        return

    if not os.path.isfile(filepath):
        print(Fore.RED + f"File not found: {filepath}")
        logger.warning("File analysis failed: file not found at %s", filepath)
        return

    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            passwords = [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        print(Fore.RED + f"Could not read file: {exc}")
        logger.error("File read error for %s: %s", filepath, exc)
        return

    if not passwords:
        print(Fore.YELLOW + "The file is empty. No passwords to analyze.")
        return

    print(Fore.GREEN + f"\nFound {len(passwords)} password(s). Analyzing...\n")

    for password in passwords:
        try:
            analysis = evaluate_password(password)
        except ValueError:
            continue
        display_analysis(password, analysis)
        session_results.append((password, analysis))

    logger.info("Batch file analysis complete. File=%s Count=%d", filepath, len(passwords))


def handle_export(session_results: List[Tuple[str, PasswordAnalysis]]) -> None:
    """Handle the 'export session report' menu option.

    Exports all analyzed passwords in the current session to both a
    ``.txt`` and a ``.json`` report file in the ``reports/`` directory.

    Args:
        session_results: The list of (password, analysis) tuples to export.
    """
    if not session_results:
        print(Fore.YELLOW + "No passwords have been analyzed yet this session.")
        return

    try:
        txt_path = export_txt_report(session_results)
        json_path = export_json_report(session_results)
    except OSError as exc:
        print(Fore.RED + f"Failed to export report: {exc}")
        logger.error("Report export failed: %s", exc)
        return

    print(Fore.GREEN + "\nReports exported successfully:")
    print(Fore.WHITE + f"  TXT  -> {txt_path}")
    print(Fore.WHITE + f"  JSON -> {json_path}")
    logger.info("Reports exported: %s, %s", txt_path, json_path)


def handle_summary(session_results: List[Tuple[str, PasswordAnalysis]]) -> None:
    """Handle the 'view session summary' menu option.

    Prints an aggregate breakdown of how many passwords fell into each
    strength rating during the current session.

    Args:
        session_results: The list of (password, analysis) tuples analyzed
            so far this session.
    """
    if not session_results:
        print(Fore.YELLOW + "No passwords have been analyzed yet this session.")
        return

    counts = {rating: 0 for rating in StrengthRating}
    for _, analysis in session_results:
        counts[analysis.rating] += 1

    total = len(session_results)
    avg_score = sum(a.score for _, a in session_results) / total

    print(Fore.CYAN + Style.BRIGHT + "\nSession Summary")
    print(Fore.CYAN + "-" * 30)
    print(Fore.WHITE + f"  Total passwords checked : {total}")
    print(Fore.WHITE + f"  Average score           : {avg_score:.1f}/100")
    for rating in StrengthRating:
        color = RATING_COLORS[rating]
        print(color + f"  {rating.value:<8} : {counts[rating]}")
    print(Fore.CYAN + "-" * 30 + "\n")


def main() -> None:
    """Run the interactive Password Strength Checker CLI application."""
    ensure_directories()
    logger.info("Application started.")
    print_banner()

    session_results: List[Tuple[str, PasswordAnalysis]] = []

    menu_actions = {
        "1": handle_single_check,
        "2": handle_file_analysis,
        "3": handle_export,
        "4": handle_summary,
    }

    while True:
        print_menu()
        choice = input(Fore.CYAN + "Select an option (1-5): " + Style.RESET_ALL).strip()

        if choice == "5":
            print(Fore.GREEN + "\nThank you for using Password Strength Checker. Stay secure!\n")
            logger.info("Application exited normally.")
            break

        action = menu_actions.get(choice)
        if action is None:
            print(Fore.RED + "Invalid option. Please choose a number between 1 and 5.")
            continue

        try:
            action(session_results)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001 - top-level safety net for CLI stability
            print(Fore.RED + f"An unexpected error occurred: {exc}")
            logger.exception("Unhandled exception in menu action '%s'", choice)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\nInterrupted by user. Exiting safely.\n")
        logger.info("Application interrupted by user (KeyboardInterrupt).")
        sys.exit(0)
