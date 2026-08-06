"""Interactive, local first-run setup for the Windows launcher.

This module deliberately imports only the Python standard library so it can check
and install project dependencies before the main application is imported.
"""

from __future__ import annotations

import argparse
import getpass
import importlib.metadata
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable


REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s*(?:==|>=|~=)\s*[^\s;]+)?\s*$"
)
API_KEYS = (
    (
        "ABUSEIPDB_API_KEY",
        "AbuseIPDB",
        "sender IP reputation will be skipped",
    ),
    (
        "VIRUSTOTAL_API_KEY",
        "VirusTotal",
        "URL and attachment reputation will be skipped",
    ),
)


def project_root() -> Path:
    """Return the extracted project directory regardless of the current folder."""
    return Path(__file__).resolve().parent.parent


def is_yes(value: str) -> bool:
    """Accept the small set of explicit affirmative launcher responses."""
    return value.strip().lower() in {"y", "yes"}


def parse_requirements(requirements_path: Path) -> tuple[list[str], list[str]]:
    """Return simple distribution names and readable notices for skipped lines."""
    requirements: list[str] = []
    notices: list[str] = []
    try:
        lines = requirements_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return requirements, ["Could not read requirements.txt."]

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = REQUIREMENT_PATTERN.match(line)
        if not match:
            notices.append(f"Ignored unsupported requirements line {line_number}: {line}")
            continue
        requirements.append(match.group(1))
    return requirements, notices


def missing_requirements(requirements_path: Path) -> tuple[list[str], list[str]]:
    """Check installed distributions without importing the application or using a network."""
    requirements, notices = parse_requirements(requirements_path)
    missing: list[str] = []
    for requirement in requirements:
        try:
            importlib.metadata.version(requirement)
        except importlib.metadata.PackageNotFoundError:
            missing.append(requirement)
    return missing, notices


def print_missing_requirements(missing: Iterable[str]) -> None:
    """Print a concise dependency list without running package installation."""
    print("Required Python packages are missing:")
    print()
    for package_name in missing:
        print(f"- {package_name}")
    print()


def install_requirements(requirements_path: Path) -> bool:
    """Install project requirements with this exact Python interpreter, once."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements_path)],
            cwd=str(project_root()),
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def persist_user_environment_value(variable_name: str, value: str) -> bool:
    """Persist one secret at Windows user scope without placing it in a command line."""
    if sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Environment",
            0,
            winreg.KEY_SET_VALUE,
        ) as environment_key:
            winreg.SetValueEx(environment_key, variable_name, 0, winreg.REG_SZ, value)
    except (ImportError, OSError):
        return False
    return True


def configure_api_key(variable_name: str, provider_name: str, skipped_message: str) -> None:
    """Optionally collect one hidden API key and retain it for this run."""
    if os.environ.get(variable_name, "").strip():
        print(f"{provider_name}: Configured")
        return

    print(f"{provider_name} API key is not configured.")
    try:
        wants_setup = input("Would you like to configure it now? (y/n): ")
    except EOFError:
        wants_setup = ""
    if not is_yes(wants_setup):
        print(f"{provider_name}: Not configured - {skipped_message}")
        return

    key_value = ""
    for attempt in range(2):
        try:
            key_value = getpass.getpass(f"Paste {provider_name} API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            key_value = ""
        if key_value:
            break
        if attempt == 0:
            print("An empty API key was not saved. Please try once more.")

    if not key_value:
        print(f"{provider_name}: Not configured - {skipped_message}")
        return

    os.environ[variable_name] = key_value
    if persist_user_environment_value(variable_name, key_value):
        print(f"{provider_name}: Configured")
    else:
        print(f"{provider_name}: Configured")
        print(
            "The API key is available for this session, but Windows could not save it permanently."
        )
        print("Configure it manually later with the documented environment-variable command.")


def ensure_requirements(requirements_path: Path) -> bool:
    """Check requirements once, optionally install once, then recheck."""
    if not requirements_path.is_file():
        print("requirements.txt was not found in the extracted project folder.")
        return False

    missing, notices = missing_requirements(requirements_path)
    for notice in notices:
        print(notice)
    if any(notice == "Could not read requirements.txt." for notice in notices):
        return False
    if not missing:
        print("Requirements: Ready")
        return True

    print_missing_requirements(missing)
    try:
        answer = input("Would you like to install the required packages now? (y/n): ")
    except EOFError:
        answer = ""
    if not is_yes(answer):
        print("Required packages were not installed.")
        print("Run this command from the extracted project folder when ready:")
        print("python -m pip install -r requirements.txt")
        print("Phish Pharm cannot start until its required packages are installed.")
        return False

    if not install_requirements(requirements_path):
        print("Requirements installation failed.")
        print("The VM may not have internet access, permission to install packages, or access to the Python package index.")
        print("Manual command:")
        print("python -m pip install -r requirements.txt")
        print("Optional user-level fallback:")
        print("python -m pip install --user -r requirements.txt")
        return False

    missing, notices = missing_requirements(requirements_path)
    for notice in notices:
        print(notice)
    if any(notice == "Could not read requirements.txt." for notice in notices):
        return False
    if missing:
        print("Requirements installation was incomplete. Phish Pharm cannot start yet.")
        print_missing_requirements(missing)
        return False

    print("Requirements: Ready")
    return True


def start_watcher(watch_folder: Path, output_folder: Path, report_format: str) -> int:
    """Start normal watch mode with the current session's environment values."""
    main_path = project_root() / "src" / "main.py"
    if not main_path.is_file():
        print("src/main.py was not found in the extracted project folder.")
        return 1
    environment = os.environ.copy()
    environment["PHISH_PHARM_REQUIREMENTS_READY"] = "1"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(main_path),
                "--watch",
                str(watch_folder),
                "--output",
                str(output_folder),
                "--format",
                report_format,
            ],
            cwd=str(project_root()),
            env=environment,
            check=False,
        )
    except OSError:
        print("Phish Pharm could not start watch mode.")
        return 1
    return completed.returncode


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    """Parse only the paths passed by the small Windows launcher."""
    parser = argparse.ArgumentParser(description="Interactive Phish Pharm launcher setup.")
    parser.add_argument("--watch", required=True, help="Folder to watch for .eml files.")
    parser.add_argument("--output", required=True, help="Folder for generated reports.")
    parser.add_argument("--format", choices=("md", "html", "both"), default="html")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    """Run guided setup, then delegate watch mode to the normal application entry point."""
    args = parse_args(arguments)
    root = project_root()
    requirements_path = root / "requirements.txt"
    if not ensure_requirements(requirements_path):
        return 1

    for variable_name, provider_name, skipped_message in API_KEYS:
        configure_api_key(variable_name, provider_name, skipped_message)

    return start_watcher(
        Path(args.watch).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
        args.format,
    )


if __name__ == "__main__":
    raise SystemExit(main())
