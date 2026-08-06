import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import bootstrap


class BootstrapTests(unittest.TestCase):
    def test_parse_requirements_ignores_blanks_comments_and_versions(self) -> None:
        requirements_path = Path("requirements.txt")
        with patch.object(
            Path,
            "read_text",
            return_value="\n# note\nrequests\ntldextract==5.3.1\nexample>=1.2\nother~=2.0\n",
        ):
            requirements, notices = bootstrap.parse_requirements(requirements_path)

        self.assertEqual(requirements, ["requests", "tldextract", "example", "other"])
        self.assertEqual(notices, [])

    def test_parse_requirements_skips_unsupported_lines_safely(self) -> None:
        requirements_path = Path("requirements.txt")
        with patch.object(Path, "read_text", return_value="-r another.txt\nrequests\n"):
            requirements, notices = bootstrap.parse_requirements(requirements_path)

        self.assertEqual(requirements, ["requests"])
        self.assertIn("Ignored unsupported requirements line 1", notices[0])

    def test_unreadable_requirements_file_stops_safely(self) -> None:
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(
                bootstrap,
                "missing_requirements",
                return_value=([], ["Could not read requirements.txt."]),
            ),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertFalse(bootstrap.ensure_requirements(Path("requirements.txt")))

    def test_missing_requirements_reports_only_missing_distributions(self) -> None:
        with (
            patch.object(bootstrap, "parse_requirements", return_value=(["requests", "tldextract"], [])),
            patch.object(
                bootstrap.importlib.metadata,
                "version",
                side_effect=["2.0", bootstrap.importlib.metadata.PackageNotFoundError],
            ),
        ):
            missing, notices = bootstrap.missing_requirements(Path("requirements.txt"))

        self.assertEqual(missing, ["tldextract"])
        self.assertEqual(notices, [])

    def test_yes_answers_are_explicit_and_case_insensitive(self) -> None:
        for value in ("y", "Y", "yes", "YES", "YeS"):
            self.assertTrue(bootstrap.is_yes(value))
        for value in ("n", "", "anything else"):
            self.assertFalse(bootstrap.is_yes(value))

    def test_declining_dependency_install_stops_cleanly(self) -> None:
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(bootstrap, "missing_requirements", return_value=(["tldextract"], [])),
            patch("builtins.input", return_value="n"),
            patch.object(bootstrap, "install_requirements") as install,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                ready = bootstrap.ensure_requirements(Path("requirements.txt"))

        self.assertFalse(ready)
        install.assert_not_called()
        self.assertIn("Phish Pharm cannot start", console_output.getvalue())

    def test_install_uses_current_python_and_requirements_path(self) -> None:
        requirements_path = Path("folder with spaces") / "requirements.txt"
        with patch.object(bootstrap.subprocess, "run") as run:
            run.return_value.returncode = 0
            installed = bootstrap.install_requirements(requirements_path)

        self.assertTrue(installed)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], [sys.executable, "-m", "pip", "install"])
        self.assertEqual(command[-2:], ["-r", str(requirements_path)])

    def test_successful_install_rechecks_dependencies(self) -> None:
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(
                bootstrap,
                "missing_requirements",
                side_effect=[(["tldextract"], []), ([], [])],
            ) as missing,
            patch("builtins.input", return_value="yes"),
            patch.object(bootstrap, "install_requirements", return_value=True),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertTrue(bootstrap.ensure_requirements(Path("requirements.txt")))
        self.assertEqual(missing.call_count, 2)

    def test_successful_pip_with_missing_packages_stops(self) -> None:
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(
                bootstrap,
                "missing_requirements",
                side_effect=[(["tldextract"], []), (["tldextract"], [])],
            ),
            patch("builtins.input", return_value="y"),
            patch.object(bootstrap, "install_requirements", return_value=True),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertFalse(bootstrap.ensure_requirements(Path("requirements.txt")))

    def test_api_key_setup_uses_hidden_input_and_never_prints_secret(self) -> None:
        secret = "not-for-console-output"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("builtins.input", return_value="yes"),
            patch.object(bootstrap.getpass, "getpass", return_value=f"  {secret}  "),
            patch.object(bootstrap, "persist_user_environment_value", return_value=True) as persist,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                bootstrap.configure_api_key("ABUSEIPDB_API_KEY", "AbuseIPDB", "sender IP reputation will be skipped")
            self.assertEqual(os.environ["ABUSEIPDB_API_KEY"], secret)

        persist.assert_called_once_with("ABUSEIPDB_API_KEY", secret)
        self.assertNotIn(secret, console_output.getvalue())

    def test_configured_keys_are_not_prompted_for_or_displayed(self) -> None:
        abuseipdb_key = "already-configured-abuseipdb"
        virustotal_key = "already-configured-virustotal"
        with (
            patch.dict(
                os.environ,
                {
                    "ABUSEIPDB_API_KEY": abuseipdb_key,
                    "VIRUSTOTAL_API_KEY": virustotal_key,
                },
                clear=True,
            ),
            patch("builtins.input") as prompt,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                bootstrap.configure_api_key(
                    "ABUSEIPDB_API_KEY", "AbuseIPDB", "sender IP reputation will be skipped"
                )
                bootstrap.configure_api_key(
                    "VIRUSTOTAL_API_KEY", "VirusTotal", "URL and attachment reputation will be skipped"
                )

        output = console_output.getvalue()
        prompt.assert_not_called()
        self.assertIn("AbuseIPDB: Configured", output)
        self.assertIn("VirusTotal: Configured", output)
        self.assertNotIn(abuseipdb_key, output)
        self.assertNotIn(virustotal_key, output)

    def test_empty_api_key_allows_one_retry_then_skips(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("builtins.input", return_value="y"),
            patch.object(bootstrap.getpass, "getpass", side_effect=[" ", ""]),
            patch.object(bootstrap, "persist_user_environment_value") as persist,
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                bootstrap.configure_api_key("VIRUSTOTAL_API_KEY", "VirusTotal", "URL and attachment reputation will be skipped")

        persist.assert_not_called()
        self.assertIn("Please try once more", console_output.getvalue())
        self.assertIn("Not configured", console_output.getvalue())

    def test_registry_persistence_failure_keeps_key_for_current_session(self) -> None:
        secret = "session-only-secret"
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("builtins.input", return_value="y"),
            patch.object(bootstrap.getpass, "getpass", return_value=secret),
            patch.object(bootstrap, "persist_user_environment_value", return_value=False),
        ):
            console_output = io.StringIO()
            with redirect_stdout(console_output):
                bootstrap.configure_api_key("ABUSEIPDB_API_KEY", "AbuseIPDB", "sender IP reputation will be skipped")
            self.assertEqual(os.environ["ABUSEIPDB_API_KEY"], secret)

        self.assertIn("available for this session", console_output.getvalue())
        self.assertNotIn(secret, console_output.getvalue())

    def test_main_passes_new_session_environment_to_watcher(self) -> None:
        with (
            patch.object(bootstrap, "ensure_requirements", return_value=True),
            patch.object(bootstrap, "configure_api_key") as configure,
            patch.object(bootstrap, "start_watcher", return_value=0) as start,
        ):
            result = bootstrap.main(["--watch", "Inbox", "--output", "Reports", "--format", "html"])

        self.assertEqual(result, 0)
        self.assertEqual(configure.call_count, 2)
        self.assertEqual(start.call_args.args[2], "html")

    def test_watcher_inherits_current_session_api_key(self) -> None:
        secret = "session-key-for-child-process"
        with (
            patch.dict(os.environ, {"ABUSEIPDB_API_KEY": secret}, clear=True),
            patch.object(Path, "is_file", return_value=True),
            patch.object(bootstrap.subprocess, "run") as run,
        ):
            run.return_value.returncode = 0
            result = bootstrap.start_watcher(Path("Inbox"), Path("Reports"), "html")

        self.assertEqual(result, 0)
        child_environment = run.call_args.kwargs["env"]
        self.assertEqual(child_environment["ABUSEIPDB_API_KEY"], secret)
        self.assertEqual(child_environment["PHISH_PHARM_REQUIREMENTS_READY"], "1")


if __name__ == "__main__":
    unittest.main()
