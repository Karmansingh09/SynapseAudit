from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from synapseaudit.github import (
    GitHubConfig,
    GitHubConfigurationError,
    GitHubService,
    parse_trusted_proxies,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = PROJECT_ROOT / "scripts" / "check_github_config.py"
CONFIG_NAMES = (
    "SYNAPSEAUDIT_GITHUB_APP_ID",
    "SYNAPSEAUDIT_GITHUB_APP_SLUG",
    "SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE",
    "SYNAPSEAUDIT_GITHUB_CALLBACK_URL",
    "SYNAPSEAUDIT_DASHBOARD_PASSWORD",
)
CALLBACK_URL = "https://audit.example.test/api/github/callback"


class GitHubConfigurationTests(unittest.TestCase):
    @staticmethod
    def blank_environment() -> dict[str, str]:
        environment = os.environ.copy()
        for name in CONFIG_NAMES:
            environment[name] = ""
        environment["SYNAPSEAUDIT_TRUSTED_PROXIES"] = ""
        return environment

    @staticmethod
    def write_key(directory: str, *, name: str = "app.pem", mode: int = 0o600) -> Path:
        path = Path(directory) / name
        path.write_text("SYNTHETIC_PRIVATE_KEY_CONTENT", encoding="utf-8")
        path.chmod(mode)
        return path

    def valid_environment(self, key_path: Path) -> dict[str, str]:
        environment = self.blank_environment()
        environment.update(
            {
                "SYNAPSEAUDIT_GITHUB_APP_ID": "123",
                "SYNAPSEAUDIT_GITHUB_APP_SLUG": "synapseaudit",
                "SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE": str(key_path),
                "SYNAPSEAUDIT_GITHUB_CALLBACK_URL": CALLBACK_URL,
                "SYNAPSEAUDIT_DASHBOARD_PASSWORD": "synthetic-test-password",
            }
        )
        return environment

    @staticmethod
    def run_preflight(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PREFLIGHT)],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_blank_configuration_keeps_local_only_mode(self) -> None:
        environment = self.blank_environment()

        result = self.run_preflight(environment)

        self.assertEqual(result.returncode, 0)
        self.assertIn("local-only mode is active", result.stdout)
        self.assertIsNone(GitHubConfig.from_environment(environment))
        self.assertFalse(GitHubService.from_environment({}).configured)

    def test_partial_configuration_lists_missing_variable_names_only(self) -> None:
        environment = self.blank_environment()
        environment["SYNAPSEAUDIT_GITHUB_APP_ID"] = "123"

        result = self.run_preflight(environment)
        diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        for name in CONFIG_NAMES[1:]:
            self.assertIn(name, diagnostics)
        self.assertNotIn("123", diagnostics)
        with self.assertRaisesRegex(GitHubConfigurationError, "missing:"):
            GitHubConfig.from_environment(environment)

    def test_invalid_app_id_is_rejected_without_echoing_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory)
            environment = self.valid_environment(key_path)
            environment["SYNAPSEAUDIT_GITHUB_APP_ID"] = "APP_ID_SECRET_VALUE"

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("positive integer", diagnostics)
        self.assertNotIn("APP_ID_SECRET_VALUE", diagnostics)

    def test_callback_scheme_and_path_are_strictly_validated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory)
            for callback in (
                "http://audit.example.test/api/github/callback",
                "https://audit.example.test/wrong-callback",
            ):
                with self.subTest(callback=callback):
                    environment = self.valid_environment(key_path)
                    environment["SYNAPSEAUDIT_GITHUB_CALLBACK_URL"] = callback
                    result = self.run_preflight(environment)
                    diagnostics = result.stdout + result.stderr

                    self.assertEqual(result.returncode, 2)
                    self.assertIn("HTTPS", diagnostics)
                    self.assertNotIn(callback, diagnostics)
                    with self.assertRaises(GitHubConfigurationError):
                        GitHubConfig.from_environment(environment)

    def test_callback_credentials_and_fragment_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory)
            for callback in (
                "https://user:password@audit.example.test/api/github/callback",
                "https://audit.example.test/api/github/callback#fragment",
            ):
                with self.subTest(callback=callback):
                    environment = self.valid_environment(key_path)
                    environment["SYNAPSEAUDIT_GITHUB_CALLBACK_URL"] = callback
                    with self.assertRaises(GitHubConfigurationError):
                        GitHubConfig.from_environment(environment)

    def test_missing_key_file_is_rejected_without_echoing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_path = Path(directory) / "secret-key-path" / "app.pem"
            environment = self.valid_environment(missing_path)

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("private key file is unavailable", diagnostics)
        self.assertNotIn(str(missing_path), diagnostics)

    def test_permissive_key_permissions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory, mode=0o640)
            environment = self.valid_environment(key_path)

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("owner-only", diagnostics)

    def test_restrictive_key_permissions_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory, mode=0o600)
            environment = self.valid_environment(key_path)

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr
            configuration = GitHubConfig.from_environment(environment)

        self.assertEqual(result.returncode, 0)
        self.assertIn("configuration is valid", result.stdout)
        self.assertIsNotNone(configuration)
        self.assertNotIn(str(key_path), diagnostics)
        self.assertNotIn("SYNTHETIC_PRIVATE_KEY_CONTENT", diagnostics)

    def test_preflight_never_leaks_environment_values_or_key_contents(self) -> None:
        secret_value = "DO_NOT_PRINT_THIS_CONFIGURATION_VALUE"
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory, name="secret-key-path.pem")
            key_path.write_text(secret_value, encoding="utf-8")
            environment = self.valid_environment(key_path)
            environment["SYNAPSEAUDIT_GITHUB_APP_ID"] = secret_value

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret_value, diagnostics)
        self.assertNotIn(str(key_path), diagnostics)

    def test_missing_dashboard_password_when_github_configured_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory)
            environment = self.valid_environment(key_path)
            environment["SYNAPSEAUDIT_DASHBOARD_PASSWORD"] = ""

            result = self.run_preflight(environment)
            diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("SYNAPSEAUDIT_DASHBOARD_PASSWORD", diagnostics)
        with self.assertRaisesRegex(GitHubConfigurationError, "SYNAPSEAUDIT_DASHBOARD_PASSWORD"):
            GitHubConfig.from_environment(environment)

    def test_trusted_proxies_preflight_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = self.write_key(directory)
            environment = self.valid_environment(key_path)
            environment["SYNAPSEAUDIT_TRUSTED_PROXIES"] = "127.0.0.1, ::1, 192.168.0.0/16"

            result = self.run_preflight(environment)
            self.assertEqual(result.returncode, 0)
            config = GitHubConfig.from_environment(environment)
            self.assertIsNotNone(config)
            self.assertEqual(len(config.trusted_proxies), 3)

    def test_invalid_trusted_proxies_preflight_rejection(self) -> None:
        environment = self.blank_environment()
        environment["SYNAPSEAUDIT_TRUSTED_PROXIES"] = "127.0.0.1, invalid-host"

        result = self.run_preflight(environment)
        diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid-host", diagnostics)
        with self.assertRaises(GitHubConfigurationError):
            GitHubConfig.from_environment(environment)

    def test_empty_entry_in_trusted_proxies_is_rejected(self) -> None:
        environment = self.blank_environment()
        environment["SYNAPSEAUDIT_TRUSTED_PROXIES"] = "127.0.0.1,,::1"

        result = self.run_preflight(environment)
        diagnostics = result.stdout + result.stderr

        self.assertEqual(result.returncode, 2)
        self.assertIn("empty entry", diagnostics)
        with self.assertRaises(GitHubConfigurationError):
            GitHubConfig.from_environment(environment)


if __name__ == "__main__":
    unittest.main()
