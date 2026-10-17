#!/usr/bin/env python3
"""Validate optional server-side GitHub App configuration safely."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from synapseaudit.github import GitHubConfig, GitHubConfigurationError


def main() -> int:
    try:
        configuration = GitHubConfig.from_environment()
    except GitHubConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if configuration is None:
        print("GitHub App integration is disabled; local-only mode is active.")
    else:
        print("GitHub App configuration is valid; private-key contents were not read.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
