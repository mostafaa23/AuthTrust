"""SARIF export for integration with GitHub/GitLab code scanning.

TODO: convert Finding -> a SARIF result object per the official spec.
"""

from pathlib import Path


def export_sarif(findings: list, output_path: Path) -> None:
    raise NotImplementedError
