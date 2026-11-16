"""Storage for evidence after it has been redacted (see sanitize.py) -
separate from any credential vault.

TODO: local storage (SQLite/JSON) for the first version, extensible to
S3 later.
"""

from pathlib import Path


class EvidenceStore:
    def __init__(self, storage_dir: Path) -> None:
        self.storage_dir = storage_dir

    def save(self, finding_id: str, evidence: dict) -> None:
        raise NotImplementedError

    def load(self, finding_id: str) -> dict:
        raise NotImplementedError
