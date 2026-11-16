"""Load every rule file under templates/rules/**/*.yaml and validate it
against templates.schema.Template before adding it to the run list.

TODO: PyYAML.safe_load + Template.model_validate for each file, collecting
errors instead of stopping at the first one (so `wily templates validate`
can report on all of them).
"""

from pathlib import Path


def load_rules(rules_dir: Path) -> list:
    raise NotImplementedError


def validate_rules(rules_dir: Path) -> dict:
    """Return {valid: [...], invalid: [(file, error), ...]}"""
    raise NotImplementedError
