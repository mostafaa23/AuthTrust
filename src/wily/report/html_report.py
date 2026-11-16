"""Interactive HTML report for viewing (Jinja2 template in
report/templates/).

TODO: a table sortable/filterable by severity/category/asset.
"""

from pathlib import Path


def export_html(findings: list, output_path: Path) -> None:
    raise NotImplementedError
