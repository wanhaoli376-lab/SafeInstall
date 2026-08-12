"""Machine-readable JSON report renderer."""

from __future__ import annotations

import json

from safeinstall.models import ScanReport
from safeinstall.redaction import redact_data


def render_json(report: ScanReport, *, indent: int = 2) -> str:
    """Serialize the stable report schema after a final recursive redaction pass."""

    data = redact_data(report.model_dump(mode="json"))
    return json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=False)
