from __future__ import annotations

import json
from typing import Any


def _serialize_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def logfmt(event: str, **fields: Any) -> str:
    parts = [f"event={event}"]
    for key in sorted(fields):
        value = fields[key]
        parts.append(f"{key}={_serialize_value(value)}")
    return " ".join(parts)

