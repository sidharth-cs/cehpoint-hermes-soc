"""Load JSON documents and validate them against the project's JSON Schemas."""
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from .paths import SCHEMAS


class ValidationError(ValueError):
    """Raised when a document does not match its schema. Carries every problem found."""

    def __init__(self, what: str, problems: list[str]):
        self.problems = problems
        super().__init__(f"{what} failed validation: " + "; ".join(problems))


@lru_cache(maxsize=None)
def _validator(schema_name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / schema_name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(doc: dict, schema_name: str, what: str) -> dict:
    errors = sorted(_validator(schema_name).iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        raise ValidationError(what, [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors])
    return doc


def load_alert(path: Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise ValidationError("alert", [f"not valid JSON: {exc}"]) from exc
    return validate(doc, "alert.schema.json", "alert")
