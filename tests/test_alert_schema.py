import json

import pytest

from soc_agent.validation import ValidationError, load_alert, validate
from tests.conftest import SAMPLE, clone


def test_sample_alert_is_valid():
    assert load_alert(SAMPLE)["alert_id"] == "ALR-2026-0001"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda a: a.pop("entities"), "entities"),
        (lambda a: a.update(severity_hint="urgent"), "severity_hint"),
        (lambda a: a["entities"].update(source_ips=["999.1.1.1"]), "source_ips"),
        (lambda a: a.update(data_provenance="production"), "data_provenance"),
        (lambda a: a.update(alert_id="12345"), "alert_id"),
        (lambda a: a.update(unexpected_field=1), "unexpected_field"),
    ],
)
def test_invalid_alerts_are_rejected(alert, mutate, expected):
    bad = clone(alert)
    mutate(bad)
    with pytest.raises(ValidationError) as exc:
        validate(bad, "alert.schema.json", "alert")
    assert expected in str(exc.value)


def test_non_json_alert_file_is_rejected(tmp_path):
    f = tmp_path / "broken.json"
    f.write_text("{not json")
    with pytest.raises(ValidationError, match="not valid JSON"):
        load_alert(f)
