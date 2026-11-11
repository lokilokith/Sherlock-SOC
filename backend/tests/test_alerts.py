import pytest
from pydantic import ValidationError

from app.schemas.alerts import Alert


def test_valid_alert_parsing() -> None:
    alert = Alert(
        alert_id="alert-001",
        title="Suspicious process",
        severity="high",
        event_ids=["sysmon-001"],
    )

    assert alert.alert_id == "alert-001"
    assert alert.event_ids == ["sysmon-001"]


def test_invalid_alert_structure_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Alert(
            alert_id="alert-001",
            title="Suspicious process",
            severity="high",
        )
