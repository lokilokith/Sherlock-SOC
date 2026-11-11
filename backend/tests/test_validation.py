from app.services.validation import dataset_metadata, run_validation


def test_validation_uses_versioned_dataset_and_real_detection_metrics() -> None:
    report = run_validation()

    assert dataset_metadata().case_count == 32
    assert report.dataset.dataset_id == "soc-001-baseline"
    assert report.metrics.tp == 15
    assert report.metrics.fp == 1
    assert report.metrics.fn == 1
    assert report.metrics.tn == 15
    assert report.metrics.f1 == 0.9375
    assert len(report.cases) == report.dataset.case_count


def test_validation_reports_missing_observability_without_mutating_alerts() -> None:
    report = run_validation()
    empty_command = next(case for case in report.cases if case.case_id == "empty-command")

    assert empty_command.detected is False
    assert "command_line" in empty_command.missing_fields
    assert empty_command.classification == "TN"
