from app.services.detection import detect_behavioural_alerts
from app.services.ingestion import normalize_sysmon_event


def _event(event_id: str, image: str, command_line: str = "", *, process_id: int | None = None,
           parent_image: str = "", event_type: str = "process_create", destination_ip: str = ""):
    payload = {
        "EventID": 3 if event_type == "network_connection" else 1,
        "EventRecordID": event_id,
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "Image": image,
        "CommandLine": command_line,
        "ProcessId": process_id,
        "event_type": event_type,
        "DestinationIp": destination_ip,
    }
    if parent_image:
        payload["ParentImage"] = parent_image
    return normalize_sysmon_event(payload)


def _metrics(predictions: dict[str, list[bool]], expected: dict[str, list[bool]]) -> dict[str, float]:
    results = {}
    for rule_id in expected:
        predicted = predictions[rule_id]
        truth = expected[rule_id]
        tp = sum(p and y for p, y in zip(predicted, truth))
        fp = sum(p and not y for p, y in zip(predicted, truth))
        fn = sum(not p and y for p, y in zip(predicted, truth))
        tn = sum(not p and not y for p, y in zip(predicted, truth))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        results[rule_id] = round(f1, 3)
        results[f"{rule_id}_precision"] = round(precision, 3)
        results[f"{rule_id}_recall"] = round(recall, 3)
        results[f"{rule_id}_specificity"] = round(specificity, 3)
    return results


def test_labelled_detection_quality_synthetic_scenarios() -> None:
    scenarios = [
        (_event("benign-ps", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe Get-Date"), []),
        (_event("suspicious-ps", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -EncodedCommand U2ltdWxhdGVk"), ["SOC-001"]),
        (_event("office-cmd-suspicious", r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", parent_image=r"C:\Office\WINWORD.EXE"), ["SOC-002"]),
        (_event("office-cmd-benign", r"C:\Windows\System32\cmd.exe", "", parent_image=r"C:\Office\WINWORD.EXE"), []),
        (_event("admin-script", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -File C:\\ProgramData\\inventory.ps1", process_id=1001), []),
        (_event("script-network", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile", process_id=1002), ["SOC-001", "SOC-003"]),
        (_event("script-network-event", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "", process_id=1002, event_type="network_connection", destination_ip="203.0.113.10"), ["SOC-003"]),
    ]
    predictions = {rule_id: [] for rule_id in ("SOC-001", "SOC-002", "SOC-003")}
    expected = {rule_id: [] for rule_id in predictions}
    all_events = [item for item, _ in scenarios]

    def triggered(rule_id: str) -> set[str]:
        return {alert.source_event_ids[0] for alert in detect_behavioural_alerts(all_events) if alert.rule_id == rule_id}

    detected = {rule_id: triggered(rule_id) for rule_id in predictions}
    detected_event_ids = {
        rule_id: {
            event_id
            for alert in detect_behavioural_alerts(all_events)
            if alert.rule_id == rule_id
            for event_id in alert.source_event_ids
        }
        for rule_id in predictions
    }
    for event, labels in scenarios:
        for rule_id in predictions:
            predicted = event.event_id in detected_event_ids[rule_id]
            predictions[rule_id].append(predicted)
            expected[rule_id].append(rule_id in labels)

    metrics = _metrics(predictions, expected)
    assert metrics["SOC-001_precision"] == 1.0
    assert metrics["SOC-001_recall"] == 1.0
    assert metrics["SOC-002_precision"] == 1.0
    assert metrics["SOC-003_precision"] == 1.0
