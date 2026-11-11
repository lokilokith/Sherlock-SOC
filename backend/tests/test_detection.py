from app.services.detection import detect_alerts, detect_behavioural_alerts
from app.services.ingestion import normalize_sysmon_event


def normalized(command_line: str, process_name: str = "powershell.exe"):
    return normalize_sysmon_event(
        {
            "EventID": 1,
            "UtcTime": "2026-11-03T09:00:00Z",
            "Computer": "SIMULATED-WIN01",
            "Image": process_name,
            "CommandLine": command_line,
            "EventRecordID": "evt-detection",
        }
    )


def test_normal_powershell_does_not_trigger_alert() -> None:
    assert detect_alerts([normalized("powershell.exe -Command Get-Date")]) == []


def test_encoded_powershell_triggers_medium_alert() -> None:
    alerts = detect_alerts([normalized("powershell.exe -EncodedCommand U2ltdWxhdGVk")])

    assert len(alerts) == 1
    assert alerts[0].severity == "medium"
    assert alerts[0].matched_indicators == ["encoded_command"]
    assert alerts[0].source_event_ids == ["evt-detection"]


def test_multiple_indicators_are_high_severity() -> None:
    alerts = detect_alerts(
        [normalized("pwsh.exe -NoProfile -WindowStyle Hidden -Command Get-Date", "pwsh.exe")]
    )

    assert alerts[0].severity == "high"
    assert alerts[0].matched_indicators == ["hidden_window", "no_profile"]


def test_noprofile_alone_is_medium_not_high() -> None:
    alerts = detect_alerts([normalized("powershell.exe -NoProfile -Command Get-Date")])

    assert alerts[0].severity == "medium"


def test_hidden_window_alone_is_medium_not_high() -> None:
    alerts = detect_alerts(
        [normalized("powershell.exe -WindowStyle Hidden -Command Get-Date")]
    )

    assert alerts[0].severity == "medium"


def test_alert_evidence_references_source_event() -> None:
    alerts = detect_alerts([normalized("powershell.exe -WindowStyle Hidden -Command Get-Date")])

    assert alerts[0].evidence_references[0].event_id == "evt-detection"
    assert "command_line" in alerts[0].evidence_references[0].fields


def test_office_spawning_shell_generates_evidence_alert() -> None:
    event = normalize_sysmon_event({
        "EventID": 1,
        "EventRecordID": "office-child",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "CommandLine": "cmd.exe /c whoami",
    })
    alerts = detect_behavioural_alerts([event])
    alert = next(item for item in alerts if item.rule_id == "SOC-002")
    assert alert.severity == "high"
    assert alert.source_event_ids == ["office-child"]
    assert "parent_process_name" in alert.evidence_references[0].fields


def test_process_network_correlation_links_both_events() -> None:
    process = normalize_sysmon_event({
        "EventID": 1,
        "EventRecordID": "script-process",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "ProcessId": 4312,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -Command test",
    })
    network = normalize_sysmon_event({
        "EventID": 3,
        "EventRecordID": "script-network",
        "UtcTime": "2026-11-03T09:00:01Z",
        "Computer": "WIN01",
        "ProcessId": 4312,
        "DestinationIp": "203.0.113.10",
        "Image": "powershell.exe",
        "event_type": "network_connection",
    })
    alerts = detect_behavioural_alerts([process, network])
    alert = next(item for item in alerts if item.rule_id == "SOC-003")
    assert alert.source_event_ids == ["script-process", "script-network"]


def test_office_legitimate_child_process_is_not_a_shell_alert() -> None:
    event = normalize_sysmon_event({
        "EventID": 1,
        "EventRecordID": "office-excel-child",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "Image": r"C:\Windows\System32\notepad.exe",
        "ParentImage": r"C:\Program Files\Microsoft Office\EXCEL.EXE",
        "ParentProcessName": "EXCEL.EXE",
        "CommandLine": "notepad.exe report.txt",
    })
    assert not [item for item in detect_behavioural_alerts([event]) if item.rule_id == "SOC-002"]


def test_office_shell_without_command_context_does_not_alert() -> None:
    event = normalize_sysmon_event({
        "EventID": 1,
        "EventRecordID": "office-cmd-empty",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "Image": r"C:\Windows\System32\cmd.exe",
        "ParentImage": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "ParentProcessName": "WINWORD.EXE",
        "CommandLine": "",
    })
    assert not [item for item in detect_behavioural_alerts([event]) if item.rule_id == "SOC-002"]


def test_network_correlation_requires_matching_process_pid() -> None:
    process = normalize_sysmon_event({
        "EventID": 1,
        "EventRecordID": "admin-script",
        "UtcTime": "2026-11-03T09:00:00Z",
        "Computer": "WIN01",
        "ProcessId": 5000,
        "Image": r"C:\Windows\System32\WindowsPowerShell\powershell.exe",
        "CommandLine": r"powershell.exe -File C:\ProgramData\inventory.ps1",
    })
    unrelated_network = normalize_sysmon_event({
        "EventID": 3,
        "EventRecordID": "unmatched-network",
        "UtcTime": "2026-11-03T09:00:01Z",
        "Computer": "WIN01",
        "ProcessId": 5001,
        "DestinationIp": "203.0.113.20",
        "Image": "powershell.exe",
    })
    assert not [item for item in detect_behavioural_alerts([process, unrelated_network]) if item.rule_id == "SOC-003"]
