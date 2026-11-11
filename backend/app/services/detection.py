import re
from dataclasses import dataclass

from app.schemas.alerts import Alert, EvidenceReference
from app.schemas.events import SecurityEvent


RULE_ID = "SOC-001"
RULE_NAME = "Suspicious PowerShell Execution"
RULE_VERSION = "2.0.0"


DETECTION_RULES = [
    {
        "rule_id": "SOC-001",
        "name": RULE_NAME,
        "description": "Detects potentially suspicious PowerShell options without alerting on ordinary PowerShell use.",
        "severity": "medium",
        "status": "enabled",
        "version": RULE_VERSION,
        "telemetry_requirements": ["process_create", "process_name", "command_line"],
        "mitre_techniques": ["T1059.001"],
        "false_positive_considerations": ["Administrative automation may legitimately use -NoProfile or hidden windows."],
        "rationale": "Encoded or hidden execution is consistent with defensive evasion or payload delivery.",
        "investigation_steps": ["Review the complete command line", "Inspect parent process context", "Check the destination host for follow-on network or file activity"],
    },
    {
        "rule_id": "SOC-002",
        "name": "Office Application Spawning Command Shell",
        "description": "Detects an office process creating PowerShell, cmd, or a scripting interpreter.",
        "severity": "high",
        "status": "enabled",
        "version": "1.0.0",
        "telemetry_requirements": ["process_create", "process_name", "parent_process_name"],
        "mitre_techniques": ["T1059.003", "T1204.002"],
        "false_positive_considerations": ["Approved document automation can spawn child processes."],
        "rationale": "Office-to-shell child execution is uncommon and can indicate malicious document execution.",
        "investigation_steps": ["Identify the document that launched the process", "Inspect macro or external-link activity", "Validate child-process command lines"],
    },
    {
        "rule_id": "SOC-003",
        "name": "Scripting Interpreter Outbound Connection",
        "description": "Correlates scripting interpreter execution with an outbound network connection.",
        "severity": "high",
        "status": "enabled",
        "version": "1.0.0",
        "telemetry_requirements": ["process_create", "network_connection", "process_id", "host_id"],
        "mitre_techniques": ["T1059.001", "T1071.001"],
        "false_positive_considerations": ["Patch, inventory, and approved automation may make scripted outbound connections."],
        "rationale": "A scripting interpreter initiating outbound communication can indicate command and control or payload retrieval.",
        "investigation_steps": ["Inspect the destination IP and domain", "Review the process command line and user", "Correlate with file creation and follow-on child processes"],
    },
]


@dataclass(frozen=True)
class DetectionMatch:
    event: SecurityEvent
    indicators: list[str]


def _has_option(command_line: str, options: tuple[str, ...]) -> bool:
    return any(re.search(option, command_line, re.IGNORECASE) for option in options)


def match_event(event: SecurityEvent) -> DetectionMatch | None:
    process_name = (event.process_name or "").lower()
    command_line = event.command_line or ""
    is_powershell = process_name in {"powershell.exe", "pwsh.exe"} or bool(
        re.search(r"(?<![\w-])(powershell|pwsh)(?:\.exe)?(?![\w-])", command_line, re.I)
    )
    if not is_powershell:
        return None

    indicators: list[str] = []
    if _has_option(command_line, (r"-(?:enc|encodedcommand)\b",)):
        indicators.append("encoded_command")
    if _has_option(command_line, (r"-windowstyle\s+hidden\b", r"-w\s+hidden\b")):
        indicators.append("hidden_window")
    if _has_option(command_line, (r"-noprofile\b", r"-nop\b")):
        indicators.append("no_profile")
    if not indicators:
        return None
    return DetectionMatch(event=event, indicators=indicators)


def detect_alerts(events: list[SecurityEvent]) -> list[Alert]:
    alerts: list[Alert] = []
    for match in (match_event(event) for event in events):
        if match is None:
            continue
        event = match.event
        severity = "high" if len(match.indicators) >= 2 else "medium"
        alerts.append(
            Alert(
                alert_id=f"{RULE_ID}-{event.event_id}",
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=severity,
                title=RULE_NAME,
                description=(
                    "PowerShell execution included: "
                    + ", ".join(match.indicators)
                    + ". A normal PowerShell process is not alerted."
                ),
                timestamp=event.timestamp,
                host_id=event.host_id,
                event_ids=[event.event_id],
                source_event_ids=[event.event_id],
                matched_indicators=match.indicators,
                evidence_references=[
                    EvidenceReference(
                        event_id=event.event_id,
                        fields=["process_name", "command_line", "timestamp"],
                    )
                ],
            )
        )
    return alerts


def _base_name(value: str | None) -> str:
    return (value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _parent_name(event: SecurityEvent) -> str:
    return _base_name(
        event.raw_payload.get("ParentImage")
        or event.raw_payload.get("ParentProcessName")
        or event.raw_payload.get("parent_process_name")
    )


def detect_behavioural_alerts(events: list[SecurityEvent]) -> list[Alert]:
    alerts = detect_alerts(events)
    processes = {
        event.process_id: event
        for event in events
        if event.process_id is not None and event.event_type == "process_create"
    }
    office_names = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    shell_names = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}

    for event in events:
        parent = _parent_name(event)
        process = _base_name(event.process_name)
        if parent in office_names and process in shell_names:
            command_line = (event.command_line or "").lower()
            suspicious_shell_context = bool(
                re.search(
                    r"(?:\b(?:/c|/k|-enc|-encodedcommand|-nop|-noprofile|-windowstyle\s+hidden)\b|"
                    r"(?:powershell|pwsh|cmd\.exe).*(?:downloadstring|invoke-|frombase64string|"
                    r"bypass|hidden|whoami|net\s+(?:user|localgroup)|certutil|bitsadmin))",
                    command_line,
                    re.IGNORECASE,
                )
            )
            if process in {"wscript.exe", "cscript.exe"}:
                suspicious_shell_context = bool(command_line)
            if not suspicious_shell_context:
                continue
            alerts.append(Alert(
                alert_id=f"SOC-002-{event.event_id}",
                rule_id="SOC-002",
                rule_name="Office Application Spawning Command Shell",
                severity="high",
                title="Office application spawned a command shell",
                description=(
                    f"{_base_name(event.process_name)} was launched by {_base_name(event.raw_payload.get('ParentImage') or parent)}. "
                    "The child process and parent relationship are supported by the persisted process event."
                ),
                timestamp=event.timestamp,
                host_id=event.host_id,
                event_ids=[event.event_id],
                source_event_ids=[event.event_id],
                matched_indicators=["office_parent_process", f"child_{process}"],
                evidence_references=[EvidenceReference(
                    event_id=event.event_id,
                    fields=["process_name", "parent_process_name", "command_line", "timestamp"],
                )],
            ))

    scripting_names = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
    process_network: set[str] = set()
    for network in events:
        if network.event_type != "network_connection":
            continue
        related = processes.get(network.process_id)
        if network.process_id is None and network.raw_payload.get("ProcessId") is not None:
            related = processes.get(int(network.raw_payload["ProcessId"]))
        if related is None:
            continue
        if related is None:
            continue
        process = _base_name(related.process_name)
        if process in scripting_names and network.destination_ip:
            key = f"{related.host_id}:{related.process_id}:{network.destination_ip}"
            if key in process_network:
                continue
            process_network.add(key)
            alerts.append(Alert(
                alert_id=f"SOC-003-{related.event_id}-{network.event_id}",
                rule_id="SOC-003",
                rule_name="Scripting Interpreter Outbound Connection",
                severity="high",
                title=f"{process} established an outbound connection",
                description=(
                    f"{process} on {related.host_id or 'an unknown host'} connected to "
                    f"{network.destination_ip}. The alert correlates process creation and network events."
                ),
                timestamp=network.timestamp,
                host_id=network.host_id or related.host_id,
                event_ids=[related.event_id, network.event_id],
                source_event_ids=[related.event_id, network.event_id],
                matched_indicators=["scripting_interpreter", "outbound_connection"],
                evidence_references=[
                    EvidenceReference(event_id=related.event_id, fields=["process_name", "command_line", "timestamp"]),
                    EvidenceReference(event_id=network.event_id, fields=["event_type", "destination_ip", "timestamp"]),
                ],
            ))
    return alerts


def detection_rule_catalog() -> list[dict[str, object]]:
    return DETECTION_RULES
