import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.validation import (
    ValidationCaseResult,
    ValidationDataset,
    ValidationMetrics,
    ValidationRule,
    ValidationRun,
)
from app.services.detection import RULE_ID, RULE_NAME, match_event
from app.services.ingestion import normalize_sysmon_event

DATASET_ID = "soc-001-baseline"
DATASET_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"


def _case(case_id: str, scenario: str, label: str, command: str | None, image: str | None, description: str, **extra: object) -> dict[str, object]:
    event: dict[str, object] = {
        "EventID": 1, "EventRecordID": case_id, "UtcTime": "2026-11-05T09:00:00Z",
        "Computer": "VALIDATION-SYNTHETIC", "Image": image, "CommandLine": command,
    }
    event.update(extra)
    return {"case_id": case_id, "scenario": scenario, "ground_truth": label, "description": description, "event": event}


def fixture_cases() -> list[dict[str, object]]:
    suspicious = [
        ("encoded", "Encoded PowerShell", "-EncodedCommand U2ltdWxhdGVk"),
        ("encoded-upper", "Case variation encoded command", "-ENCODEDCOMMAND U2ltdWxhdGVk"),
        ("hidden", "Hidden PowerShell window", "-WindowStyle Hidden -Command Get-Date"),
        ("hidden-short", "Short hidden window option", "-w hidden -Command Get-Date"),
        ("nop", "No profile execution", "-NoProfile -Command Get-Date"),
        ("nop-short", "Short no profile option", "-nop -Command Get-Date"),
        ("encoded-hidden", "Encoded hidden execution", "-EncodedCommand abc -WindowStyle Hidden"),
        ("encoded-nop", "Encoded no-profile execution", "-EncodedCommand abc -NoProfile"),
        ("hidden-nop", "Hidden no-profile execution", "-WindowStyle Hidden -NoProfile"),
        ("pwsh-encoded", "PowerShell Core encoded execution", "-EncodedCommand abc", "pwsh.exe"),
        ("path-encoded", "PowerShell path encoded execution", "-EncodedCommand abc", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("command-encoded", "Command-line encoded execution", "-Command powershell -enc abc", "cmd.exe"),
        ("download-encoded", "Synthetic download-related encoded command", "-EncodedCommand abc -Command DownloadString"),
        ("parent-hidden", "Hidden child from synthetic script host", "-WindowStyle Hidden -Command Get-Date", "powershell.exe"),
        ("mixed-case", "Mixed-case no profile", "-NoPrOfIlE -Command Get-Date"),
        ("whitespace", "Unusual spacing around hidden option", "-WindowStyle    Hidden -Command Get-Date"),
    ]
    benign = [
        ("normal-get-date", "Normal administrative PowerShell", "-Command Get-Date", "powershell.exe"),
        ("normal-service", "Service query", "-Command Get-Service", "powershell.exe"),
        ("script", "Benign local script", "-File C:\\Scripts\\Inventory.ps1", "powershell.exe"),
        ("process", "Ordinary process creation", "cmd.exe /c whoami", "cmd.exe"),
        ("pwsh-help", "PowerShell help", "-Command Get-Help Get-Process", "pwsh.exe"),
        ("keyword-string", "Harmless keyword in a string", '-Command Write-Output "encodedcommand"', "powershell.exe"),
        ("keyword-comment", "Harmless comment keyword", "-Command # -EncodedCommand is documented", "powershell.exe"),
        ("window-normal", "Normal visible window", "-WindowStyle Normal -Command Get-Date", "powershell.exe"),
        ("profile", "Explicit profile", "-Command Get-Profile", "powershell.exe"),
        ("python", "Ordinary Python process", "python.exe script.py", "python.exe"),
        ("notepad", "Ordinary desktop process", "notepad.exe", "notepad.exe"),
        ("admin-network", "Benign network inspection", "-Command Get-NetTCPConnection", "powershell.exe"),
        ("safe-download", "Benign documentation download", "-Command Invoke-WebRequest https://example.invalid/docs", "powershell.exe"),
        ("dash-word", "Non-option word resembling encoded", "-Command echo encodedcommand", "powershell.exe"),
        ("pwsh-version", "PowerShell version check", "-Command $PSVersionTable", "pwsh.exe"),
        ("empty-command", "PowerShell with missing command", None, "powershell.exe"),
    ]
    cases = [
        _case(i, s, "malicious", c, img[0] if img else "powershell.exe",
              f"Synthetic suspicious scenario: {s}.",
              **({"ParentProcessId": 100} if i == "parent-hidden" else {}))
        for i, s, c, *img in suspicious
    ]
    cases += [_case(i, s, "benign", c, img[0] if img else "powershell.exe", f"Synthetic benign scenario: {s}.") for i, s, c, *img in benign]
    return cases


def dataset_metadata() -> ValidationDataset:
    return ValidationDataset(dataset_id=DATASET_ID, version=DATASET_VERSION, description="32 deterministic synthetic Sysmon process-creation cases for SOC-001.", case_count=len(fixture_cases()))


def _metric(value: int, denominator: int) -> float | None:
    return round(value / denominator, 4) if denominator else None


def run_validation() -> ValidationRun:
    cases: list[ValidationCaseResult] = []
    counts = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    rule = ValidationRule(rule_id=RULE_ID, name=RULE_NAME, version=RULE_VERSION)
    for raw in fixture_cases():
        event = normalize_sysmon_event(raw["event"])
        match = match_event(event)
        detected = match is not None
        label = raw["ground_truth"]
        classification = ("TP" if label == "malicious" else "FP") if detected else ("FN" if label == "malicious" else "TN")
        counts[classification] += 1
        matched = match.indicators if match else []
        failed = [] if matched else ["PowerShell process", "at least one suspicious option"]
        missing = [field for field in ("process_name", "command_line", "parent_process_id") if getattr(event, field) is None]
        cases.append(ValidationCaseResult(
            case_id=raw["case_id"], scenario=raw["scenario"], description=raw["description"],
            ground_truth=label, detected=detected, expected_behavior="Detect" if label == "malicious" else "Ignore",
            actual_behavior="Detected" if detected else "Ignored", matched_conditions=matched,
            failed_conditions=failed, missing_fields=missing,
            observability="missing" if missing else "available", classification=classification,
            event_fields={"process_name": event.process_name, "command_line": event.command_line, "parent_process_id": event.parent_process_id},
        ))
    tp, fp, fn, tn = (counts[k] for k in ("TP", "FP", "FN", "TN"))
    precision = _metric(tp, tp + fp)
    recall = _metric(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision is not None and recall is not None and precision + recall else None
    metrics = ValidationMetrics(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1, specificity=_metric(tn, tn + fp), accuracy=_metric(tp + tn, tp + fp + fn + tn))
    dataset = dataset_metadata()
    dataset_hash = hashlib.sha256(json.dumps(fixture_cases(), sort_keys=True).encode()).hexdigest()
    rule_hash = hashlib.sha256(f"{RULE_ID}:{RULE_NAME}:{RULE_VERSION}".encode()).hexdigest()
    return ValidationRun(run_id=f"validation-{uuid4().hex[:12]}", rule=rule, dataset=dataset, rule_hash=rule_hash, dataset_hash=dataset_hash, executed_at=datetime.now(timezone.utc), metrics=metrics, cases=cases)


def rules() -> list[ValidationRule]:
    return [ValidationRule(rule_id=RULE_ID, name=RULE_NAME, version=RULE_VERSION)]
