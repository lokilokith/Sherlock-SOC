import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.persistence import repository
from app.persistence.models import EventRecord


DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "enterprise-attack.json"
_MITRE_CACHE: dict[str, Any] | None = None


def _external_id(stix_object: dict[str, Any]) -> str | None:
    for reference in stix_object.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _load_mitre() -> dict[str, Any]:
    global _MITRE_CACHE
    if _MITRE_CACHE is not None:
        return _MITRE_CACHE
    with DATASET_PATH.open("r", encoding="utf-8") as source:
        bundle = json.load(source)
    objects = bundle.get("objects", [])
    techniques = {}
    tactics = {}
    relationships = []
    for item in objects:
        if item.get("type") == "x-mitre-tactic":
            tactics[item.get("name", "")] = {
                "id": item.get("id"),
                "name": item.get("name"),
                "short_name": item.get("x_mitre_shortname"),
                "description": item.get("description", ""),
            }
        elif item.get("type") == "attack-pattern":
            external_id = _external_id(item)
            if not external_id:
                continue
            kill_chain = [
                phase.get("phase_name")
                for phase in item.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques[external_id] = {
                "id": external_id,
                "stix_id": item.get("id"),
                "name": item.get("name"),
                "description": item.get("description", ""),
                "tactics": kill_chain,
                "platforms": item.get("x_mitre_platforms", []),
                "data_sources": item.get("x_mitre_data_sources", []),
                "deprecated": item.get("x_mitre_deprecated", False),
            }
        elif item.get("type") == "relationship":
            relationships.append(item)
    _MITRE_CACHE = {
        "techniques": techniques,
        "tactics": tactics,
        "relationships": relationships,
    }
    return _MITRE_CACHE


def mitre_overview() -> dict[str, Any]:
    data = _load_mitre()
    technique_count = len([t for t in data["techniques"].values() if not t["deprecated"]])
    return {
        "source": "MITRE ATT&CK Enterprise",
        "dataset_path": str(DATASET_PATH),
        "version": "enterprise-attack",
        "tactic_count": len(data["tactics"]),
        "technique_count": technique_count,
        "relationship_count": len(data["relationships"]),
        "loaded": DATASET_PATH.exists(),
    }


def mitre_matrix() -> dict[str, Any]:
    data = _load_mitre()
    matrix: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tactic_name in data["tactics"]:
        matrix[tactic_name] = []
    for technique in data["techniques"].values():
        if technique["deprecated"]:
            continue
        for tactic in technique["tactics"]:
            display_name = next(
                (name for name, value in data["tactics"].items() if value["short_name"] == tactic),
                tactic.replace("-", " ").title(),
            )
            matrix[display_name].append(technique)
    return {
        "tactics": [
            {"name": name, "short_name": info["short_name"], "techniques": sorted(matrix.get(name, []), key=lambda item: item["name"])}
            for name, info in data["tactics"].items()
        ]
    }


def list_mitre_techniques(search: str = "") -> list[dict[str, Any]]:
    query = search.casefold()
    techniques = [
        item
        for item in _load_mitre()["techniques"].values()
        if not item["deprecated"]
        and (not query or query in item["id"].casefold() or query in item["name"].casefold())
    ]
    return sorted(techniques, key=lambda item: item["id"])


def get_mitre_technique(external_id: str) -> dict[str, Any] | None:
    technique = _load_mitre()["techniques"].get(external_id.upper())
    return None if technique and technique["deprecated"] else technique


def evidence_graph(session: Session, investigation_id: str) -> dict[str, Any]:
    investigation = repository.get_investigation(session, investigation_id)
    if not investigation:
        return {"investigation_id": investigation_id, "nodes": [], "edges": [], "found": False}
    alert = repository.get_alert(session, investigation.alert_id)
    nodes = [{"id": investigation_id, "type": "investigation", "label": investigation_id}]
    edges = []
    if alert:
        nodes.append({"id": alert.alert_id, "type": "alert", "label": alert.title})
        edges.append({"source": investigation_id, "target": alert.alert_id, "relation": "investigates"})
    for evidence in repository.list_evidence_for_alert(session, alert.alert_id) if alert else []:
        event = repository.get_event(session, evidence.event_id)
        nodes.append({
            "id": evidence.event_id,
            "type": "event",
            "label": event.process_name if event and event.process_name else evidence.event_id,
        })
        edges.append({"source": alert.alert_id, "target": evidence.event_id, "relation": "supported-by"})
        if event and (event.parent_process_id or event.process_id):
            nodes.append({"id": f"process-{event.process_id}", "type": "process", "label": event.process_name or str(event.process_id)})
            edges.append({"source": evidence.event_id, "target": f"process-{event.process_id}", "relation": "observed-in"})
    unique_nodes = {node["id"]: node for node in nodes}
    return {"investigation_id": investigation_id, "nodes": list(unique_nodes.values()), "edges": edges, "found": True}


def attack_storyline(session: Session, investigation_id: str) -> dict[str, Any]:
    investigation = repository.get_investigation(session, investigation_id)
    if not investigation:
        return {"investigation_id": investigation_id, "events": [], "summary": "Investigation not found."}
    alert = repository.get_alert(session, investigation.alert_id)
    timeline = []
    if alert:
        for evidence in repository.list_evidence_for_alert(session, alert.alert_id):
            event = repository.get_event(session, evidence.event_id)
            if event:
                timeline.append({
                    "timestamp": event.timestamp.isoformat(),
                    "event_id": event.event_id,
                    "type": event.event_type,
                    "host": event.host_id,
                    "process": event.process_name,
                    "command_line": event.command_line,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                })
    timeline.sort(key=lambda item: item["timestamp"])
    return {
        "investigation_id": investigation_id,
        "summary": alert.description if alert else "No alert associated.",
        "events": timeline,
    }


def soc_copilot(session: Session, investigation_id: str) -> dict[str, Any]:
    graph = evidence_graph(session, investigation_id)
    storyline = attack_storyline(session, investigation_id)
    investigation = repository.get_investigation(session, investigation_id)
    response = {
        "investigation_id": investigation_id,
        "summary": "Evidence-backed investigation assistant response.",
        "observations": [],
        "questions": [],
        "recommended_actions": [],
    }
    if investigation:
        response["observations"].append(f"{len(graph['nodes'])} evidence graph nodes are associated with the investigation.")
        response["observations"].append(f"{len(storyline['events'])} timeline events support the reconstructed storyline.")
        response["questions"].extend([
            "Which host or account initiated the earliest observed process activity?",
            "Were any sibling processes, network connections, or persistence mechanisms observed around the same time?",
        ])
        response["recommended_actions"].extend([
            "Validate the timeline against endpoint telemetry.",
            "Contain only confirmed affected assets; do not treat provider reputation alone as endpoint compromise.",
        ])
    return response


def hunting_query(session: Session, indicator: str = "", host: str = "", process: str = "") -> dict[str, Any]:
    events = repository.list_events(session)
    needle = indicator.casefold()
    host_query = host.casefold()
    process_query = process.casefold()
    matches = []
    for event in events:
        searchable = " ".join([
            event.host_id or "",
            event.process_name or "",
            event.command_line or "",
            event.source_ip or "",
            event.destination_ip or "",
            event.domain or "",
            event.file_hash or "",
        ]).casefold()
        if ((not needle or needle in searchable)
                and (not host_query or host_query in (event.host_id or "").casefold())
                and (not process_query or process_query in (event.process_name or "").casefold())):
            matches.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "host_id": event.host_id,
                "process_name": event.process_name,
                "command_line": event.command_line,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
            })
    return {
        "filters": {"indicator": indicator, "host": host, "process": process},
        "total": len(matches),
        "matches": matches[:500],
    }


def evidence_quality(session: Session, investigation_id: str) -> dict[str, Any]:
    investigation = repository.get_investigation(session, investigation_id)
    if not investigation:
        return {"investigation_id": investigation_id, "confidence": 0.0, "label": "Unknown", "components": {}}
    alert = repository.get_alert(session, investigation.alert_id)
    evidence_count = len(repository.list_evidence_for_alert(session, alert.alert_id)) if alert else 0
    distinct_fields = {
        field
        for evidence in (repository.list_evidence_for_alert(session, alert.alert_id) if alert else [])
        for field in evidence.fields
    }
    completeness = min(1.0, (evidence_count / 3.0) * 0.65 + (len(distinct_fields) / 6.0) * 0.35)
    if completeness >= 0.8:
        label = "High"
    elif completeness >= 0.45:
        label = "Moderate"
    else:
        label = "Low"
    return {
        "investigation_id": investigation_id,
        "confidence": round(completeness, 3),
        "label": label,
        "components": {
            "evidence_references": evidence_count,
            "distinct_observed_fields": len(distinct_fields),
            "provider_data_available": bool(repository.list_threat_intelligence_lookups(session, alert.alert_id)) if alert else False,
        },
    }


def ioc_explorer(session: Session, indicator: str) -> dict[str, Any]:
    normalized = indicator.strip().lower()
    events = [
        event for event in repository.list_events(session)
        if normalized in " ".join([
            event.source_ip or "",
            event.destination_ip or "",
            event.domain or "",
            event.file_hash or "",
            event.command_line or "",
        ]).lower()
    ]
    associations = []
    lookups = []
    for alert in repository.list_alerts(session):
        if alert.alert_id:
            for lookup in repository.list_threat_intelligence_lookups(session, alert.alert_id):
                if lookup.normalized_value.lower() == normalized:
                    lookups.append({
                        "provider": lookup.provider_name,
                        "verdict": lookup.verdict,
                        "status": lookup.lookup_status,
                        "cached": lookup.cached,
                        "timestamp": lookup.lookup_timestamp.isoformat(),
                    })
        if any(normalized in value.lower() for value in alert.matched_indicators):
            associations.append(alert.alert_id)
    return {
        "indicator": indicator,
        "normalized_indicator": normalized,
        "related_event_count": len(events),
        "related_alert_ids": sorted(set(associations)),
        "provider_results": lookups,
        "first_observed": min((event.timestamp for event in events), default=None).isoformat() if events else None,
    }


def detection_coverage(session: Session) -> dict[str, Any]:
    alerts = repository.list_alerts(session)
    rule_counts = Counter(alert.rule_id for alert in alerts)
    mitre_mapping = {
        "SOC-001": ["T1059.001"],
        "SOC-002": ["T1059.003"],
        "SOC-003": ["T1071.001"],
    }
    coverage = []
    for rule_id, count in sorted(rule_counts.items()):
        coverage.append({
            "rule_id": rule_id,
            "alert_count": count,
            "techniques": mitre_mapping.get(rule_id, []),
        })
    return {
        "covered_rules": len(coverage),
        "mapped_techniques": sorted({technique for item in coverage for technique in item["techniques"]}),
        "rules": coverage,
    }
