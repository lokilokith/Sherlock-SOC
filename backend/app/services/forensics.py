import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Protocol

from pydantic import ValidationError

from app.schemas.alerts import Alert
from app.schemas.events import SecurityEvent
from app.schemas.alerts import EvidenceReference
from app.schemas.forensics import ForensicAnalysis


class ForensicsError(RuntimeError):
    """Raised when forensic analysis cannot produce valid evidence-backed output."""


class ForensicsProvider(Protocol):
    def __call__(self, prompt: str) -> str:
        ...


def build_forensics_prompt(
    alert: Alert, events: list[SecurityEvent]
) -> str:
    return json.dumps(
        {
            "instructions": (
                "Return JSON only matching the ForensicAnalysis schema. Use only "
                "the supplied events. Do not invent process relationships. Every "
                "finding must reference supplied event IDs."
            ),
            "alert": alert.model_dump(mode="json"),
            "events": [
                {
                    "event_id": event.event_id,
                    "source": event.source,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp.isoformat(),
                    "process_id": event.process_id,
                    "parent_process_id": event.parent_process_id,
                    "process_name": event.process_name,
                    "command_line": event.command_line,
                    "raw_payload": event.raw_payload,
                }
                for event in events
            ],
        },
        indent=2,
    )


def _validate_references(
    result: ForensicAnalysis, events: list[SecurityEvent]
) -> None:
    event_ids = {event.event_id for event in events}
    event_by_id = {event.event_id: event for event in events}
    references = list(result.evidence_references)
    references.extend(
        ref
        for finding in [*result.observed_behaviors, *result.hypotheses]
        for ref in finding.evidence_refs
    )
    references.extend(
        EvidenceReference(event_id=entry.event_id, fields=entry.evidence_fields)
        for entry in result.timeline
    )
    references.extend(
        EvidenceReference(
            event_id=ref,
            fields=relationship.evidence_fields,
        )
        for relationship in result.process_relationships
        for ref in (relationship.parent_event_id, relationship.child_event_id)
    )
    valid_fields = {
        "event_id",
        "source",
        "event_type",
        "timestamp",
        "host_id",
        "user_id",
        "process_id",
        "parent_process_id",
        "process_name",
        "command_line",
        "source_ip",
        "destination_ip",
        "domain",
        "file_hash",
        "raw_payload",
    }
    if any(reference.event_id not in event_ids for reference in references):
        raise ForensicsError("Forensics output references unavailable evidence.")
    if any(
        not set(reference.fields).issubset(valid_fields)
        for reference in references
    ):
        raise ForensicsError("Forensics output references unavailable evidence fields.")
    if result.timeline != sorted(result.timeline, key=lambda entry: entry.timestamp):
        raise ForensicsError("Forensics timeline must be chronological.")
    for relationship in result.process_relationships:
        parent = event_by_id[relationship.parent_event_id]
        child = event_by_id[relationship.child_event_id]
        if (
            parent.process_id is None
            or child.parent_process_id is None
            or child.parent_process_id != parent.process_id
        ):
            raise ForensicsError(
                "Forensics output claims an unsupported process relationship."
            )


class ForensicsAgent:
    def __init__(
        self, provider: ForensicsProvider, timeout_seconds: float = 30
    ) -> None:
        self.provider = provider
        self.timeout_seconds = timeout_seconds

    def evaluate(
        self, alert: Alert, events: list[SecurityEvent]
    ) -> ForensicAnalysis:
        if not events:
            raise ForensicsError("No persisted evidence is available for this alert.")
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self.provider, build_forensics_prompt(alert, events))
        try:
            raw_output = future.result(timeout=self.timeout_seconds)
        except TimeoutError as error:
            future.cancel()
            raise ForensicsError("Forensics provider timed out.") from error
        except Exception as error:
            raise ForensicsError(f"Forensics provider failed: {error}") from error
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        try:
            result = ForensicAnalysis.model_validate_json(raw_output)
        except (ValidationError, ValueError) as error:
            raise ForensicsError(
                "Forensics provider returned malformed structured output."
            ) from error
        if result.alert_id != alert.alert_id:
            raise ForensicsError("Forensics output references the wrong alert.")
        _validate_references(result, events)
        return result


class CrewAIForensicsProvider:
    def __init__(self) -> None:
        from crewai import Agent, Crew, LLM, Process, Task

        model = os.getenv("SHERLOCK_LLM_MODEL")
        if not model:
            raise ForensicsError("SHERLOCK_LLM_MODEL is not configured.")
        agent = Agent(
            role="SOC forensics analyst",
            goal="Reconstruct only observed process activity and cite event evidence.",
            backstory="You are a cautious forensic analyst who never invents relationships.",
            allow_delegation=False,
            llm=LLM(model=model, temperature=0),
        )
        self._agent = agent
        self._task_type = Task
        self._crew_type = Crew
        self._process = Process.sequential

    def __call__(self, prompt: str) -> str:
        task = self._task_type(
            description=prompt,
            expected_output="A single JSON object matching the ForensicAnalysis schema.",
            agent=self._agent,
        )
        return self._crew_type(
            agents=[self._agent], tasks=[task], process=self._process
        ).kickoff().raw
