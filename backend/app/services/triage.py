import json
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Protocol

from pydantic import ValidationError

from app.schemas.alerts import Alert, TriageResult
from app.schemas.events import SecurityEvent


class TriageError(RuntimeError):
    """Raised when a triage provider cannot return valid evidence-backed output."""


class TriageProvider(Protocol):
    def __call__(self, prompt: str) -> str:
        ...


def build_triage_prompt(alert: Alert, events: list[SecurityEvent]) -> str:
    evidence = [
        {
            "event_id": event.event_id,
            "source": event.source,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "process_name": event.process_name,
            "command_line": event.command_line,
            "raw_payload": event.raw_payload,
        }
        for event in events
    ]
    return json.dumps(
        {
            "instructions": (
                "Return JSON only with fields alert_id, investigation_priority, "
                "explanation, missing_information, and evidence_refs. Use only "
                "the supplied evidence. Do not invent facts."
            ),
            "alert": alert.model_dump(mode="json"),
            "events": evidence,
        },
        indent=2,
    )


class TriageAgent:
    def __init__(self, provider: TriageProvider, timeout_seconds: float = 30) -> None:
        self.provider = provider
        self.timeout_seconds = timeout_seconds

    def evaluate(self, alert: Alert, events: list[SecurityEvent]) -> TriageResult:
        event_ids = {event.event_id for event in events}
        prompt = build_triage_prompt(alert, events)
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self.provider, prompt)
        try:
            raw_output = future.result(timeout=self.timeout_seconds)
        except TimeoutError as error:
            future.cancel()
            raise TriageError("Triage provider timed out.") from error
        except Exception as error:
            raise TriageError(f"Triage provider failed: {error}") from error
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        try:
            result = TriageResult.model_validate_json(raw_output)
        except (ValidationError, ValueError) as error:
            raise TriageError("Triage provider returned malformed structured output.") from error
        if result.alert_id != alert.alert_id:
            raise TriageError("Triage output references the wrong alert.")
        if not result.evidence_refs:
            raise TriageError("Triage output must reference evidence.")
        if not set(result.evidence_refs).issubset(event_ids):
            raise TriageError("Triage output references unavailable evidence.")
        return result


class CrewAITriageProvider:
    """CrewAI-backed provider; the deterministic service validates its output."""

    def __init__(self) -> None:
        from crewai import Agent, Crew, LLM, Process, Task

        model = os.getenv("SHERLOCK_LLM_MODEL")
        if not model:
            raise TriageError("SHERLOCK_LLM_MODEL is not configured.")
        self._agent = Agent(
            role="SOC triage analyst",
            goal="Explain alert evidence without inventing facts.",
            backstory="You are a cautious SOC analyst who cites supplied event IDs.",
            allow_delegation=False,
            llm=LLM(model=model, temperature=0),
        )
        self._task_type = Task
        self._crew_type = Crew
        self._process = Process.sequential

    def __call__(self, prompt: str) -> str:
        task = self._task_type(
            description=prompt,
            expected_output="A single JSON object matching the requested fields.",
            agent=self._agent,
        )
        result = self._crew_type(
            agents=[self._agent], tasks=[task], process=self._process
        ).kickoff()
        return result.raw
