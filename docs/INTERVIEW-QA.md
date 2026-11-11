# Technical Interview Questions and Answers

## Why is detection deterministic?

The detection engine provides reproducible SOC-001 rule matches and prevents a model from inventing alerts. Agents explain and enrich persisted evidence only.

## How is evidence grounded?

Every specialist result is validated against event IDs and fields present in the persisted alert evidence. Invalid references fail that specialist result.

## What happens when one agent fails?

The coordinator records the agent status and error category, preserves any valid results, and reports missing analysis instead of fabricating a conclusion.

## Why are confidence values separate?

Detection support, evidence completeness, threat assessment, and execution completion answer different questions. Combining them would make a completed workflow look like proof of malicious intent.

## Is this an autonomous SOC replacement?

No. It is a bounded investigation assistant for evidence review. It does not execute endpoint actions, change security controls, or delete files.

## What is the deployment limitation?

SQLite requires persistent storage and is appropriate for a local or single-instance MVP. A multi-instance production deployment needs an approved database strategy and operational backups.
## How do you validate SOC-001?

The Detection Validation Lab runs the same deterministic evaluator used by alert
generation against 32 version-controlled synthetic, labelled Sysmon cases. It
calculates the confusion matrix and standard rates from actual executions, stores
the report separately, and does not invoke agents or mutate production telemetry.
Those metrics describe fixture coverage and are not a substitute for validation
against representative enterprise data.
