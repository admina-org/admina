# Admina Governance for CrewAI

Govern every CrewAI agent step — LLM reasoning, tool invocations, and task outputs — through Admina's governance pipeline. In-process, no sidecar needed.

## Install

```bash
pip install -e ".[nlp]"   # Admina with NLP (spaCy for PII)
pip install crewai         # Your CrewAI deps
```

## Quick Start

```python
from crewai import Agent, Task, Crew
from admina.integrations.crewai.callbacks import admina_step_callback, admina_task_callback

agent = Agent(
    role="Researcher",
    goal="Analyze market trends",
    backstory="Senior market analyst",
    step_callback=admina_step_callback,
)

task = Task(
    description="Research Q4 revenue for ACME Corp",
    expected_output="Revenue summary",
    agent=agent,
)

crew = Crew(
    agents=[agent],
    tasks=[task],
    task_callback=admina_task_callback,
)

result = crew.kickoff()
```

## What Gets Governed

| Callback | When | Checks |
|----------|------|--------|
| `AdminaStepCallback` | After each agent step (LLM call, tool use) | Firewall + PII + Loop detection |
| `AdminaTaskCallback` | After each task completes | PII redaction on final output |

## Configuration

```python
from admina.integrations.crewai.callbacks import AdminaStepCallback, AdminaTaskCallback

step_cb = AdminaStepCallback(
    session_id="my-crew",          # Session ID for loop detection
    pii_redaction=True,            # Redact PII (default: True)
    firewall=True,                 # Injection firewall (default: True)
    loop_detection=True,           # Loop breaker (default: True)
    on_block="raise",              # "raise" or "warn" (default: "raise")
    audit=True,                    # Emit governance events (default: True)
)

task_cb = AdminaTaskCallback(
    pii_redaction=True,
    audit=True,
)

agent = Agent(role="...", step_callback=step_cb)
crew = Crew(agents=[agent], tasks=[task], task_callback=task_cb)
```

## Handling Blocks

```python
from admina.integrations.crewai.callbacks import AdminaStepCallback, GovernanceBlockedError

step_cb = AdminaStepCallback(on_block="raise")

try:
    crew.kickoff()
except GovernanceBlockedError as e:
    print(f"Blocked: {e.action} (risk: {e.risk_level})")
```

Set `on_block="warn"` to log warnings without stopping the crew.

## Multi-Agent Crews

Each agent can have its own governance configuration:

```python
researcher = Agent(
    role="Researcher",
    step_callback=AdminaStepCallback(session_id="researcher", firewall=True),
)

writer = Agent(
    role="Writer",
    step_callback=AdminaStepCallback(session_id="writer", pii_redaction=True),
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    task_callback=AdminaTaskCallback(),
)
```

## Stats

```python
print(step_cb.get_stats())
# {"session_id": "my-crew", "step_count": 12, "block_count": 1, "redact_count": 3}
```
