# Quick Start

## Installation

```bash
git clone https://github.com/admina-org/admina.git
cd admina

# SDK only (lightweight — 3 dependencies)
pip install -e .

# With proxy infrastructure
pip install -e ".[proxy]"

# Everything (proxy + NLP + telemetry)
pip install -e ".[full]"
```

!!! note "Ollama required for LLM features"
    Install [Ollama](https://ollama.ai) and pull a model: `ollama pull llama3.1:8b`

## SDK Usage

### Governed Model

```python
from admina import GovernedModel
from admina.plugins.builtin.adapters.ollama import OllamaAdapter

adapter = OllamaAdapter(host="http://localhost:11434")
model = GovernedModel(model_name="llama3.1:8b", adapter=adapter)
response = await model.ask("Summarize this document")

print(response.text)          # PII-redacted response
print(response.governance)    # Governance metadata
```

### Governed Data

```python
from admina import GovernedData
from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector

connector = ChromaDBConnector(host="localhost", port=8000)
data = GovernedData(connector=connector, residency_zone="eu")
result = await data.ingest(documents)
```

### Compliance Kit

```python
from admina import ComplianceKit

kit = ComplianceKit()
report = kit.gap_analysis(risk_category="high", current_compliance={})
print(report.compliance_score)
```

## Full Stack (Docker)

```bash
cp .env.example .env   # Configure secrets
docker compose up --build
```

- Dashboard: [http://localhost:3000](http://localhost:3000)
- API docs: [http://localhost:8080/docs](http://localhost:8080/docs)
- Grafana: [http://localhost:3001](http://localhost:3001)

## CLI

```bash
pip install -e .
admina init my-project    # Scaffold a governed AI project
admina dev                # Start local dev stack
```
