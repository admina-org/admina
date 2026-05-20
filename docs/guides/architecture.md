# Architecture

Admina is organized into layers: **SDK** (in-process), **Proxy** (network),
**Governance Domains**, **Plugin System**, and **Core** types/events.

## System Overview

```mermaid
graph TB
    subgraph Client["Client Applications"]
        APP["Your App / Agent"]
    end

    subgraph SDK["SDK Layer (in-process)"]
        GM["GovernedModel"]
        GD["GovernedData"]
        GA["GovernedAgent"]
        CK["ComplianceKit"]
    end

    subgraph Proxy["Governance Proxy (network)"]
        FW["Injection Firewall"]
        PII["PII Redactor"]
        LB["Loop Breaker"]
        GG["Governance Guards"]
    end

    subgraph Domains["Governance Domains"]
        DS["Data Sovereignty\n(PII, Residency, Classification)"]
        AS["Agent Security\n(Firewall, Loop Breaker)"]
        CO["Compliance\n(EU AI Act, Forensic, OTEL)"]
        AI["AI Infrastructure\n(LLM Engine, RAG, WebUI)"]
    end

    subgraph Core["Core"]
        TY["Types & Enums\n(RiskLevel, GovernanceAction, EventType)"]
        EB["Event Bus\n(pub/sub governance events)"]
        CF["Config\n(AdminaConfig, YAML)"]
    end

    subgraph Plugins["Plugin System (14 builtin)"]
        PR["Plugin Registry"]
        BA["9 Base Interfaces"]
    end

    subgraph Storage["Infrastructure"]
        RE[("Redis\n(rate limiting)")]
        CH[("ClickHouse\n(event store)")]
        MI[("MinIO\n(forensic store)")]
    end

    subgraph Upstream["Upstream"]
        MCP["MCP Servers"]
        OL["Ollama / LLM"]
    end

    APP -->|"import"| SDK
    APP -->|"POST /mcp"| Proxy

    SDK --> Domains
    Proxy --> Domains
    Proxy --> Storage

    Domains --> Core
    Plugins --> Domains
    Proxy --> Upstream

    SDK --> EB
    Proxy --> EB
```

## Layer Details

### SDK (6 classes)

The SDK provides in-process governance primitives:

| Class | Purpose |
|-------|---------|
| `GovernedModel` | Governed LLM inference with PII redaction |
| `GovernedData` | Governed data access with residency zones |
| `GovernedAgent` | Governed agent-to-agent MCP calls |
| `ComplianceKit` | EU AI Act risk classification & gap analysis |

### Governance Domains

```mermaid
graph LR
    subgraph ds["Data Sovereignty"]
                    SensitivityLevel
        DataClassifier
        PIIRedactor
        ResidencyViolation
    end
    subgraph as2["Agent Security"]
                    InjectionFirewall
        LoopBreaker
    end
    subgraph co["Compliance"]
                    EUAIActCompliance
        ForensicBlackBox
        OTELGovernanceExporter
    end
    subgraph ai["AI Infrastructure"]
                    GPUVendor
        GPUInfo
        LLMBackend
        OllamaConfig
    end
```

### Plugin System

9 extensible plugin interfaces with 14 builtin implementations:

| Interface | Builtin |
|-----------|---------|
| `BaseModelAdapter` | OllamaAdapter, OpenAIAdapter |
| `BaseDataConnector` | ChromaDBConnector, FilesystemConnector |
| `BaseGovernanceGuard` | GuardrailsAIGuard |
| `BaseTransportAdapter` | MCPTransport, HTTPRESTTransport |
| `BaseForensicStore` | MinIOForensicStore, FilesystemForensicStore |
| `BaseAuthProvider` | APIKeyAuthProvider |
| `BasePIIEngine` | SpaCyRegexPIIEngine |
| `BaseAlertChannel` | LogAlertChannel, WebhookAlertChannel |
| `BaseComplianceTemplate` | EUAIActTemplate |

### Proxy Pipeline

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Proxy
    participant FW as Firewall
    participant PII as PII Redactor
    participant LB as Loop Breaker
    participant G as Guards
    participant U as Upstream MCP

    C->>P: POST /mcp (JSON-RPC)
    P->>P: Auth middleware
    P->>P: Rate limiting (Redis)
    P->>FW: Scan for injections
    alt Injection detected
        FW-->>P: BLOCK (403)
        P-->>C: 403 Forbidden
    end
    P->>PII: Redact PII from request
    P->>LB: Check for reasoning loops
    alt Loop detected
        LB-->>P: CIRCUIT_BREAK (429)
        P-->>C: 429 Too Many Requests
    end
    P->>G: Plugin guards inspection
    P->>U: Forward to upstream
    U-->>P: Response
    P->>G: Response inspection
    P->>PII: Redact PII from response
    P->>P: Store event (ClickHouse)
    P->>P: Emit to Event Bus
    P-->>C: Governed response
```

### Proxy Modules

| Module | Purpose |
|--------|---------|
    | `config` | Proxy component |
| `engine_bridge` | Proxy component |
| `main` | Proxy component |
| `multi_upstream` | Proxy component |

### Core Types

```mermaid
classDiagram
    class RiskLevel {
        LOW
        MEDIUM
        HIGH
        CRITICAL
    }
    class GovernanceAction {
        ALLOW
        BLOCK
        REDACT
        ESCALATE
        CIRCUIT_BREAK
    }
    class EventType {
        MCP_REQUEST
        MODEL_CALL
        DATA_ACCESS
        AGENT_REQUEST
        GOVERNANCE_DECISION
        ...
    }
    class GovernanceRequest {
        +str content
        +str method
        +str direction
        +str session_id
        +dict metadata
    }
    class GovernanceResponse {
        +str content
        +str action
        +str risk_level
        +float latency_us
    }
```
