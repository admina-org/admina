# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Admina — 9 plugin abstract base classes.

Every extensible capability in Admina is defined as a plugin interface.
Community developers subclass these ABCs to add support for new models,
data sources, compliance frameworks, protocols, and more.

Install a community plugin::

    admina plugin install admina-guard-toxicity

Or build your own by subclassing any base class below and registering
it in ``admina.yaml`` under the ``plugins:`` section.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

    from admina.core.types import GovernanceRequest, GovernanceResponse


# ---------------------------------------------------------------------------
# 1. BaseModelAdapter
# ---------------------------------------------------------------------------


class BaseModelAdapter(ABC):
    """Interface for LLM / model backends.

    A model adapter wraps a single inference provider (Ollama, OpenAI,
    Bedrock, vLLM, …) and exposes a uniform ``send()`` method so that
    :class:`GovernedModel` can route prompts through any backend.

    Default implementations:
        * ``OllamaAdapter`` — local Ollama instance (built-in).
        * ``OpenAIAdapter`` — OpenAI-compatible APIs (built-in).
        * ``AnthropicAdapter`` — Anthropic Claude models via ``anthropic`` SDK (built-in).
        * ``MistralAdapter`` — Mistral AI models via ``mistralai`` SDK (built-in).
        * ``BedrockAdapter`` — AWS Bedrock Converse API via ``boto3`` (built-in).
        * ``GeminiAdapter`` — Google Gemini models via ``google-genai`` SDK (built-in).
        * ``VLLMAdapter`` — vLLM OpenAI-compatible server (built-in).

    Community plugin example:
        ``admina-adapter-cohere`` — Cohere Command models.

    Example usage::

        class MyAdapter(BaseModelAdapter):
            @property
            def name(self) -> str:
                return "my-backend"

            def supports_model(self, model_name: str) -> bool:
                return model_name.startswith("my-")

            async def send(self, prompt, context=None, **kw):
                return {"text": "hello", "metadata": {"tokens": 5}}
    """

    @abstractmethod
    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to the model and return the response.

        Args:
            prompt: The text prompt to send.
            context: Optional conversation context or system prompt.
            **kwargs: Provider-specific parameters (temperature, etc.).

        Returns:
            A dict with at least ``{"text": str, "metadata": {"tokens": int,
            "latency_ms": float, ...}}``.
        """

    @abstractmethod
    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` if this adapter can serve *model_name*.

        Args:
            model_name: A model identifier, e.g. ``"llama3"`` or ``"gpt-4o"``.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique short name for this adapter (e.g. ``"ollama"``)."""


# ---------------------------------------------------------------------------
# 2. BaseDataConnector
# ---------------------------------------------------------------------------


class BaseDataConnector(ABC):
    """Interface for document / vector-store backends.

    A data connector knows how to **ingest** documents (chunk, embed,
    store) and **query** them (search, rank, return).

    Default implementations:
        * ``ChromaDBConnector`` — local ChromaDB (built-in).
        * ``FilesystemConnector`` — plain filesystem (built-in).

    Community plugin example:
        ``admina-connector-fhir`` — HL7 FHIR clinical data.

    Example usage::

        class CsvConnector(BaseDataConnector):
            @property
            def name(self) -> str:
                return "csv"

            async def ingest(self, source, **kw):
                return {"doc_count": 1, "chunk_count": 42}

            async def query(self, query, **kw):
                return [{"text": "row1", "metadata": {}, "score": 0.9}]
    """

    @abstractmethod
    async def ingest(self, source: Any, **kwargs: Any) -> dict:
        """Ingest documents from *source* into the store.

        Args:
            source: A file path, URL, bytes, or provider-specific locator.
            **kwargs: Provider-specific ingestion options.

        Returns:
            A dict with at least ``{"doc_count": int, "chunk_count": int}``.
        """

    @abstractmethod
    async def query(self, query: str, **kwargs: Any) -> list[dict]:
        """Search the store and return ranked results.

        Args:
            query: The search query string.
            **kwargs: Provider-specific search options (top_k, filters, …).

        Returns:
            A list of dicts, each with ``{"text": str, "metadata": dict,
            "score": float}``.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique short name for this connector (e.g. ``"chromadb"``)."""


# ---------------------------------------------------------------------------
# 3. BaseGovernanceGuard
# ---------------------------------------------------------------------------


class BaseGovernanceGuard(ABC):
    """Interface for a pluggable governance inspection step in the pipeline.

    A guard is a single stage that can be added to Admina's governance
    pipeline alongside the built-in steps (loop breaker, firewall, PII).
    Each guard inspects requests and/or responses and returns an action
    decision (ALLOW, BLOCK, REDACT).

    Guards are auto-discovered from ``plugins/builtin/guards/`` or any
    path listed under ``plugins:`` in ``admina.yaml``.  They run in the
    pipeline after the built-in steps.  If the plugin's ``__init__``
    accepts a ``config`` parameter, it receives the plugin's
    ``plugin_config:`` block from ``admina.yaml`` at instantiation.

    Community plugin examples:
        * ``admina-guard-toxicity`` — ML-based toxic language detection.
        * ``admina-guard-guardrailsai`` — wraps GuardrailsAI validators.
        * ``admina-guard-bias`` — statistical bias detection.

    Example usage::

        class ToxicityGuard(BaseGovernanceGuard):
            name = "toxicity"

            async def inspect_request(self, request):
                # analyse request content ...
                return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

            async def inspect_response(self, response):
                return {"action": "ALLOW", "risk_level": "LOW", "details": ""}
    """

    @abstractmethod
    async def inspect_request(self, request: dict) -> dict:
        """Inspect an inbound request before it reaches the model.

        Args:
            request: Governance request payload dict.  At minimum contains
                ``"content"`` (the raw text) and ``"params"`` (tool args).

        Returns:
            A dict with ``{"action": "ALLOW"|"BLOCK"|"REDACT",
            "risk_level": str, "details": str}``.
        """

    @abstractmethod
    async def inspect_response(self, response: dict) -> dict:
        """Inspect the model's response before it reaches the caller.

        Args:
            response: Governance response payload dict.

        Returns:
            Same structure as :meth:`inspect_request`.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique short name for this guard (e.g. ``"toxicity"``)."""


# ---------------------------------------------------------------------------
# 4. BaseComplianceTemplate
# ---------------------------------------------------------------------------


class BaseComplianceTemplate(ABC):
    """Interface for regulatory compliance frameworks.

    A compliance template defines a set of requirements (articles,
    controls, checks) and can evaluate the current governance state
    against them to produce a gap analysis.

    Default implementations:
        * ``EUAIActTemplate`` — EU AI Act Art. 6-15 (built-in).
        * ``GDPRTemplate`` — GDPR basics (built-in).

    Community plugin example:
        ``admina-compliance-hipaa`` — US HIPAA compliance checks.

    Example usage::

        class SOC2Template(BaseComplianceTemplate):
            @property
            def framework_name(self) -> str:
                return "SOC2"

            def get_requirements(self):
                return [{"id": "cc1", "title": "Control environment",
                         "checks": []}]

            def evaluate(self, governance_state):
                return {"score": 0.75, "gaps": ["cc1"], "covered": []}
    """

    @abstractmethod
    def get_requirements(self) -> list[dict]:
        """Return the list of requirements for this framework.

        Returns:
            A list of dicts, each with ``{"id": str, "title": str,
            "checks": list[callable]}``.
        """

    @abstractmethod
    def evaluate(self, governance_state: dict) -> dict:
        """Evaluate current governance state against the requirements.

        Args:
            governance_state: A dict describing the system's governance
                posture (active domains, configuration, recent events).

        Returns:
            A dict with ``{"score": float, "gaps": list, "covered": list}``.
        """

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """The compliance framework name (e.g. ``"EU AI Act"``)."""


# ---------------------------------------------------------------------------
# 5. BaseTransportAdapter
# ---------------------------------------------------------------------------


class BaseTransportAdapter(ABC):
    """Interface for wire-protocol adapters.

    A transport adapter converts between a protocol-specific wire format
    (MCP JSON-RPC, A2A, REST, AG-UI, …) and the protocol-agnostic
    :class:`GovernanceRequest` / :class:`GovernanceResponse` dataclasses.

    This is the key to Admina's protocol independence: the governance
    engine never sees wire format, only ``GovernanceRequest`` objects.

    Default implementations:
        * ``MCPTransportAdapter`` — JSON-RPC 2.0 (built-in).
        * ``HTTPRESTTransportAdapter`` — plain REST (built-in).

    Community plugin examples:
        * ``admina-transport-a2a`` — Google A2A protocol.
        * ``admina-transport-ag-ui`` — AG-UI streaming protocol.

    Example usage::

        class GRPCTransport(BaseTransportAdapter):
            @property
            def protocol_name(self) -> str:
                return "grpc"

            async def parse_request(self, raw_request):
                ...  # deserialize protobuf → GovernanceRequest

            async def format_response(self, gov_response, original):
                ...  # GovernanceResponse → protobuf

            def register_routes(self, app):
                ...  # mount gRPC service
    """

    @abstractmethod
    async def parse_request(self, raw_request: Any) -> GovernanceRequest:
        """Normalize a protocol-specific request into a GovernanceRequest.

        Args:
            raw_request: The raw incoming request (e.g. Starlette Request,
                bytes, dict).

        Returns:
            A :class:`GovernanceRequest` instance.
        """

    @abstractmethod
    async def format_response(
        self,
        gov_response: GovernanceResponse,
        original: Any,
    ) -> Any:
        """Convert a GovernanceResponse back to protocol-specific format.

        Args:
            gov_response: The governance engine's decision.
            original: The original raw request, for correlation.

        Returns:
            A protocol-specific response object.
        """

    @abstractmethod
    def register_routes(self, app: FastAPI) -> None:
        """Register protocol-specific HTTP routes on the FastAPI app.

        Args:
            app: The FastAPI application instance.

        Example:
            ``app.add_api_route("/mcp", self.handle, methods=["POST"])``
        """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Protocol identifier (e.g. ``"mcp"``, ``"a2a"``, ``"rest"``)."""


# ---------------------------------------------------------------------------
# 6. BaseForensicStore
# ---------------------------------------------------------------------------


class BaseForensicStore(ABC):
    """Interface for forensic audit-trail storage backends.

    A forensic store persists governance records into an append-only
    log.  The SHA-256 hash-chain logic lives in the core engine — the
    store only handles I/O (write, read-back, verify).

    Default implementations:
        * ``FilesystemForensicStore`` — local JSON files (built-in).
        * ``ForensicBlackBox`` — S3-compatible object storage via boto3
          (works with AWS S3, MinIO servers, R2, SeaweedFS, …), with
          optional WORM Object Lock.

    Community plugin example:
        ``admina-forensic-azure-blob`` — Azure Blob Storage backend.

    Example usage::

        class SQLiteForensicStore(BaseForensicStore):
            @property
            def store_name(self) -> str:
                return "sqlite"

            async def append(self, record):
                ...  # INSERT INTO forensic_log
                return "row-id-123"

            async def verify_chain(self, last_n=0):
                return {"valid": True, "records": 100, "last_hash": "ab12..."}
    """

    @abstractmethod
    async def append(self, record: dict) -> str:
        """Write a governance record to the store.

        The hash-chain computation is done by the core engine before
        calling this method; the store simply persists the record.

        Args:
            record: The governance record dict (includes hash fields).

        Returns:
            A storage-specific identifier for the written record.
        """

    @abstractmethod
    async def verify_chain(self, last_n: int = 0) -> dict:
        """Verify the integrity of the hash chain.

        Args:
            last_n: If > 0, verify only the last *n* records.
                If 0, verify the entire chain.

        Returns:
            A dict with ``{"valid": bool, "records": int,
            "last_hash": str}``.
        """

    @property
    @abstractmethod
    def store_name(self) -> str:
        """Unique short name for this store (e.g. ``"filesystem"``)."""


# ---------------------------------------------------------------------------
# 7. BaseAuthProvider
# ---------------------------------------------------------------------------


class BaseAuthProvider(ABC):
    """Interface for authentication and authorization providers.

    An auth provider handles identity verification (authenticate) and
    permission checks (authorize) for incoming requests.  If the
    plugin's ``__init__`` accepts a ``config`` parameter, it receives
    the plugin's ``plugin_config:`` block from ``admina.yaml`` at
    instantiation.

    Default implementations:
        * ``APIKeyAuthProvider`` — simple API-key auth (built-in).

    Community plugin example:
        ``admina-auth-ldap`` — LDAP / Active Directory authentication.

    Example usage::

        class JWTAuthProvider(BaseAuthProvider):
            @property
            def provider_name(self) -> str:
                return "jwt"

            async def authenticate(self, request):
                ...  # decode JWT, verify signature
                return {"user_id": "u1", "roles": ["admin"], "metadata": {}}

            async def authorize(self, user, action, resource=""):
                return "admin" in user["roles"]
    """

    @abstractmethod
    async def authenticate(self, request: Any) -> dict:
        """Authenticate an incoming request.

        Args:
            request: The raw request object (e.g. Starlette Request).

        Returns:
            A dict with ``{"user_id": str, "roles": list, "metadata": dict}``.

        Raises:
            Exception: If authentication fails.
        """

    @abstractmethod
    async def authorize(
        self,
        user: dict,
        action: str,
        resource: str = "",
    ) -> bool:
        """Check whether *user* is allowed to perform *action*.

        Args:
            user: The dict returned by :meth:`authenticate`.
            action: The action being attempted (e.g. ``"model.call"``).
            resource: Optional resource identifier.

        Returns:
            ``True`` if authorized, ``False`` otherwise.
        """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique short name for this provider (e.g. ``"apikey"``)."""


# ---------------------------------------------------------------------------
# 8. BasePIIEngine
# ---------------------------------------------------------------------------


class BasePIIEngine(ABC):
    """Interface for PII detection and redaction engines.

    A PII engine detects personally identifiable information in text
    and redacts it with placeholders like ``[EMAIL]``, ``[PERSON]``.

    Default implementations:
        * ``SpaCyRegexPIIEngine`` — spaCy NER + regex rules (built-in).

    Community plugin example:
        ``admina-pii-presidio`` — Microsoft Presidio with 10+ language
        support and ML-based entity recognition.

    Example usage::

        class SimplePII(BasePIIEngine):
            @property
            def supported_languages(self) -> list[str]:
                return ["en"]

            async def detect(self, text, categories=None):
                return [{"type": "EMAIL", "start": 10, "end": 25,
                         "text": "foo@bar.com", "confidence": 0.99}]

            async def redact(self, text, matches):
                return text[:10] + "[EMAIL]" + text[25:]
    """

    @abstractmethod
    async def detect(
        self,
        text: str,
        categories: list[str] | None = None,
    ) -> list[dict]:
        """Detect PII entities in *text*.

        Args:
            text: The input text to scan.
            categories: Optional list of PII types to detect (e.g.
                ``["EMAIL", "PERSON"]``).  ``None`` means detect all.

        Returns:
            A list of dicts, each with ``{"type": str, "start": int,
            "end": int, "text": str, "confidence": float}``.
        """

    @abstractmethod
    async def redact(self, text: str, matches: list[dict]) -> str:
        """Replace detected PII spans with type-based placeholders.

        Args:
            text: The original text.
            matches: The list returned by :meth:`detect`.

        Returns:
            The redacted text with placeholders like ``[EMAIL]``, ``[PERSON]``.
        """

    @property
    @abstractmethod
    def supported_languages(self) -> list[str]:
        """ISO 639-1 codes of languages this engine supports."""


# ---------------------------------------------------------------------------
# 9. BaseAlertChannel
# ---------------------------------------------------------------------------


class BaseAlertChannel(ABC):
    """Interface for governance alert delivery channels.

    An alert channel delivers governance notifications (blocked requests,
    compliance gaps, chain verification failures, …) to operators via
    their preferred medium.  If the plugin's ``__init__`` accepts a
    ``config`` parameter, it receives the plugin's ``plugin_config:``
    block from ``admina.yaml`` at instantiation.

    Default implementations:
        * ``LogAlertChannel`` — Python logger (built-in).
        * ``WebhookAlertChannel`` — HTTP POST to a URL (built-in).

    Community plugin example:
        ``admina-alert-slack`` — Slack webhook with rich formatting.

    Example usage::

        class EmailAlert(BaseAlertChannel):
            @property
            def channel_name(self) -> str:
                return "email"

            async def send_alert(self, alert):
                ...  # send via SMTP
                return True
    """

    @abstractmethod
    async def send_alert(self, alert: dict) -> bool:
        """Send a governance alert.

        Args:
            alert: A dict with ``{"level": str, "domain": str,
                "summary": str, "details": dict,
                "timestamp": datetime}``.

        Returns:
            ``True`` if the alert was delivered successfully.
        """

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Unique short name for this channel (e.g. ``"slack"``)."""
