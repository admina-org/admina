# Data Sovereignty

The data sovereignty domain handles PII detection and redaction, data residency
enforcement, and data classification. It operates bidirectionally — scanning both
outbound requests and inbound responses.

## PII Redaction

Uses spaCy NER + regex patterns for comprehensive PII detection across emails,
phone numbers, credit cards, SSNs, IBANs, IP addresses, and named entities.

```python
from admina.domains.data_sovereignty.pii import PIIRedactor

redactor = PIIRedactor()
result = redactor.redact("Contact alice@example.com or call 555-123-4567")
print(result["redacted_text"])   # Contact [EMAIL] or call [PHONE]
print(result["count"])           # 2
```

**See also:** [GovernedModel](governed-model.md) for automatic PII redaction on
model calls, [Plugin Interfaces](plugins-base.md) for building custom PII engines.

## API Reference

::: domains.data_sovereignty.pii

::: domains.data_sovereignty.classification

::: domains.data_sovereignty.residency
