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

"""
Admina — Anti-Injection Firewall — Agent Security domain
Dual-layer defense: regex pattern matching + heuristic analysis.
"""

import base64
import logging
import re
import time
import unicodedata

from admina.core.types import RiskLevel

logger = logging.getLogger("admina.firewall")


# ── Text normalization (run BEFORE regex matching) ─────────────
# Common evasion tricks neutralised here: homoglyph (Cyrillic→Latin),
# leetspeak (1→i, 0→o, 3→e, 4→a, 5→s, 7→t), char-by-char hyphenation
# ("I-g-n-o-r-e" → "Ignore"), and short base64 payloads.

# Cyrillic → Latin lookalikes (a small but high-frequency subset).
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "у": "y",
        "У": "Y",
        "х": "x",
        "Х": "X",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "ѕ": "s",
        "Ѕ": "S",
        "ԁ": "d",
        "ɡ": "g",
        "ѵ": "v",
        "𝐈": "I",
        "𝐢": "i",  # mathematical bold
        "ꞵ": "B",
    }
)

_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)

_BASE64_RX = re.compile(r"\b[A-Za-z0-9+/]{12,}={0,2}\b")
_CHAR_HYPHEN_RX = re.compile(r"\b(?:[A-Za-z][-_.·‧•\s]){2,}[A-Za-z]\b")
_WHITESPACE_RX = re.compile(r"\s+")


def _rot13_decode(text: str) -> str:
    return text.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
        )
    )


# Words frequent enough to flag a candidate as likely-English (or near-EU
# language) after rot13 decoding. Avoids decoding random strings that
# happen to be rot13-shaped.
_ROT13_HINTS = (
    "ignore",
    "ignora",
    "ignorez",
    "olvida",
    "vergessen",
    "instruction",
    "instructions",
    "istruzioni",
    "anweisungen",
    "previous",
    "above",
    "system",
    "prompt",
    "rules",
    "reveal",
    "expose",
    "execute",
    "the",
    "and",
    "you",
)


def normalize_text(text: str) -> str:
    """Apply best-effort obfuscation neutralisation before pattern matching.

    Returns a normalised string; the caller also still scans the raw text,
    so legitimate base64 / ROT13 content is never lost. The transformation
    pipeline is order-sensitive: decode FIRST (case matters for base64),
    then fold case / leetspeak.
    """
    if not text:
        return text

    # 1. Unicode NFKC fold (full-width → ASCII, etc.)
    norm = unicodedata.normalize("NFKC", text)

    # 2. Homoglyph fold (Cyrillic/math → Latin lookalikes), case-preserving
    norm = norm.translate(_HOMOGLYPHS)

    # 3. Char-by-char hyphenation: "I-g-n-o-r-e" → "Ignore"
    def _collapse(match: re.Match) -> str:
        return re.sub(r"[-_.·‧•\s]", "", match.group(0))

    norm = _CHAR_HYPHEN_RX.sub(_collapse, norm)

    # 4. base64 decode of short tokens — BEFORE lowercase/leet so we don't
    # corrupt the encoded payload. Concatenate decoded text back so the
    # subsequent regex pass can match the plaintext.
    decoded_b64: list[str] = []
    for token in _BASE64_RX.findall(norm):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            txt = raw.decode("utf-8", errors="strict")
            if txt.isprintable() and len(txt) >= 3:
                decoded_b64.append(txt)
        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
            continue
    if decoded_b64:
        norm = norm + " " + " ".join(decoded_b64)

    # 5. ROT13 decode — opt-in: only if the decoded text contains at least
    # one English/EU-lang hint word, to avoid decoding random strings.
    rot = _rot13_decode(norm)
    rot_lower = rot.lower()
    if any(h in rot_lower for h in _ROT13_HINTS):
        norm = norm + " " + rot

    # 6. Lowercase + leetspeak fold (now safe — no more raw payloads to
    # preserve). Done last because regex matching is case-insensitive
    # but leetspeak substitution is one-way.
    norm = norm.lower().translate(_LEET)

    # 7. Collapse whitespace
    norm = _WHITESPACE_RX.sub(" ", norm).strip()
    return norm


# ── Fast-Path Regex Patterns ──────────────────────────────────
# Patterns are matched against BOTH the raw input and the normalised
# input (see normalize_text above), which neutralises common evasions.
#
# Coverage targets per the v0.9 release MODEL_CARD: instruction_override,
# role_hijack, prompt_extraction, jailbreak, delimiter_injection,
# data_exfiltration, tool_abuse, obfuscation, multilang_evasion.
#
# When adding a new variant: add a positive test in
# tests/test_proxy_security.py and a negative test (benign string that
# must NOT match) in the same file.

# A shared verb list for instruction-override variants. Kept here so it
# can be shared across the four English regexes (ignore/disregard/forget/
# bypass-family) without drift.
_OVERRIDE_VERBS = (
    r"(?:ignore|disregard|forget|override|bypass|circumvent|skip|sidestep|"
    r"nullify|cancel|suspend|drop|remove|undo)"
)
_OVERRIDE_QUAL = (
    r"(?:(?:all|the|any|every|your|those)\s+(?:of\s+)?(?:your\s+|the\s+)?)?"
    r"(?:previous|prior|above|earlier|safety|security|content)?\s*"
)
_OVERRIDE_TARGETS = (
    r"(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?|"
    r"guardrails?|restrictions?|policies|the\s+above|everything|filters?|safeguards?)"
)

INJECTION_PATTERNS = [
    # ─── 1. Direct instruction override (English) ───────────────
    (
        rf"{_OVERRIDE_VERBS}\s+{_OVERRIDE_QUAL}{_OVERRIDE_TARGETS}",
        "instruction_override",
        RiskLevel.CRITICAL,
    ),
    # Imperative chain (multiple short verbs separated by punctuation):
    # "Ignore. Forget. Override. Reveal everything."
    (
        r"\b(?:ignore|disregard|forget|override|bypass)\b[\s.;,!]+"
        r"\b(?:ignore|disregard|forget|override|bypass|reveal|expose|leak)\b",
        "instruction_override",
        RiskLevel.HIGH,
    ),
    # ─── 2. Role hijacking ─────────────────────────────────────
    (r"you\s+are\s+now\s+(?:a|an|the|in)\s+", "role_hijack", RiskLevel.HIGH),
    (r"act\s+as\s+(?:a|an|if\s+you\s+were|DAN|AIM|STAN|DUDE)\b", "role_hijack", RiskLevel.HIGH),
    (r"pretend\s+(?:to\s+be|you\s+are|that\s+you)\s+", "role_hijack", RiskLevel.HIGH),
    (
        r"(?:let'?s|let\s+us)\s+(?:roleplay|role\s+play|pretend|imagine)\b",
        "role_hijack",
        RiskLevel.HIGH,
    ),
    (
        r"from\s+now\s+on,?\s+you\s+(?:will|must|should|are|have\s+to)\s+",
        "role_hijack",
        RiskLevel.HIGH,
    ),
    # ─── 3. System prompt extraction ───────────────────────────
    (
        r"(?:show|reveal|display|print|output|repeat|echo|tell|give|share|expose)"
        r"\s+(?:me\s+)?(?:your|the)?\s*"
        r"(?:full\s+|complete\s+|original\s+|initial\s+|verbatim\s+)?"
        r"(?:system\s+|hidden\s+|internal\s+|secret\s+)?"
        r"(?:prompt|instructions?|rules?|configuration|config|policy|policies)",
        "prompt_extraction",
        RiskLevel.HIGH,
    ),
    (
        r"what\s+(?:are|is)\s+(?:your|the)\s+"
        r"(?:system\s+|hidden\s+|internal\s+|original\s+|initial\s+)?"
        r"(?:prompt|instructions?|rules?|guidelines?|configuration)",
        "prompt_extraction",
        RiskLevel.MEDIUM,
    ),
    # ─── 4. Jailbreak / mode-toggle ────────────────────────────
    # All "<noun> mode <toggle>" variants in one regex.
    (
        r"\b(?:DAN|do\s+anything\s+now|developer|admin|debug|maintenance|"
        r"god|sudo|root|jailbreak|uncensored|unrestricted)\s+mode\s+"
        r"(?:enabled|activated|on|engaged|unlock(?:ed)?)\b",
        "jailbreak",
        RiskLevel.CRITICAL,
    ),
    (r"\bDAN\s+(?:mode|prompt)\b", "jailbreak", RiskLevel.CRITICAL),
    (
        r"\b(?:do\s+anything\s+now|always\s+intelligent\s+(?:and\s+)?machiavellian)\b",
        "jailbreak",
        RiskLevel.CRITICAL,
    ),
    # ─── 5. Delimiter / template injection ─────────────────────
    (
        r"<\|im_(?:start|end)\|>|<\|endoftext\|>|<\|fim_[a-z]+\|>|"
        r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|"
        r"<\|system\|>|<\|user\|>|<\|assistant\|>",
        "delimiter_injection",
        RiskLevel.CRITICAL,
    ),
    (r"</?(?:system|user|assistant)>", "delimiter_injection", RiskLevel.HIGH),
    (r"###\s*(?:system|instruction|human|assistant)\s*:", "delimiter_injection", RiskLevel.HIGH),
    # ─── 6. Data exfiltration ──────────────────────────────────
    (
        r"(?:curl|wget|fetch|nc\s+-|netcat)\s+[\w./:?&=-]*?(?:https?|ftp|file|gopher)://",
        "data_exfiltration",
        RiskLevel.HIGH,
    ),
    # Verb "email" intentionally excluded — too many benign sentences
    # ("send report to alice@corp.com") would match. Bare email addresses
    # are not exfil targets; URLs and known burner domains are.
    (
        r"(?:send|post|upload|exfiltrate|forward|transmit|leak)\s+"
        r"(?:.{0,80}?)\s+(?:to|via|towards|through)\s+"
        r"(?:https?://|ftp://|file://|external\s+(?:endpoint|server|url)|"
        r"attacker(?:\.com|-controlled)|evil\.com|webhook\.site|requestbin|"
        r"burpcollaborator|ngrok\.io|localtunnel|serveo|"
        r"pastebin\.com|gist\.github)",
        "data_exfiltration",
        RiskLevel.HIGH,
    ),
    # ─── 7. Tool abuse (NEW category — agentic systems) ────────
    # System-shell execution
    (
        r"\b(?:exec|spawn|system|popen|subprocess|os\.system|shell_exec|run_command|"
        r"shell\s+(?:command|tool))\b\s*[:(]?\s*[\"'`]?(?:rm\s+-rf|wget\s|curl\s|"
        r"bash\s|sh\s+-c|/bin/|cmd\.exe|powershell)",
        "tool_abuse",
        RiskLevel.CRITICAL,
    ),
    # Sensitive filesystem paths
    (
        r"\b(?:cat|read|fetch|get|tail|head|less|more|file_read|read_file)\b\s+"
        r"(?:/etc/(?:passwd|shadow|hosts|sudoers|ssl)|/root/|"
        r"~?/\.ssh/|~?/\.aws/credentials|~?/\.netrc|~?/\.docker/config|"
        r"~?/\.kube/config|/proc/self/environ|/var/log/auth)",
        "tool_abuse",
        RiskLevel.CRITICAL,
    ),
    # Private/internal API calls
    (
        r"\b(?:call|invoke|fetch|hit|access|GET|POST)\b\s+(?:the\s+)?(?:internal\s+|private\s+|admin\s+)"
        r"(?:api|endpoint|service|tool|function)",
        "tool_abuse",
        RiskLevel.HIGH,
    ),
    (
        r"(?:^|[\s/])/admin/|/internal/|/_private/|/debug/|localhost:\d+/(?:admin|debug|metrics)",
        "tool_abuse",
        RiskLevel.HIGH,
    ),
    # Destructive commands as imperatives
    (
        r"\b(?:rm\s+-rf?|drop\s+(?:database|table|schema)|delete\s+from\s+\w+|"
        r"truncate\s+table|format\s+(?:c:|/dev/)|mkfs\.|dd\s+if=)",
        "tool_abuse",
        RiskLevel.CRITICAL,
    ),
    # ─── 8. Encoded / obfuscated payloads ──────────────────────
    (r"\bbase64\s*(?:encode|decode|\.b64|payload|encoded)", "obfuscation", RiskLevel.MEDIUM),
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){2,}", "obfuscation", RiskLevel.HIGH),
    # ROT13 marker phrasings
    (
        r"\b(?:rot13|rot-13|caesar\s+cipher)\b\s+(?:decode|decoded|payload|this)?",
        "obfuscation",
        RiskLevel.MEDIUM,
    ),
    # Hex-escape-as-instruction
    (r"\\x[0-9a-fA-F]{2}\s*(?:gnore|orget|verride|ypass)", "obfuscation", RiskLevel.HIGH),
    # ─── 9. Multilingual evasion ───────────────────────────────
    # Italian
    (
        r"(?:ignora|dimentica|scarta|annulla|bypassa|ometti|salta)\s+"
        r"(?:tutt[oae](?:\s+(?:le|i|gli|delle|dei))?\s+|ogni\s+|qualsiasi\s+|"
        r"le\s+|i\s+|gli\s+|delle\s+|dei\s+)?"
        r"(?:precedenti\s+|prime\s+|sopra\s+)?"
        r"(?:istruzioni?|regole|prompt|direttive|linee\s+guida|restrizioni?)",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # Italian — verb after target ("istruzioni precedenti")
    (
        r"(?:ignora|dimentica|scarta|annulla|bypassa)\s+"
        r"(?:tutt[oae]\s+)?(?:le\s+|i\s+|gli\s+)?"
        r"(?:istruzioni?|regole|direttive)\s+(?:precedenti|sopra)",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # French
    (
        r"(?:ignor(?:ez|e)|oublie[zr]?|écart[eo]z|annul(?:e|ez)|contournez|sautez)\s+"
        r"(?:tout(?:e|es)?\s+(?:les\s+|la\s+|le\s+)?|les\s+|la\s+|le\s+)?"
        r"(?:précédent(?:e|s|es)?\s+)?"
        r"(?:instructions?|règles|consignes|directives|prompts?|restrictions?)",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # French — verb-then-noun-then-adjective ("instructions précédentes")
    (
        r"(?:ignor(?:ez|e)|oublie[zr]?)\s+"
        r"(?:tout(?:e|es)?\s+(?:les\s+|la\s+|le\s+)?|les\s+|la\s+|le\s+)?"
        r"(?:instructions?|règles|consignes|directives)\s+précédent(?:e|s|es)?",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # Spanish
    (
        r"(?:ignor[ae]|olvid[ae]|descart[ae]|anul[ae]|omit[ae]|salt[ae])\s+"
        r"(?:tod[oa]s?\s+(?:las\s+|los\s+|la\s+|el\s+)?|las\s+|los\s+|la\s+|el\s+)?"
        r"(?:anteriores?\s+|previas?\s+)?"
        r"(?:instrucciones|reglas|directivas|consignas|restricciones)",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # Spanish — verb-then-noun-then-adjective ("instrucciones anteriores")
    (
        r"(?:ignor[ae]|olvid[ae])\s+"
        r"(?:tod[oa]s?\s+(?:las\s+|los\s+)?|las\s+|los\s+)?"
        r"(?:instrucciones|reglas|directivas)\s+anteriores?",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
    # German
    (
        r"(?:ignoriere(?:n)?|vergiss|verges(?:sen|st)|missachte(?:n)?|"
        r"überschreibe(?:n)?|umgehe(?:n)?|überspringe(?:n)?)\s+"
        r"(?:Sie\s+)?"
        r"(?:alle\s+|die\s+)?"
        r"(?:vorherigen?\s+|bisherigen?\s+|obigen?\s+)?"
        r"(?:Anweisungen|Regeln|Vorgaben|Richtlinien|Prompts?|Beschränkungen)",
        "multilang_evasion",
        RiskLevel.CRITICAL,
    ),
]

# Imperative verbs used by the heuristic deep-path scanner.
# Add terms here when new attack patterns emerge that use novel command words.
IMPERATIVE_WORDS = [
    "ignore",
    "override",
    "bypass",
    "circumvent",
    "disable",
    "forget",
    "must",
    "always",
    "never",
    "immediately",
    "execute",
    "reveal",
    "output",
    "print",
    "display",
    "repeat",
    "expose",
    "leak",
]

# Compile patterns for performance
COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE | re.DOTALL), name, level)
    for pattern, name, level in INJECTION_PATTERNS
]


class InjectionFirewall:
    """
    Dual-layer prompt injection defense.
    Fast path: compiled regex patterns.
    Deep path: heuristic scoring for novel/obfuscated attacks.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, "RiskLevel"]] | None = None,
        disabled_categories: list[str] | set[str] | None = None,
    ) -> None:
        """Build a firewall instance.

        Args:
            extra_patterns: Optional list of `(regex, category, risk_level)`
                tuples appended to the builtin pattern set. Loaded from
                ``admina.yaml`` -> ``agent_security.firewall.custom_patterns``
                so operators can add domain-specific rules without forking.
            disabled_categories: Categories (e.g. ``"jailbreak"``) that must
                never be flagged. Useful in observe mode while tuning, or
                when a category produces too many false positives in a
                specific deployment. Builtin pattern set is preserved; only
                matches in disabled categories are silently dropped.
        """
        self.total_checked: int = 0
        self.total_blocked: int = 0
        self.detections_by_type: dict[str, int] = {}
        self._disabled = set(disabled_categories or ())

        # Compile per-instance pattern list. Builtins first, then user
        # extras (so user rules can match what builtins miss).
        patterns = list(INJECTION_PATTERNS)
        if extra_patterns:
            for entry in extra_patterns:
                if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                    logger.warning(
                        "Skipping malformed custom firewall pattern: %r "
                        "(expected (regex, category, risk_level))",
                        entry,
                    )
                    continue
                patterns.append(tuple(entry))
        self._compiled = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), name, level) for p, name, level in patterns
        ]

    def fast_path(self, text: str) -> dict:
        """
        Regex-based fast path scan. Target: <5ms.

        Patterns are matched against the raw text AND against a normalised
        copy (homoglyph/leetspeak/char-by-char/base64 neutralised) so the
        same regex set covers a much wider attack surface without bloating
        the pattern list.

        Returns: {is_injection: bool, patterns: [...], risk_level: str}
        """
        start = time.perf_counter()
        matches: list[dict] = []
        seen: set[str] = set()
        max_risk = RiskLevel.LOW

        normalized = normalize_text(text)
        # Search raw text first (fast common case), then the normalised
        # variant if it differs. De-dupe on pattern name so the same regex
        # matching in both paths counts once.
        candidates = (text,) if normalized == text.lower() else (text, normalized)
        for candidate in candidates:
            for compiled, name, level in self._compiled:
                if name in seen or name in self._disabled:
                    continue
                if compiled.search(candidate):
                    matches.append({"pattern": name, "risk_level": level})
                    seen.add(name)
                    if self._risk_order(level) > self._risk_order(max_risk):
                        max_risk = level

        elapsed_ms = (time.perf_counter() - start) * 1000

        return {
            "is_injection": len(matches) > 0,
            "patterns": matches,
            "risk_level": max_risk,
            "scan_type": "fast_path",
            "latency_ms": round(elapsed_ms, 2),
        }

    def deep_path(self, text: str) -> dict:
        """
        Heuristic-based deep path analysis for novel attacks.
        Scores multiple signals to detect sophisticated injection attempts.
        Target: <200ms.
        """
        start = time.perf_counter()
        score = 0.0
        signals = []

        # Signal 1: High imperative verb density
        text_lower = text.lower()
        word_count = max(len(text_lower.split()), 1)
        imp_count = sum(1 for w in IMPERATIVE_WORDS if w in text_lower)
        imp_density = imp_count / word_count
        if imp_density > 0.1:
            score += 0.3
            signals.append(f"imperative_density={imp_density:.2f}")

        # Signal 2: Unusual character distribution
        special_chars = sum(1 for c in text if c in "<>[]{}|\\`~")
        special_ratio = special_chars / max(len(text), 1)
        if special_ratio > 0.05:
            score += 0.2
            signals.append(f"special_char_ratio={special_ratio:.2f}")

        # Signal 3: Context switching markers
        context_switches = len(re.findall(r"(---+|===+|###|```|</?[a-z]+>)", text, re.IGNORECASE))
        if context_switches > 2:
            score += 0.25
            signals.append(f"context_switches={context_switches}")

        # Signal 4: Abnormal length for a tool argument
        if len(text) > 2000:
            score += 0.15
            signals.append(f"abnormal_length={len(text)}")

        # Signal 5: Mixed languages / encoding markers
        if re.search(r"(\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;)", text):
            score += 0.2
            signals.append("encoded_chars_detected")

        elapsed_ms = (time.perf_counter() - start) * 1000

        is_injection = score >= 0.5
        risk = RiskLevel.LOW
        if score >= 0.7:
            risk = RiskLevel.CRITICAL
        elif score >= 0.5:
            risk = RiskLevel.HIGH
        elif score >= 0.3:
            risk = RiskLevel.MEDIUM

        return {
            "is_injection": is_injection,
            "score": round(score, 3),
            "signals": signals,
            "risk_level": risk,
            "scan_type": "deep_path",
            "latency_ms": round(elapsed_ms, 2),
        }

    def check(self, text: str) -> dict:
        """
        Full dual-layer scan. Fast path first, deep path if needed.
        """
        self.total_checked += 1

        # Layer 1: Fast path
        fast = self.fast_path(text)
        if fast["is_injection"] and self._risk_order(fast["risk_level"]) >= self._risk_order(
            RiskLevel.HIGH
        ):
            self.total_blocked += 1
            for p in fast["patterns"]:
                self.detections_by_type[p["pattern"]] = (
                    self.detections_by_type.get(p["pattern"], 0) + 1
                )
            logger.warning("[BLOCKED] Injection blocked (fast path): %s", fast["patterns"])
            return fast

        # Layer 2: Deep path
        deep = self.deep_path(text)
        combined_injection = fast["is_injection"] or deep["is_injection"]
        combined_risk = (
            fast["risk_level"]
            if self._risk_order(fast["risk_level"]) >= self._risk_order(deep["risk_level"])
            else deep["risk_level"]
        )

        result = {
            "is_injection": combined_injection,
            "risk_level": combined_risk,
            "fast_path": fast,
            "deep_path": deep,
            "latency_ms": round(fast["latency_ms"] + deep["latency_ms"], 2),
        }

        if combined_injection:
            self.total_blocked += 1
            logger.warning("[BLOCKED] Injection blocked (combined): risk=%s", combined_risk)

        return result

    @staticmethod
    def _risk_order(level: RiskLevel) -> int:
        return {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}[
            level
        ]

    def get_stats(self) -> dict:
        return {
            "total_checked": self.total_checked,
            "total_blocked": self.total_blocked,
            "block_rate": round(self.total_blocked / max(self.total_checked, 1) * 100, 2),
            "detections_by_type": self.detections_by_type,
        }
