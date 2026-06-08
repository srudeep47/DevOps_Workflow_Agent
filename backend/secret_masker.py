"""
Secret Masker — strips sensitive values from content BEFORE sending to the AI.

Each detected secret is replaced with a labeled placeholder so the AI can still
understand the structure of the file (e.g., a DB URL is present) without ever
seeing the actual credential value.
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple

# ── Pattern Registry ──────────────────────────────────────────────────────────
# Each entry: (human-readable name, compiled regex, placeholder label)
# Order matters: more specific patterns first to avoid double-masking.

_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # Private key blocks (multi-line) — highest priority
    (
        "SSH / RSA / EC Private Key",
        re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.MULTILINE),
        "<PRIVATE_KEY_EXPOSED>",
    ),
    # JWT tokens
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
        "<JWT_TOKEN_EXPOSED>",
    ),
    # AWS access key
    (
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "<AWS_ACCESS_KEY_EXPOSED>",
    ),
    # AWS secret key (key = value form)
    (
        "AWS Secret Access Key",
        re.compile(r'(?i)(aws_secret[_a-z]*)\s*[=:]\s*["\']?([A-Za-z0-9+/]{30,})["\']?'),
        "<AWS_SECRET_KEY_EXPOSED>",
    ),
    # GitHub tokens
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        "<GITHUB_TOKEN_EXPOSED>",
    ),
    # Stripe API keys
    (
        "Stripe Secret Key",
        re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"),
        "<STRIPE_KEY_EXPOSED>",
    ),
    # Google API key
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "<GOOGLE_API_KEY_EXPOSED>",
    ),
    # Slack tokens
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        "<SLACK_TOKEN_EXPOSED>",
    ),
    # Database connection strings with embedded credentials
    (
        "Database URL with Credentials",
        re.compile(r'(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlite)://[^:\s"\']+:[^@\s"\']+@[^\s"\']+'),
        "<DATABASE_URL_EXPOSED>",
    ),
    # Bearer tokens in HTTP headers
    (
        "Bearer Token",
        re.compile(r"(?i)Bearer\s+([A-Za-z0-9\-_.+/]{20,})"),
        "Bearer <BEARER_TOKEN_EXPOSED>",
    ),
    # Generic API key assignments:  api_key = "abc123..."
    (
        "Generic API Key",
        re.compile(r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']'),
        r"\1=<API_KEY_EXPOSED>",
    ),
    # Secret / client_secret assignments
    (
        "Secret Key / Client Secret",
        re.compile(r'(?i)(secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']'),
        r"\1=<SECRET_KEY_EXPOSED>",
    ),
    # Generic password in config (quoted value)
    (
        "Hardcoded Password",
        re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'),
        r"\1=<PASSWORD_EXPOSED>",
    ),
    # Generic TOKEN/SECRET/KEY/PASS= "value"
    (
        "Hardcoded Credential Variable",
        re.compile(r'(?i)\b(TOKEN|SECRET|KEY|PWD|PASS|CREDENTIAL)\s*=\s*["\']([A-Za-z0-9\-_.+/]{16,})["\']'),
        r"\1=<HARDCODED_CREDENTIAL_EXPOSED>",
    ),
]


@dataclass
class MaskResult:
    masked_content: str
    findings: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def summary(self) -> str:
        if not self.findings:
            return "No sensitive data detected."
        lines = [f"⚠️  {len(self.findings)} sensitive item(s) masked before AI analysis:"]
        for f in self.findings:
            lines.append(f"  • {f}")
        return "\n".join(lines)


def mask_secrets(content: str) -> MaskResult:
    """
    Scan *content* for secrets and replace each with a labeled placeholder.
    Returns a MaskResult with the sanitized text and a human-readable findings list.
    The actual secret values are never stored — only the pattern name and occurrence count.
    """
    result = content
    findings: List[str] = []

    for name, pattern, placeholder in _PATTERNS:
        matches = pattern.findall(result)
        if matches:
            count = len(matches) if isinstance(matches[0], str) else len(matches)
            # For group-capturing patterns (where placeholder uses \1), use re.sub;
            # for literal placeholders, use pattern.sub directly.
            if r"\1" in placeholder:
                result = pattern.sub(lambda m: f"{m.group(1)}={placeholder.split('=')[1]}", result)
            else:
                result = pattern.sub(placeholder, result)
            findings.append(f"{name} — {count} occurrence(s) → replaced with {placeholder.split('=')[-1] if '=' in placeholder else placeholder}")

    return MaskResult(masked_content=result, findings=findings)
