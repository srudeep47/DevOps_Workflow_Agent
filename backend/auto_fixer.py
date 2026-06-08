"""
Auto-Fix Generator — rule-based YAML transformer for common CI/CD issues.

Rules applied (in order):
  1. Replace hardcoded credentials with GitHub Secrets references
  2. Add timeout-minutes to jobs that lack it
  3. Add top-level permissions block if missing
  4. Pin bare `uses: owner/action` to a version tag
  5. Remove docker login -p <plaintext> and replace with secret reference

Returns both the fixed YAML string and a human-readable diff.
"""

import re
import difflib
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class FixResult:
    original: str
    fixed: str
    rules_applied: List[str] = field(default_factory=list)

    @property
    def diff(self) -> str:
        return "\n".join(
            difflib.unified_diff(
                self.original.splitlines(),
                self.fixed.splitlines(),
                fromfile="original.yaml",
                tofile="fixed.yaml",
                lineterm="",
            )
        )

    @property
    def changed(self) -> bool:
        return self.original != self.fixed


# ── Individual fix rules ──────────────────────────────────────────────────────

def _fix_hardcoded_aws_key(text: str) -> Tuple[str, List[str]]:
    """Replace AKIA… access key with a secrets reference."""
    rules = []
    pattern = re.compile(r'(AWS_ACCESS_KEY_ID\s*[:=]\s*)["\']?(AKIA[0-9A-Z]{16})["\']?')
    if pattern.search(text):
        text = pattern.sub(r'\1${{ secrets.AWS_ACCESS_KEY_ID }}', text)
        rules.append("Replaced hardcoded AWS Access Key ID with `${{ secrets.AWS_ACCESS_KEY_ID }}`")
    return text, rules


def _fix_hardcoded_aws_secret(text: str) -> Tuple[str, List[str]]:
    rules = []
    pattern = re.compile(
        r'(?i)(AWS_SECRET[_A-Z]*\s*[:=]\s*)["\']?([A-Za-z0-9+/]{30,})["\']?'
    )
    if pattern.search(text):
        text = pattern.sub(r'\1${{ secrets.AWS_SECRET_ACCESS_KEY }}', text)
        rules.append("Replaced hardcoded AWS Secret Key with `${{ secrets.AWS_SECRET_ACCESS_KEY }}`")
    return text, rules


def _fix_hardcoded_passwords(text: str) -> Tuple[str, List[str]]:
    rules = []
    # password: "value" or password = "value"
    pattern = re.compile(
        r'(?i)((?:password|passwd|pwd|db_password)\s*[:=]\s*)["\']([^"\']{4,})["\']'
    )
    def replacer(m):
        var_name = m.group(1).strip().rstrip(':=').strip().upper()
        return f"{m.group(1)}${{{{ secrets.{var_name} }}}}"

    if pattern.search(text):
        text = pattern.sub(replacer, text)
        rules.append("Replaced hardcoded passwords with `${{ secrets.VARIABLE_NAME }}`")
    return text, rules


def _fix_docker_login_plaintext(text: str) -> Tuple[str, List[str]]:
    rules = []
    pattern = re.compile(r'(docker\s+login\s+.*?-p\s+)\S+')
    if pattern.search(text):
        text = pattern.sub(r'\1${{ secrets.REGISTRY_PASSWORD }}', text)
        rules.append("Replaced plaintext docker login password with `${{ secrets.REGISTRY_PASSWORD }}`")
    return text, rules


def _fix_database_url_credentials(text: str) -> Tuple[str, List[str]]:
    rules = []
    pattern = re.compile(
        r'(?i)((postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://([^:]+)):([^@]+)@'
    )
    if pattern.search(text):
        text = pattern.sub(r'\1:${{ secrets.DB_PASSWORD }}@', text)
        rules.append("Replaced embedded DB password in connection URL with `${{ secrets.DB_PASSWORD }}`")
    return text, rules


def _fix_missing_timeout(text: str) -> Tuple[str, List[str]]:
    """Add timeout-minutes: 30 to job blocks that have runs-on but no timeout."""
    rules = []
    lines = text.splitlines()
    result = []
    i = 0
    job_block_start = False
    added = False

    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()

        # Detect a top-level job definition (indented under `jobs:`)
        if re.match(r'^    \S[\w-]+\s*:', line) and not stripped.startswith('#'):
            job_block_start = True

        if job_block_start:
            if 'runs-on:' in stripped and i + 1 < len(lines):
                # Check if timeout-minutes is already in the next few lines of the same job
                look_ahead = lines[i:i+6]
                has_timeout = any('timeout-minutes' in l for l in look_ahead)
                if not has_timeout:
                    indent = len(line) - len(line.lstrip())
                    result.append(line)
                    result.append(' ' * indent + 'timeout-minutes: 30')
                    added = True
                    i += 1
                    continue

        result.append(line)
        i += 1

    if added:
        rules.append("Added `timeout-minutes: 30` to jobs missing a timeout")
    return "\n".join(result), rules


def _fix_missing_permissions(text: str) -> Tuple[str, List[str]]:
    """Add a restrictive top-level permissions block if none exists."""
    rules = []
    if 'permissions:' not in text:
        # Insert after the `on:` block (find first job or end of on block)
        insert_block = "permissions:\n  contents: read\n  actions: read\n\n"
        # Insert before `jobs:` keyword
        if 'jobs:' in text:
            text = text.replace('jobs:', insert_block + 'jobs:', 1)
            rules.append("Added restrictive `permissions: contents: read` block (principle of least privilege)")
    return text, rules


def _fix_unpinned_actions(text: str) -> Tuple[str, List[str]]:
    """Warn about unpinned actions (uses: owner/action without version)."""
    rules = []
    pattern = re.compile(r'uses:\s+([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)\s*$', re.MULTILINE)
    matches = pattern.findall(text)
    if matches:
        # Add a comment above each unpinned action
        def add_pin_comment(m):
            action = m.group(1)
            return f"uses: {action}  # ⚠️  Pin to a specific tag or SHA: uses: {action}@v3"
        text = pattern.sub(add_pin_comment, text)
        rules.append(
            f"Flagged {len(matches)} unpinned action(s) with pinning recommendation comments: "
            + ", ".join(matches[:3]) + ("..." if len(matches) > 3 else "")
        )
    return text, rules


def _fix_env_secrets_in_run(text: str) -> Tuple[str, List[str]]:
    """Replace TOKEN=hardcoded / SECRET=hardcoded patterns in run: blocks."""
    rules = []
    pattern = re.compile(
        r'(?i)\b(TOKEN|SECRET|KEY|API_KEY|AUTH_TOKEN)\s*=\s*["\']([A-Za-z0-9\-_.+/]{16,})["\']'
    )
    if pattern.search(text):
        def replacer(m):
            var = m.group(1).upper()
            return f'{var}=${{{{ secrets.{var} }}}}'
        text = pattern.sub(replacer, text)
        rules.append("Replaced hardcoded TOKEN/SECRET/KEY values in run blocks with secrets references")
    return text, rules


# ── Orchestrator ──────────────────────────────────────────────────────────────

_RULES = [
    _fix_hardcoded_aws_key,
    _fix_hardcoded_aws_secret,
    _fix_hardcoded_passwords,
    _fix_docker_login_plaintext,
    _fix_database_url_credentials,
    _fix_env_secrets_in_run,
    _fix_missing_timeout,
    _fix_missing_permissions,
    _fix_unpinned_actions,
]


def auto_fix_yaml(yaml_content: str) -> FixResult:
    """Apply all fix rules and return a FixResult with diff and rule log."""
    text = yaml_content
    all_rules: List[str] = []

    for rule_fn in _RULES:
        try:
            text, rules = rule_fn(text)
            all_rules.extend(rules)
        except Exception:
            pass  # never break on a bad rule

    return FixResult(original=yaml_content, fixed=text, rules_applied=all_rules)
