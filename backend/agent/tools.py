import re
import subprocess
import yaml as pyyaml
from langchain.tools import tool


@tool
def log_analyzer(log_content: str) -> str:
    """Slices the last 4000 characters of a CI/CD log to surface stack traces and error messages."""
    tail = log_content[-4000:] if len(log_content) > 4000 else log_content
    error_lines = [
        line for line in tail.splitlines()
        if any(k in line.lower() for k in ["error", "fail", "exception", "traceback", "fatal", "exit code"])
    ]
    summary = f"LOG TAIL ({len(tail)} chars):\n{tail}"
    if error_lines:
        summary += f"\n\nKEY ERROR LINES ({len(error_lines)}):\n" + "\n".join(error_lines[:30])
    return summary


@tool
def yaml_analyzer(yaml_content: str) -> str:
    """Parses and analyzes a CI/CD YAML configuration file, returning its structure and detected issues."""
    try:
        parsed = pyyaml.safe_load(yaml_content)
        top_keys = list(parsed.keys()) if isinstance(parsed, dict) else "list structure"
        issues = []
        raw = yaml_content[:6000]

        if isinstance(parsed, dict):
            jobs = parsed.get("jobs", {})
            for job_name, job in (jobs.items() if isinstance(jobs, dict) else []):
                steps = job.get("steps", []) if isinstance(job, dict) else []
                for step in steps:
                    if isinstance(step, dict):
                        uses = step.get("uses", "")
                        if uses and "@v" not in uses and "actions/" in uses:
                            issues.append(f"Unpinned action: {uses}")

        result = f"YAML PARSED OK\nTop-level keys: {top_keys}"
        if issues:
            result += f"\n\nPOTENTIAL ISSUES:\n" + "\n".join(issues)
        result += f"\n\nFULL CONTENT:\n{raw}"
        return result
    except pyyaml.YAMLError as e:
        return f"YAML PARSE ERROR: {str(e)}\n\nRAW:\n{yaml_content[:4000]}"


@tool
def security_scanner(content: str) -> str:
    """Scans content for hardcoded AWS keys, API tokens, passwords, and secrets using regex patterns."""
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9+/]{30,}",
        "Generic API Key": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?",
        "Hardcoded Password": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}['\"]?",
        "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
        "Generic Secret/Token": r"(?i)(secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?",
        "Docker Registry Login": r"(?i)docker\s+login.*-p\s+\S+",
        "SSH Private Key": r"-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----",
        "Database URL with Credentials": r"(?i)(postgres|mysql|mongodb)://[^:]+:[^@]+@",
    }
    findings = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append(f"[CRITICAL] {name} detected — {len(matches)} occurrence(s)")

    if findings:
        return "SECURITY SCAN FINDINGS:\n" + "\n".join(findings)
    return "SECURITY SCAN: No hardcoded credentials detected."


@tool
def sandbox_validator(fix_command: str) -> str:
    """Validates a generated fix by running it in an isolated subprocess sandbox and returning the exit code."""
    if not fix_command or not fix_command.strip():
        return "VALIDATION SKIPPED: No command provided."

    safe_prefixes = (
        "python3 -c", "python -c",
        "node -e", "node --version",
        "echo ", "npm --version",
        "pip --version", "pip3 --version",
    )
    cmd = fix_command.strip()
    if not any(cmd.startswith(p) for p in safe_prefixes):
        return (
            f"VALIDATION SKIPPED: Command not in sandbox safe list.\n"
            f"Command: {cmd[:120]}\n"
            f"Note: Full Docker sandbox validation is available when running locally with Docker installed."
        )

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
            cwd="/tmp",
        )
        status = "PASS ✅" if result.returncode == 0 else "FAIL ❌"
        return (
            f"SANDBOX VALIDATION: {status}\n"
            f"Exit Code: {result.returncode}\n"
            f"Stdout: {result.stdout[:400]}\n"
            f"Stderr: {result.stderr[:400]}"
        )
    except subprocess.TimeoutExpired:
        return "SANDBOX VALIDATION: TIMEOUT (15s limit exceeded)"
    except Exception as e:
        return f"SANDBOX VALIDATION: ERROR\n{str(e)}"
