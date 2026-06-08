def parse_analysis(content: str) -> dict:
    sections = {
        "root_cause": "",
        "fix_suggestions": "",
        "security_issues": "",
        "explanation": "",
        "prevention": "",
        "raw": content,
    }
    section_map = {
        "root cause analysis": "root_cause",
        "fix suggestions": "fix_suggestions",
        "security issues": "security_issues",
        "explanation": "explanation",
        "prevention recommendations": "prevention",
    }
    lines = content.split("\n")
    current_section = None
    current_lines = []

    for line in lines:
        heading = line.lstrip("#").strip().lower()
        matched = next((field for key, field in section_map.items() if heading.startswith(key)), None)
        if matched:
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section, current_lines = matched, []
        elif current_section:
            current_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()
    return sections


def get_severity(analysis: dict) -> str:
    security = analysis.get("security_issues", "").lower()
    root_cause = analysis.get("root_cause", "").lower()
    if any(kw in security for kw in ["hardcoded secret", "api key", "password", "token", "credential", "private key"]):
        return "CRITICAL"
    if any(kw in security for kw in ["authentication", "injection", "privilege", "exposed", "vulnerability"]):
        return "HIGH"
    if "error" in root_cause or "fail" in root_cause:
        return "MEDIUM"
    return "LOW"


def calculate_confidence(analysis: dict) -> float:
    score = 0.4
    if len(analysis.get("root_cause", "")) > 50:
        score += 0.2
    if len(analysis.get("fix_suggestions", "")) > 50:
        score += 0.2
    if analysis.get("security_issues"):
        score += 0.1
    if analysis.get("prevention"):
        score += 0.1
    return min(round(score, 2), 1.0)
