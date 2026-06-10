import os
import yaml
from langchain_openai import ChatOpenAI
from openai import OpenAI
from dotenv import load_dotenv
from tenacity import retry, wait_exponential, stop_after_attempt
from loguru import logger
load_dotenv()

MODEL = "gemini-2.5-flash"

llm = ChatOpenAI(
    model=MODEL,
    api_key=os.getenv("GEMINI_API_KEY"),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
    temperature=0,
)

client = OpenAI(
    api_key=os.getenv("GEMINI_API_KEY"),
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
)
@retry(
    wait=wait_exponential(multiplier=2, min=2, max=60),
    stop=stop_after_attempt(5),
    before_sleep=lambda retry_state: logger.warning(
        f"Retrying Gemini API: attempt {retry_state.attempt_number}"
    ),
    reraise=True,
)
def create_chat_completion(messages):
    logger.info("Calling Gemini API")

    response = client.chat.completions.create(
        model=MODEL,
        max_completion_tokens=4096,
        messages=messages,
    )

    logger.info("Gemini API call successful")

    return response
SYSTEM_PROMPT = """You are an expert DevOps engineer and CI/CD specialist with deep knowledge of:
- GitHub Actions, GitLab CI, Jenkins, CircleCI, and other CI/CD platforms
- Docker, Kubernetes, and container orchestration
- Security best practices for pipelines and infrastructure
- Root cause analysis for pipeline failures

When analyzing CI/CD logs or configuration files, you provide:
1. Precise root cause identification
2. Actionable fix suggestions with code examples
3. Security vulnerability detection
4. Clear explanations of why failures occurred
5. Best practice recommendations

Always structure your responses clearly with sections and use technical precision."""


def list_repo_files(directory_path):
    structure = []
    for root, dirs, files in os.walk(directory_path):
        for ignore_dir in ["node_modules", ".git", "venv", "__pycache__", "build", "dist", "sample_data"]:
            if ignore_dir in dirs:
                dirs.remove(ignore_dir)
        for file in files:
            structure.append(os.path.join(root, file))
    return structure


def read_important_files(files):
    important_extensions = (".yml", ".yaml", ".json", ".sh", ".dockerfile", "dockerfile")
    log_extensions = (".log", ".txt")
    contents = []
    count = 0

    for file in files:
        filename_lower = os.path.basename(file).lower()
        file_ext = os.path.splitext(filename_lower)[1]
        is_config = file_ext in important_extensions or "dockerfile" in filename_lower or "jenkins" in filename_lower
        is_log = file_ext in log_extensions

        if is_config or is_log:
            count += 1
            if count > 20:
                break
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = f.read()
                    if is_log:
                        content_slice = data[-4000:] if len(data) > 4000 else data
                        contents.append(f"\n\nFILE (LOG TAIL): {file}\n\n{content_slice}")
                    else:
                        content_slice = data[:8000]
                        contents.append(f"\n\nFILE (CONFIG): {file}\n\n{content_slice}")
            except Exception:
                pass

    return "\n".join(contents)


def run_agent_analysis(repo_path, user_query):
    if not os.path.exists(repo_path):
        return f"Error: The directory path '{repo_path}' does not exist."

    files = list_repo_files(repo_path)
    repo_data = read_important_files(files)

    if not repo_data.strip():
        return "No relevant CI/CD configuration or log files found in the specified directory."

    prompt = f"""You are an expert DevOps Engineer and CI/CD Specialist.

Analyze this repository's configurations and logs carefully to answer the user's request.

Tasks:
1. Detect CI/CD failures (analyze log tails for errors)
2. Detect security vulnerabilities (exposed credentials, insecure container bases)
3. Detect misconfigurations
4. Suggest precise fixes with code blocks
5. Clear step-by-step root cause analysis

USER REQUEST:
{user_query}

TARGET REPOSITORY CONTEXT:
{repo_data}
"""
    response = llm.invoke(prompt)
    return response.content


def analyze_logs(log_content: str, filename: str = "pipeline.log") -> dict:
    prompt = f"""Analyze the following CI/CD pipeline log file: `{filename}`

<log_content>
{log_content}
</log_content>

Provide a comprehensive analysis with these exact sections:

## Root Cause Analysis
## Fix Suggestions
## Security Issues
## Explanation
## Prevention Recommendations"""

    response = create_chat_completion([
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": prompt},
])
    return parse_analysis(response.choices[0].message.content)


def analyze_yaml(yaml_content: str, filename: str = "pipeline.yaml") -> dict:
    prompt = f"""Analyze the following CI/CD pipeline configuration file: `{filename}`

<yaml_content>
{yaml_content}
</yaml_content>

Provide a comprehensive analysis with these exact sections:

## Root Cause Analysis
## Fix Suggestions
## Security Issues
## Explanation
## Prevention Recommendations"""

    response = create_chat_completion([
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": prompt},
])
    return parse_analysis(response.choices[0].message.content)


def analyze_combined(log_content: str, yaml_content: str, log_filename: str = "pipeline.log", yaml_filename: str = "pipeline.yaml") -> dict:
    prompt = f"""Analyze this CI/CD pipeline holistically.

**Configuration file:** `{yaml_filename}`
<yaml_content>
{yaml_content}
</yaml_content>

**Execution log:** `{log_filename}`
<log_content>
{log_content}
</log_content>

Perform a cross-referenced analysis with these exact sections:

## Root Cause Analysis
## Fix Suggestions
## Security Issues
## Explanation
## Prevention Recommendations"""

    response = create_chat_completion([
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": prompt},
])
    return parse_analysis(response.choices[0].message.content)


def parse_analysis(content: str) -> dict:
    sections = {"root_cause": "", "fix_suggestions": "", "security_issues": "", "explanation": "", "prevention": "", "raw": content}
    section_map = {"root cause analysis": "root_cause", "fix suggestions": "fix_suggestions", "security issues": "security_issues", "explanation": "explanation", "prevention recommendations": "prevention"}
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
    text = (
        analysis.get("root_cause", "") + " " +
        analysis.get("security_issues", "") + " " +
        analysis.get("fix_suggestions", "")
    ).lower()

    critical_keywords = [
        "hardcoded secret",
        "api key",
        "password",
        "token",
        "credential",
        "private key",
        "secret key",
        "aws_access_key",
    ]

    high_keywords = [
        "authentication failure",
        "permission denied",
        "unauthorized",
        "access denied",
        "security vulnerability",
        "remote code execution",
        "privilege escalation",
    ]

    medium_keywords = [
        "module not found",
        "dependency error",
        "build failed",
        "compilation error",
        "test failure",
        "pipeline failed",
        "docker build failed",
    ]

    if any(k in text for k in critical_keywords):
        return "CRITICAL"

    if any(k in text for k in high_keywords):
        return "HIGH"

    if any(k in text for k in medium_keywords):
        return "MEDIUM"

    return "LOW"
