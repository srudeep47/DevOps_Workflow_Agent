import os
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from loguru import logger

from .tools import log_analyzer, yaml_analyzer, security_scanner, sandbox_validator
from backend.secret_masker import mask_secrets, MaskResult

from dotenv import load_dotenv
load_dotenv()
MODEL = "llama-3.3-70b-versatile"

llm = ChatOpenAI(
    model=MODEL,
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
    temperature=0,
)

    
TOOLS = [log_analyzer, yaml_analyzer, security_scanner, sandbox_validator]

SYSTEM_PROMPT = """You are an expert DevOps engineer and CI/CD specialist. You have access to these tools:
- log_analyzer: Extracts error context from the tail of CI/CD logs
- yaml_analyzer: Parses and validates YAML pipeline configurations
- security_scanner: Hunts for hardcoded credentials, API keys, and secrets
- sandbox_validator: Validates a Python/bash fix command by running it in a sandbox

ALWAYS follow this workflow:
1. Call the appropriate tool(s) to gather context (log_analyzer for logs, yaml_analyzer for YAML)
2. ALWAYS call security_scanner on any YAML or configuration content
3. If you generate a fix command (python3 -c or echo), call sandbox_validator to verify it
4. Provide your final structured analysis using EXACTLY these section headers:

## Root Cause Analysis
When describing the root cause, explicitly mention:

- error code
- affected component
- resource state

Examples:
disk full
memory exhausted
network timeout
authentication failure
dependency conflict

## Fix Suggestions

When suggesting fixes:

- Include exact commands whenever possible.
- Mention concrete technologies, versions and tools.
- Mention remediation keywords commonly used by DevOps engineers.
- Be specific rather than generic.

Examples:

GitHub Actions:
- pin actions to commit SHA
- use actions/checkout@v4
- avoid floating tags
- use immutable versions

Disk space:
- npm cache clean --force
- docker system prune -af
- remove unused artifacts
- clean workspace
- increase runner disk size
## Security Issues
(All vulnerabilities found — reference security_scanner output)

## Explanation
(Plain-language walkthrough of what went wrong)

## Prevention Recommendations
(3-5 actionable best practices)"""


def build_agent():
    return create_react_agent(llm, TOOLS, prompt=SYSTEM_PROMPT)


_agent = None


def get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent

def normalize_agent_output(text: str) -> str:
    output = text

    required_headers = [
        "## Root Cause Analysis",
        "## Fix Suggestions",
        "## Security Issues",
        "## Explanation",
        "## Prevention Recommendations",
    ]

    for header in required_headers:
        if header.lower() not in output.lower():
            output += f"\n\n{header}\nNot provided."

    return output

def run_agent(content: str, content_type: str = "log", filename: str = "pipeline.log") -> str:
    # ── Step 1: Mask secrets before the content reaches the AI ───────────────
    mask: MaskResult = mask_secrets(content)
    if mask.count > 0:
        logger.warning(
            f"Secret masker: {mask.count} sensitive item(s) redacted from '{filename}' "
            f"before AI analysis — {[f.split(' —')[0] for f in mask.findings]}"
        )
    safe_content = mask.masked_content

    logger.info(f"Agent starting | type={content_type} | file={filename}")

    if content_type == "log":
        user_msg = (
            f"Analyze this CI/CD log file `{filename}` for failures and root causes:\n\n"
            f"{safe_content[:8000]}"
        )
    else:
        user_msg = (
            f"Analyze this CI/CD pipeline configuration `{filename}` for misconfigurations "
            f"and security issues:\n\n{safe_content[:8000]}"
        )

    try:
        agent = get_agent()
        result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
        for i, msg in enumerate(result["messages"]):
            print(f"\nMESSAGE {i}")
            print(type(msg).__name__)
            print(getattr(msg, "content", "NO CONTENT"))
        final = result["messages"][-1].content
        print("\n================ RAW OUTPUT START ================\n")
        print(final)
        print("\n================ RAW OUTPUT END ==================\n")
        final = normalize_agent_output(final)

        return final
    except Exception as e:
        logger.error(f"Agent error: {e}")
        raise


def run_agent_with_reasoning_trace(content: str, content_type: str = "log", filename: str = "pipeline.log") -> tuple:
    """
    Run agent and return (final_analysis, reasoning_trace).
    Trace captures all tool invocations and responses for explainability.
    """
    mask: MaskResult = mask_secrets(content)
    if mask.count > 0:
        logger.warning(
            f"Secret masker: {mask.count} sensitive item(s) redacted from '{filename}'"
        )
    safe_content = mask.masked_content

    logger.info(f"Agent starting (with trace) | type={content_type} | file={filename}")

    if content_type == "log":
        user_msg = (
            f"Analyze this CI/CD log file `{filename}` for failures and root causes:\n\n"
            f"{safe_content[:8000]}"
        )
    else:
        user_msg = (
            f"Analyze this CI/CD pipeline configuration `{filename}` for misconfigurations "
            f"and security issues:\n\n{safe_content[:8000]}"
        )

    try:
        agent = get_agent()
        result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
        
        # Extract reasoning trace from message history
        trace = []
        for i, msg in enumerate(result["messages"]):
            step = {
                "step": i,
                "type": type(msg).__name__,
            }
            
            # Capture tool calls
            if hasattr(msg, 'tool_calls') and msg.tool_calls:
                step["tool_calls"] = []
                for tc in msg.tool_calls:
                    tool_step = {
                        "name": tc.name,
                        "args": tc.args if hasattr(tc, 'args') else str(tc)[:200],
                    }
                    step["tool_calls"].append(tool_step)
            
            # Capture AI responses
            if hasattr(msg, 'content') and msg.content:
                step["content_preview"] = msg.content[:300] if len(msg.content) > 300 else msg.content
            
            # Capture tool responses
            if hasattr(msg, 'name') and hasattr(msg, 'content'):
                step["tool_name"] = msg.name
                step["tool_result"] = msg.content[:500] if msg.content else "No output"
            
            trace.append(step)
        
        final = result["messages"][-1].content
        logger.success(f"Agent complete (traced) | file={filename}")
        return final, trace
    except Exception as e:
        logger.error(f"Agent error (trace): {e}")
        raise


def run_agent_with_mask_report(content: str, content_type: str, filename: str):
    """
    Same as run_agent but also returns the MaskResult so callers can
    surface what was redacted to the user.
    """
    mask: MaskResult = mask_secrets(content)
    if mask.count > 0:
        logger.warning(
            f"Secret masker: {mask.count} item(s) redacted from '{filename}'"
        )

    logger.info(f"Agent starting | type={content_type} | file={filename}")
    safe_content = mask.masked_content

    if content_type == "log":
        user_msg = (
            f"Analyze this CI/CD log file `{filename}` for failures and root causes:\n\n"
            f"{safe_content[:8000]}"
        )
    else:
        user_msg = (
            f"Analyze this CI/CD pipeline configuration `{filename}` for misconfigurations "
            f"and security issues:\n\n{safe_content[:8000]}"
        )

    try:
        agent = get_agent()
        result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
        final = result["messages"][-1].content
        logger.success(f"Agent complete | file={filename}")
        return final, mask
    except Exception as e:
        logger.error(f"Agent error: {e}")
        raise


def run_combined_agent(log_content: str, yaml_content: str, log_filename: str, yaml_filename: str) -> str:
    # Mask both files before sending to AI
    log_mask = mask_secrets(log_content)
    yaml_mask = mask_secrets(yaml_content)

    total_masked = log_mask.count + yaml_mask.count
    if total_masked > 0:
        logger.warning(f"Secret masker: {total_masked} item(s) redacted from combined analysis")

    logger.info(f"Agent combined | log={log_filename} | yaml={yaml_filename}")

    user_msg = (
        f"Perform a cross-referenced analysis of this pipeline configuration and its execution log.\n\n"
        f"**Config file:** `{yaml_filename}`\n{yaml_mask.masked_content[:4000]}\n\n"
        f"**Execution log:** `{log_filename}`\n{log_mask.masked_content[:4000]}"
    )

    try:
        agent = get_agent()
        result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
        final = result["messages"][-1].content
        logger.success("Combined agent complete")
        return final
    except Exception as e:
        logger.error(f"Combined agent error: {e}")
        raise
