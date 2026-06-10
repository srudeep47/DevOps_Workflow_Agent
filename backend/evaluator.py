"""
Evaluation Framework — scores agent output against a golden dataset.

Scoring rubric (100 pts total per test case):
  - Section presence  (25 pts): Are all required sections in the output?
  - Root cause match  (30 pts): Do root_cause_keywords appear in the analysis?
  - Fix quality       (25 pts): Do fix_keywords appear in fix suggestions?
  - Security coverage (20 pts): Do security_keywords appear when expected?

Each keyword group score = (keywords found / total expected keywords) × weight.
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from difflib import SequenceMatcher
from loguru import logger

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data", "golden_dataset.json")

WEIGHTS = {
    "sections":   25,
    "root_cause": 30,
    "fixes":      25,
    "security":   20,
}
SYNONYMS = {
    "pin": [
        "pinned",
        "pinning",
        "specific version",
        "fixed version",
    ],

    "sha": [
        "commit sha",
        "commit hash",
        "immutable version",
    ],

    "tag": [
        "@v1",
        "@v2",
        "@v3",
        "@v4",
        "version tag",
    ],

    "cleanup": [
        "clean workspace",
        "remove artifacts",
        "delete temporary files",
        "cleanup",
    ],

    "cache": [
        "npm cache clean",
        "clear cache",
        "purge cache",
        "cache cleanup",
    ],

    "prune": [
        "docker system prune",
        "remove unused images",
        "prune docker",
    ],

    "size": [
        "increase disk size",
        "increase disk space",
        "larger disk",
        "more storage",
    ],

    "limit": [
        "resource limit",
        "disk limit",
        "storage limit",
    ],

    "secrets": [
        "github secrets",
        "secret manager",
        "vault",
        "credential store",
    ],

    "environment": [
        "env variable",
        "environment variable",
        "env vars",
    ],

    "upgrade": [
        "update",
        "migrate",
        "newer version",
    ],
}

@dataclass
class TestResult:
    test_id: str
    test_name: str
    score: float           # 0–100
    max_score: float       # 100
    breakdown: Dict[str, Any]
    agent_output: str
    latency_seconds: float
    passed: bool           # score >= 70


@dataclass
class EvaluationReport:
    total_tests: int
    passed: int
    failed: int
    overall_score: float
    results: List[TestResult]


def load_golden_dataset() -> List[Dict]:
    with open(DATASET_PATH, "r") as f:
        return json.load(f)

def similar(a: str, b: str) -> float:
    return SequenceMatcher(
        None,
        a.lower(),
        b.lower()
    ).ratio()
    
def _keyword_score(text: str, keywords: List[str], weight: int):
    if not keywords:
        return weight, [], []

    text_lower = text.lower()

    found = []
    missed = []

    for kw in keywords:

        matched = False

        # Exact match
        if kw.lower() in text_lower:
            matched = True

        # Synonym match
        if not matched:
            for synonym in SYNONYMS.get(kw.lower(), []):
                if synonym.lower() in text_lower:
                    matched = True
                    break

        # Fuzzy match
        if not matched:
            text_words = text_lower.split()

            for word in text_words:
                if similar(word, kw) >= 0.85:
                    matched = True
                    break

        if matched:
            found.append(kw)
        else:
            missed.append(kw)

    ratio = len(found) / len(keywords)

    return (
        round(ratio * weight, 1),
        found,
        missed,
    )


def _section_score(text: str, sections: List[str], weight: int) -> tuple[float, List[str], List[str]]:
    """Returns (score, found_sections, missing_sections)."""
    if not sections:
        return weight, [], []
    found = [s for s in sections if s.lower() in text.lower()]
    missing = [s for s in sections if s.lower() not in text.lower()]
    ratio = len(found) / len(sections)
    logger.warning(f"Expected sections: {sections}")
    logger.warning(f"Found sections: {found}")
    logger.warning(f"Missing sections: {missing}")
    return round(ratio * weight, 1), found, missing


def evaluate_output(agent_output: str, expected: Dict) -> Dict[str, Any]:
    """Score a single agent output against expected criteria."""
    text = agent_output

    sec_score, sec_found, sec_missing = _section_score(
        text, expected.get("required_sections", []), WEIGHTS["sections"]
    )
    rc_score, rc_found, rc_missed = _keyword_score(
        text, expected.get("root_cause_keywords", []), WEIGHTS["root_cause"]
    )
    fix_score, fix_found, fix_missed = _keyword_score(
        text, expected.get("fix_keywords", []), WEIGHTS["fixes"]
    )
    logger.warning(f"Fix Found: {fix_found}")
    logger.warning(f"Fix Missed: {fix_missed}")
    # Security: only penalise if security keywords were expected
    sec_kws = expected.get("security_keywords", [])
    if sec_kws:
        sk_score, sk_found, sk_missed = _keyword_score(text, sec_kws, WEIGHTS["security"])
    else:
        # No security keywords expected → full marks (not a security test case)
        sk_score, sk_found, sk_missed = WEIGHTS["security"], [], []

    total = sec_score + rc_score + fix_score + sk_score

    return {
        "total_score": round(total, 1),
        "breakdown": {
            "sections":    {"score": sec_score, "max": WEIGHTS["sections"],  "found": sec_found,  "missing": sec_missing},
            "root_cause":  {"score": rc_score,  "max": WEIGHTS["root_cause"], "found": rc_found,  "missed": rc_missed},
            "fixes":       {"score": fix_score, "max": WEIGHTS["fixes"],      "found": fix_found, "missed": fix_missed},
            "security":    {"score": sk_score,  "max": WEIGHTS["security"],   "found": sk_found,  "missed": sk_missed},
        },
    }


def run_evaluation(run_agent_fn, run_yaml_agent_fn=None, test_ids: Optional[List[str]] = None) -> EvaluationReport:
    """
    Execute the golden dataset through the agent and score each result.

    Args:
        run_agent_fn: callable(content, content_type, filename) → str
        run_yaml_agent_fn: same signature; if None, run_agent_fn is used for yaml too
        test_ids: optional subset of golden IDs to run (runs all if None)
    """
    dataset = load_golden_dataset()
    if test_ids:
        dataset = [d for d in dataset if d["id"] in test_ids]

    results: List[TestResult] = []

    for case in dataset:
        logger.info(f"Evaluating: {case['id']} — {case['name']}")
        start = time.time()
        try:
            fn = run_yaml_agent_fn if (case["type"] == "yaml" and run_yaml_agent_fn) else run_agent_fn
            output = fn(case["content"], case["type"], case["filename"])
        except Exception as e:
            logger.error(f"Agent failed on {case['id']}: {e}")
            output = f"AGENT ERROR: {e}"

        elapsed = round(time.time() - start, 2)
        scored = evaluate_output(output, case["expected"])

        results.append(TestResult(
            test_id=case["id"],
            test_name=case["name"],
            score=scored["total_score"],
            max_score=100.0,
            breakdown=scored["breakdown"],
            agent_output=output,
            latency_seconds=elapsed,
            passed=scored["total_score"] >= 70,
        ))

    passed = sum(1 for r in results if r.passed)
    overall = round(sum(r.score for r in results) / len(results), 1) if results else 0.0

    return EvaluationReport(
        total_tests=len(results),
        passed=passed,
        failed=len(results) - passed,
        overall_score=overall,
        results=results,
    )
