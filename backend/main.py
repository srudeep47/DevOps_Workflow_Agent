import asyncio
import hashlib
import os
import sys
import time
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cachetools import TTLCache
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .schemas import (
    AnalysisResult,
    CombinedAnalyzeRequest,
    LogAnalyzeRequest,
    RepoAnalyzeRequest,
    YamlAnalyzeRequest,
)
from .agent.graph import run_agent, run_agent_with_mask_report, run_combined_agent
from .utils import calculate_confidence, get_severity, parse_analysis
from .secret_masker import mask_secrets
from .database import init_db, record_analysis, resolve_analysis, get_stats, get_recent_analyses, get_analysis
from .analytics import get_analytics
from .auto_fixer import auto_fix_yaml
from analyzer import run_agent_analysis

# ── Observability ─────────────────────────────────────────────────────────────
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)

logger.remove()
logger.add(
    sys.stdout,
    level="INFO",
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<7}</level> | {message}",
)

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

# ── TTL Cache (200 entries · 10 min TTL) ─────────────────────────────────────
_cache: TTLCache = TTLCache(maxsize=200, ttl=600)

AI_TIMEOUT_SECONDS = 90


def _cache_key(*parts: str) -> str:
    return hashlib.md5(":".join(parts).encode()).hexdigest()


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="DevOps Workflow Agent API", version="2.0.0", docs_url="/api/docs")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("SQLite DB initialised")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = round(time.time() - start, 3)
    logger.info(f"[{request.method}] {request.url.path} — {elapsed}s")
    return response


# ── Helpers ───────────────────────────────────────────────────────────────────
def _build_result(raw: str, masked_items: Optional[List[str]] = None) -> dict:
    analysis = parse_analysis(raw)
    return {
        **{k: v for k, v in analysis.items() if k != "raw"},
        "raw": raw,
        "severity": get_severity(analysis),
        "confidence_score": calculate_confidence(analysis),
        "verified_fix": False,
        "masked_secrets": masked_items or [],
    }


async def _run_with_timeout(fn, *args):
    try:
        return await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, fn, *args),
            timeout=AI_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Analysis timed out after {AI_TIMEOUT_SECONDS}s. Try with a smaller file.",
        )


# ── Stats & Health ────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Reads from shared SQLite — consistent across all gunicorn workers."""
    stats = await asyncio.get_event_loop().run_in_executor(None, get_stats)
    return {"status": "ok", **stats}


@app.get("/api/stats")
async def stats():
    return await asyncio.get_event_loop().run_in_executor(None, get_stats)


# ── Analysis History ──────────────────────────────────────────────────────────
@app.get("/api/analyses")
async def list_analyses(limit: int = 20):
    rows = await asyncio.get_event_loop().run_in_executor(None, get_recent_analyses, limit)
    return {"analyses": rows, "count": len(rows)}


@app.get("/api/analyses/{analysis_id}")
async def get_one(analysis_id: int):
    row = await asyncio.get_event_loop().run_in_executor(None, get_analysis, analysis_id)
    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return row


@app.post("/api/analyses/{analysis_id}/resolve")
async def mark_resolved(analysis_id: int):
    ok = await asyncio.get_event_loop().run_in_executor(None, resolve_analysis, analysis_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Analysis not found or already resolved")
    return {"id": analysis_id, "resolved": True}


# ── Secret Pre-scan ───────────────────────────────────────────────────────────
@app.post("/api/scan/secrets")
async def scan_secrets_only(request: Request, body: dict):
    content = body.get("content", "")
    if not content:
        raise HTTPException(status_code=400, detail="content field required")
    result = mask_secrets(content)
    return {
        "secrets_found": result.count,
        "findings": result.findings,
        "summary": result.summary,
        "masked_content": result.masked_content,
    }


# ── Analysis Endpoints ────────────────────────────────────────────────────────
@app.post("/api/analyze/log")
@limiter.limit("10/minute")
async def analyze_log(req: LogAnalyzeRequest, request: Request):
    key = _cache_key("log", req.filename, req.content[:500])
    if key in _cache:
        logger.info(f"Cache HIT — log:{req.filename}")
        return _cache[key]

    with tracer.start_as_current_span("analyze_log") as span:
        span.set_attribute("filename", req.filename)
        try:
            raw, mask = await _run_with_timeout(
                run_agent_with_mask_report, req.content, "log", req.filename
            )
            result = _build_result(raw, mask.findings)
            # Persist to shared DB
            analysis_id = await asyncio.get_event_loop().run_in_executor(
                None, record_analysis,
                "log", req.filename,
                result["severity"], result["confidence_score"],
                mask.count, result.get("root_cause", "")[:300],
            )
            result["analysis_id"] = analysis_id
            _cache[key] = result
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/yaml")
@limiter.limit("10/minute")
async def analyze_yaml_config(req: YamlAnalyzeRequest, request: Request):
    key = _cache_key("yaml", req.filename, req.content[:500])
    if key in _cache:
        logger.info(f"Cache HIT — yaml:{req.filename}")
        return _cache[key]

    with tracer.start_as_current_span("analyze_yaml") as span:
        span.set_attribute("filename", req.filename)
        try:
            raw, mask = await _run_with_timeout(
                run_agent_with_mask_report, req.content, "yaml", req.filename
            )
            result = _build_result(raw, mask.findings)
            analysis_id = await asyncio.get_event_loop().run_in_executor(
                None, record_analysis,
                "yaml", req.filename,
                result["severity"], result["confidence_score"],
                mask.count, result.get("root_cause", "")[:300],
            )
            result["analysis_id"] = analysis_id
            _cache[key] = result
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"YAML analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/combined")
@limiter.limit("10/minute")
async def analyze_combined(req: CombinedAnalyzeRequest, request: Request):
    key = _cache_key("combined", req.log_filename, req.yaml_filename,
                     req.log_content[:300], req.yaml_content[:300])
    if key in _cache:
        logger.info(f"Cache HIT — combined")
        return _cache[key]

    with tracer.start_as_current_span("analyze_combined") as span:
        span.set_attribute("log_filename", req.log_filename)
        try:
            raw = await _run_with_timeout(
                run_combined_agent,
                req.log_content, req.yaml_content,
                req.log_filename, req.yaml_filename,
            )
            log_mask = mask_secrets(req.log_content)
            yaml_mask = mask_secrets(req.yaml_content)
            all_findings = log_mask.findings + yaml_mask.findings
            result = _build_result(raw, all_findings)
            analysis_id = await asyncio.get_event_loop().run_in_executor(
                None, record_analysis,
                "combined", f"{req.log_filename}+{req.yaml_filename}",
                result["severity"], result["confidence_score"],
                len(all_findings), result.get("root_cause", "")[:300],
            )
            result["analysis_id"] = analysis_id
            _cache[key] = result
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Combined analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/repo")
@limiter.limit("5/minute")
async def analyze_repo(req: RepoAnalyzeRequest, request: Request):
    key = _cache_key("repo", req.repo_path, req.query)
    if key in _cache:
        logger.info(f"Cache HIT — repo:{req.repo_path}")
        return _cache[key]

    with tracer.start_as_current_span("analyze_repo") as span:
        span.set_attribute("repo_path", req.repo_path)
        try:
            start = time.time()
            result_text = await _run_with_timeout(run_agent_analysis, req.repo_path, req.query)
            elapsed = round(time.time() - start, 2)
            analysis_id = await asyncio.get_event_loop().run_in_executor(
                None, record_analysis,
                "repo", req.repo_path, "MEDIUM", 0.7, 0, result_text[:300],
            )
            response = {"result": result_text, "latency_seconds": elapsed, "analysis_id": analysis_id}
            _cache[key] = response
            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Repo analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))


# ── Analytics ────────────────────────────────────────────────────────────────
@app.get("/api/analytics")
async def analytics():
    data = await asyncio.get_event_loop().run_in_executor(None, get_analytics)
    return data


# ── Auto-Fix ──────────────────────────────────────────────────────────────────
@app.post("/api/fix/yaml")
async def fix_yaml(body: dict):
    content = body.get("content", "")
    if not content:
        raise HTTPException(status_code=400, detail="content field required")
    result = auto_fix_yaml(content)
    return {
        "fixed_yaml": result.fixed,
        "diff": result.diff,
        "rules_applied": result.rules_applied,
        "changed": result.changed,
        "rules_count": len(result.rules_applied),
    }


# ── Evaluation ────────────────────────────────────────────────────────────────
@app.post("/api/evaluate")
@limiter.limit("2/minute")
async def evaluate(request: Request, body: dict = None):
    from .evaluator import run_evaluation
    test_ids = (body or {}).get("test_ids", None)
    logger.info(f"Evaluation run | tests={test_ids or 'ALL'}")
    try:
        report = await _run_with_timeout(run_evaluation, run_agent, None, test_ids)
        return {
            "overall_score": report.overall_score,
            "total_tests": report.total_tests,
            "passed": report.passed,
            "failed": report.failed,
            "pass_rate": round(report.passed / report.total_tests * 100, 1) if report.total_tests else 0,
            "results": [
                {
                    "id": r.test_id,
                    "name": r.test_name,
                    "score": r.score,
                    "passed": r.passed,
                    "latency_seconds": r.latency_seconds,
                    "breakdown": r.breakdown,
                    "agent_output_preview": r.agent_output[:600] + "..." if len(r.agent_output) > 600 else r.agent_output,
                }
                for r in report.results
            ],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
