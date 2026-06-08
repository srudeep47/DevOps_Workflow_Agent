from pydantic import BaseModel, Field
from typing import Optional


class LogAnalyzeRequest(BaseModel):
    content: str
    filename: str = "pipeline.log"


class YamlAnalyzeRequest(BaseModel):
    content: str
    filename: str = "pipeline.yaml"


class CombinedAnalyzeRequest(BaseModel):
    log_content: str
    yaml_content: str
    log_filename: str = "pipeline.log"
    yaml_filename: str = "pipeline.yaml"


class RepoAnalyzeRequest(BaseModel):
    repo_path: str = "."
    query: str


class AnalysisResult(BaseModel):
    root_cause: str = ""
    fix_suggestions: str = ""
    security_issues: str = ""
    explanation: str = ""
    prevention: str = ""
    severity: str = "LOW"
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    verified_fix: bool = False
    sandbox_exit_code: Optional[int] = None
    raw: str = ""
