# evals/toolsets.py：步驟 5 比較的三種工具組。C 就是作品用的 vuln_agent.tools.TOOLS，A、B 只為了對照
from dataclasses import replace
from typing import Literal

from pydantic import Field

from vuln_agent.tools import TOOLS, Args, Tool, call_tool

# A. 只有一個大工具：模型用 intent 選查法，其他參數全部攤在同一個 schema 裡
class QueryVulnsArgs(Args):
    intent: Literal["cve_lookup", "search_vulns", "prioritize", "run_sql"]
    cve_id: str | None = None
    product: str | None = None
    cwe: str | None = None
    min_cvss: float | None = None
    in_kev: bool | None = None
    min_epss: float | None = None
    days: int | None = None
    limit: int | None = None
    cve_ids: list[str] | None = None
    query: str | None = Field(None, description="intent 是 run_sql 時的 SELECT")

def query_vulns(intent, **kwargs):
    """轉給對應的小工具，只帶那個工具認得的參數。"""
    fields = TOOLS[intent].args.model_fields
    return call_tool(TOOLS, intent, {k: v for k, v in kwargs.items() if v is not None and k in fields})

A = {"query_vulns": Tool("query_vulns", "查詢漏洞資料庫，intent 決定查法。", QueryVulnsArgs, query_vulns)}

# B. 四個小工具，描述只有一行（參數 schema 跟 C 一樣）
ONE_LINE = {
    "cve_lookup": "查單一 CVE。",
    "search_vulns": "搜尋漏洞。",
    "prioritize": "排序 CVE 的修補優先順序。",
    "run_sql": "執行 SQL 查詢。",
}
B = {name: replace(t, description=ONE_LINE[name]) for name, t in TOOLS.items()}

# C. 四個小工具，描述寫清楚何時用、何時不用與參數範例
C = TOOLS

TOOLSETS = {"A": A, "B": B, "C": C}

def tool_names(calls: list[dict]) -> set[str]:
    """把工具呼叫換成邏輯上的工具名稱；A 的 query_vulns 看 intent 參數，三組才能用同一份 expected_tools 比較。"""
    return {c["input"].get("intent", c["name"]) if c["name"] == "query_vulns" else c["name"] for c in calls}
