# tests/test_tools.py：四個工具不經過 LLM 直接測；要先 docker compose up 並跑過 ETL
import pytest

from vuln_agent.tools import TOOLS, ToolError, call_tool, query

def sample(sql: str) -> str:
    """從資料庫挑一個測試用的 CVE，測試不依賴特定資料。"""
    return query(sql)[0]["cve_id"]

def test_cve_lookup_found():
    cve_id = sample("SELECT cve_id FROM kev JOIN cve USING (cve_id) LIMIT 1")
    r = call_tool(TOOLS, "cve_lookup", {"cve_id": cve_id})
    assert r["found"] and r["cve_id"] == cve_id and r["in_kev"]

def test_cve_lookup_not_found():
    r = call_tool(TOOLS, "cve_lookup", {"cve_id": "CVE-1999-99999999"})
    assert r["found"] is False and "message" in r

def test_cve_lookup_bad_format_tells_model_what_is_valid():
    with pytest.raises(ToolError, match="cve_id"):
        call_tool(TOOLS, "cve_lookup", {"cve_id": "log4shell"})

def test_search_vulns_reports_total_when_truncated():
    r = call_tool(TOOLS, "search_vulns", {"in_kev": True, "limit": 3})
    assert r["returned"] == 3 and r["total"] > 3 and r["truncated"]
    assert all(row["in_kev"] for row in r["results"])

def test_search_vulns_sorted_kev_first():
    rows = call_tool(TOOLS, "search_vulns", {"limit": 50})["results"]
    kev = [row["in_kev"] for row in rows]
    assert kev == sorted(kev, reverse=True)

def test_search_vulns_rejects_out_of_range_and_unknown_args():
    with pytest.raises(ToolError, match="min_cvss"):
        call_tool(TOOLS, "search_vulns", {"min_cvss": 15})
    with pytest.raises(ToolError, match="vendor"):
        call_tool(TOOLS, "search_vulns", {"vendor": "nginx"})

def test_prioritize_kev_first_unknown_last():
    kev = sample("SELECT cve_id FROM kev LIMIT 1")
    other = sample("SELECT e.cve_id FROM epss e LEFT JOIN kev k USING (cve_id) WHERE k.cve_id IS NULL LIMIT 1")
    unknown = "CVE-1999-99999999"
    ranked = call_tool(TOOLS, "prioritize", {"cve_ids": [unknown, other, kev, kev]})["ranked"]
    assert [r["cve_id"] for r in ranked] == [kev, other, unknown]  # 重複的只算一次
    assert "KEV" in ranked[0]["reason"] and "查不到" in ranked[2]["reason"]

def test_run_sql_select_with_auto_limit():
    r = call_tool(TOOLS, "run_sql", {"query": "SELECT generate_series(1, 1000) AS n;"})
    assert len(r["rows"]) == 100 and r["truncated"]

@pytest.mark.parametrize("sql", [
    "DELETE FROM cve",
    "SELECT 1; DROP TABLE cve",
    "WITH d AS (DELETE FROM cve RETURNING *) SELECT * FROM d",  # 字串檢查放行，靠子查詢與唯讀交易擋下
    "SELECT * FROM etl_runs",                                   # 沒授權的表
    "SELECT pg_sleep(10)",                                      # 超過 statement_timeout
])
def test_run_sql_blocks_writes_multi_statements_and_slow_queries(sql):
    with pytest.raises(ToolError):
        call_tool(TOOLS, "run_sql", {"query": sql})
    assert query("SELECT count(*) AS n FROM cve")[0]["n"] > 0
