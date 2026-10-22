# tests/test_report.py：階段 3 的報告工具與 context 管理，不經過 LLM；要先 docker compose up 並跑過 ETL
import json
from types import SimpleNamespace

import pytest

from vuln_agent import report
from vuln_agent.context import CHARS_PER_TOKEN, compact, estimate_tokens, trim_result
from vuln_agent.db import connect
from vuln_agent.report import NAIVE_REPORT_TOOLS, REPORT_TOOLS
from vuln_agent.tools import ToolError, call_tool, query

@pytest.fixture
def report_file(tmp_path, monkeypatch):
    """在暫存目錄做一份小的 Trivy 報告，並把 data/reports/ 指到那裡；其中一筆用真的 KEV CVE。"""
    kev = query("SELECT cve_id FROM kev LIMIT 1")[0]["cve_id"]
    vulns = [{"VulnerabilityID": kev, "PkgName": "libssl3", "InstalledVersion": "3.0.1",
              "FixedVersion": "3.0.2", "Severity": "CRITICAL"}]
    vulns += [{"VulnerabilityID": f"CVE-2099-{i:04d}", "PkgName": f"pkg{i % 3}", "InstalledVersion": "1.0",
               "FixedVersion": "" if i % 2 else "1.1", "Severity": "HIGH" if i < 5 else "LOW"}
              for i in range(30)]
    (tmp_path / "trivy").mkdir()
    path = tmp_path / "trivy" / "test.json"
    packages = [{"Name": "libssl3", "SrcName": "openssl"}]  # 來源套件只記在 Packages
    path.write_text(json.dumps({"Results": [{"Target": "os", "Packages": packages, "Vulnerabilities": vulns},
                                            {"Target": "app", "Vulnerabilities": None}]}))
    monkeypatch.setattr(report, "ROOT", tmp_path.parent)
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    return SimpleNamespace(path=f"{tmp_path.name}/trivy/test.json", kev=kev)

@pytest.fixture
def imported(report_file):
    r = call_tool(REPORT_TOOLS, "import_report", {"path": report_file.path})
    yield SimpleNamespace(**vars(report_file), **r)
    with connect("etl") as conn:
        conn.execute("DELETE FROM reports WHERE report_id = %s", [r["report_id"]])

def test_report_path_rejects_files_outside_reports_dir(report_file):
    with pytest.raises(ToolError, match="data/reports"):
        call_tool(NAIVE_REPORT_TOOLS, "read_scan_report", {"path": "../.env"})
    with pytest.raises(ToolError, match="找不到"):
        call_tool(REPORT_TOOLS, "import_report", {"path": report_file.path.replace("test.json", "nope.json")})

def test_read_scan_report_returns_whole_json(report_file):
    r = call_tool(NAIVE_REPORT_TOOLS, "read_scan_report", {"path": report_file.path})
    assert len(r["Results"][0]["Vulnerabilities"]) == 31

def test_import_report_returns_summary_only(imported):
    assert imported.total == 31
    assert imported.by_severity == {"CRITICAL": 1, "HIGH": 5, "LOW": 25}
    assert len(imported.top10) == 10 and imported.top10[0]["severity"] == "CRITICAL"

def test_query_findings_filters_and_counts_total(imported):
    r = call_tool(REPORT_TOOLS, "query_findings", {"report_id": imported.report_id, "severity": "HIGH"})
    assert r["total"] == r["returned"] == 5 and r["next_cursor"] is None
    r = call_tool(REPORT_TOOLS, "query_findings", {"report_id": imported.report_id, "package": "SSL"})
    assert [f["cve_id"] for f in r["findings"]] == [imported.kev]
    r = call_tool(REPORT_TOOLS, "query_findings", {"report_id": imported.report_id, "package": "openssl"})
    assert [(f["pkg_name"], f["src_name"]) for f in r["findings"]] == [("libssl3", "openssl")]
    r = call_tool(REPORT_TOOLS, "query_findings", {"report_id": imported.report_id, "package": "pkg1"})
    assert r["total"] == 10 and r["findings"][0]["src_name"] == "pkg1"  # 沒有 SrcName 時用套件名稱
    r = call_tool(REPORT_TOOLS, "query_findings", {"report_id": imported.report_id, "in_kev": True})
    assert r["total"] == 1 and r["findings"][0]["in_kev"]

def test_query_findings_pages_with_cursor(imported):
    seen, cursor = [], None
    while True:
        r = call_tool(REPORT_TOOLS, "query_findings",
                      {"report_id": imported.report_id, "limit": 10, "cursor": cursor})
        assert r["total"] == 31  # 每一頁都拿到全部符合的筆數
        seen += [f["id"] for f in r["findings"]]
        if (cursor := r["next_cursor"]) is None:
            break
    assert len(seen) == len(set(seen)) == 31

def test_query_findings_unknown_report(imported):
    with pytest.raises(ToolError, match="import_report"):
        call_tool(REPORT_TOOLS, "query_findings", {"report_id": 10**12})

def test_findings_readable_by_run_sql(imported):
    from vuln_agent.tools import TOOLS
    sql = f"SELECT pkg_name, count(*) AS n FROM findings WHERE report_id = {imported.report_id} GROUP BY 1 ORDER BY 2 DESC"
    assert call_tool(TOOLS, "run_sql", {"query": sql})["rows"][0]["n"] == 10

def test_trim_result_cuts_longest_list_and_says_so():
    rows = [{"id": i, "pad": "x" * 100} for i in range(1000)]
    r = trim_result({"total": 1000, "rows": rows}, max_tokens=500)
    assert 0 < len(r["rows"]) < 1000 and r["total"] == 1000 and "已截斷" in r["note"]
    assert estimate_tokens(r) <= 500 + 50  # note 本身多出的一點
    assert trim_result({"rows": [1]}, max_tokens=500) == {"rows": [1]}

def test_trim_result_falls_back_to_text_when_first_row_too_big():
    r = trim_result({"Results": [{"pad": "x" * 10_000}]}, max_tokens=100)
    assert len(r["partial_json"]) == int(100 * CHARS_PER_TOKEN) and "已截斷" in r["note"]

def tool_round(i: int, size: int) -> list:
    """一輪工具呼叫：assistant 的 text 與 tool_use（SDK 物件的樣子），加上 user 的 tool_result。"""
    blocks = [SimpleNamespace(type="text", text=f"結論 {i}"),
              SimpleNamespace(type="tool_use", id=f"t{i}", name="query_findings", input={"report_id": i})]
    return [{"role": "assistant", "content": blocks},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": f"t{i}", "content": "y" * size}]}]

def test_compact_replaces_history_with_one_summary():
    messages = [{"role": "user", "content": "有幾個 Critical？"}] + tool_round(1, 5000) + tool_round(2, 300)
    assert compact(messages, max_tokens=10_000) is messages  # 沒超過就原樣回傳
    out = compact(messages, max_tokens=1000)
    assert len(out) == 1 and out[0]["role"] == "user"
    s = out[0]["content"]
    assert s.startswith("有幾個 Critical？") and "結論 1" in s and "結論 2" in s
    assert "query_findings" in s and "共 5000 字元" in s
    assert "y" * 300 in s and "y" * 5000 not in s  # 最近一次的結果完整保留，較早的只留開頭
