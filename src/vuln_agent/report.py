# src/vuln_agent/report.py：階段 3 的掃描報告工具。天真版直接回傳整份 JSON；
# 匯入版把報告攤平存進資料庫，模型只拿摘要，再用篩選與分頁查需要的部分
import json
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from vuln_agent.db import connect
from vuln_agent.tools import Args, Tool, ToolError, query

ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "data" / "reports"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
MAX_FINDINGS = 50

def report_path(path: str) -> Path:
    """把模型給的路徑轉成實際檔案；只接受 data/reports/ 底下已存在的檔案，擋掉 ../.env 這類路徑。"""
    p = (ROOT / path).resolve()
    if not p.is_relative_to(REPORTS_DIR.resolve()):
        raise ValueError(f"只能讀 data/reports/ 底下的報告，收到 {path}")
    if not p.is_file():
        raise ValueError(f"找不到報告檔 {path}")
    return p

def parse_trivy(path: Path) -> list[dict]:
    """Trivy JSON 的弱點在 Results[].Vulnerabilities[]，攤平成一列一筆。
    來源套件（SrcName）只記在同一個 Result 的 Packages[]，沒有的話用套件名稱本身。"""
    rows = []
    for r in json.loads(path.read_text()).get("Results", []):
        src = {p["Name"]: p.get("SrcName") for p in (r.get("Packages") or [])}
        rows += [{"cve_id": v["VulnerabilityID"], "pkg_name": v["PkgName"],
                  "src_name": src.get(v["PkgName"]) or v["PkgName"],
                  "installed_version": v.get("InstalledVersion"), "fixed_version": v.get("FixedVersion") or None,
                  "severity": v.get("Severity", "UNKNOWN"), "target": r.get("Target")}
                 for v in (r.get("Vulnerabilities") or [])]
    return rows

# ---- 參數 ----

class ReportPathArgs(Args):
    path: str = Field(description="報告路徑，相對於專案根目錄，例如 data/reports/trivy/myapp.json")

    @field_validator("path")
    @classmethod
    def under_reports_dir(cls, v: str) -> str:
        report_path(v)
        return v

class QueryFindingsArgs(Args):
    report_id: int = Field(description="import_report 回傳的 report_id")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] | None = None
    package: str | None = Field(None, description="套件名稱或來源套件名稱的一部分，不分大小寫；例如 openssl 會找到來源是 openssl 的 libssl3、libcrypto3")
    in_kev: bool | None = Field(None, description="true 只看已被實際利用（在 CISA KEV）的")
    limit: int = Field(20, ge=1, le=MAX_FINDINGS, description="這一頁最多幾筆")
    cursor: int | None = Field(None, description="上一頁回傳的 next_cursor，第一頁不用給")

# ---- 工具本體 ----

def read_scan_report(path: str) -> dict:
    """天真版：整份 JSON 原封不動回傳，報告多大，context 就多大。"""
    return json.loads(report_path(path).read_text())

def import_report(path: str) -> dict:
    """攤平後用 vuln_etl 寫進 findings，只回傳 report_id 與統計摘要。"""
    rows = parse_trivy(report_path(path))
    with connect("etl") as conn:
        report_id = conn.execute("INSERT INTO reports (path) VALUES (%s) RETURNING report_id", [path]).fetchone()[0]
        conn.cursor().executemany("""
            INSERT INTO findings (report_id, cve_id, pkg_name, src_name, installed_version, fixed_version, severity, target)
            VALUES (%(report_id)s, %(cve_id)s, %(pkg_name)s, %(src_name)s, %(installed_version)s, %(fixed_version)s,
                    %(severity)s, %(target)s)""", [{"report_id": report_id, **r} for r in rows])
    by_severity = {s: n for s in SEVERITIES if (n := sum(r["severity"] == s for r in rows))}
    top = sorted(rows, key=lambda r: SEVERITIES.index(r["severity"]))
    return {"report_id": report_id, "total": len(rows), "by_severity": by_severity,
            "top10": [{k: r[k] for k in ("cve_id", "pkg_name", "src_name", "fixed_version", "severity")} for r in top[:10]],
            "note": "完整清單用 query_findings 依 severity、package、in_kev 篩選與分頁"}

def query_findings(report_id, severity, package, in_kev, limit, cursor) -> dict:
    """依條件查報告裡的弱點；total 是符合條件的總筆數，next_cursor 不是 null 就代表還有下一頁。"""
    rows = query("""
        SELECT * FROM (
            SELECT f.id, f.cve_id, f.pkg_name, f.src_name, f.installed_version, f.fixed_version, f.severity,
                   k.cve_id IS NOT NULL AS in_kev, count(*) OVER () AS total
            FROM findings f LEFT JOIN kev k USING (cve_id)
            WHERE f.report_id = %(report_id)s
              AND (%(severity)s::text IS NULL OR f.severity = %(severity)s)
              AND (%(package)s::text IS NULL OR f.pkg_name ILIKE %(package)s OR f.src_name ILIKE %(package)s)
              AND (%(in_kev)s::boolean IS NULL OR (k.cve_id IS NOT NULL) = %(in_kev)s)
        ) s
        WHERE id > %(cursor)s
        ORDER BY id
        LIMIT %(limit)s""",  # total 在套用 cursor 之前算，所以每一頁拿到的都是全部符合的筆數
        {"report_id": report_id, "severity": severity, "package": package and f"%{package}%",
         "in_kev": in_kev, "cursor": cursor or 0, "limit": limit + 1})
    if not rows and not query("SELECT 1 FROM reports WHERE report_id = %s", [report_id]):
        raise ToolError(f"沒有 report_id {report_id}，請先用 import_report 匯入報告")
    has_more = len(rows) > limit
    rows = rows[:limit]
    total = rows[0]["total"] if rows else 0
    for r in rows:
        del r["total"]
    return {"total": total, "returned": len(rows),
            "next_cursor": rows[-1]["id"] if has_more else None, "findings": rows}

# ---- 工具清單：天真版和匯入版分開，notebook 依策略組合 ----

NAIVE_REPORT_TOOLS = {t.name: t for t in [
    Tool("read_scan_report", """讀取 Trivy 掃描報告，回傳整份 JSON。
何時用：問題跟某份掃描報告的內容有關。
範例：{"path": "data/reports/trivy/myapp.json"}""", ReportPathArgs, read_scan_report),
]}

REPORT_TOOLS = {t.name: t for t in [
    Tool("import_report", """匯入 Trivy 掃描報告，回傳 report_id、總筆數、各 severity 筆數與最嚴重的前 10 筆。
何時用：問題跟某份掃描報告有關，而且這次對話還沒匯入過它；拿到 report_id 後用 query_findings 查細節。
範例：{"path": "data/reports/trivy/myapp.json"}""", ReportPathArgs, import_report),
    Tool("query_findings", f"""查已匯入報告裡的弱點，可依 severity、套件名稱、是否在 KEV 篩選，每頁最多 {MAX_FINDINGS} 筆。
total 是符合條件的總筆數，回答「有幾個」用 total；next_cursor 不是 null 時，把它當 cursor 傳入可以拿下一頁。
何時不用：要依套件分組計數這類統計時，用 run_sql 查 findings 表。
範例：{{"report_id": 1, "severity": "CRITICAL"}}、{{"report_id": 1, "package": "openssl", "limit": 50}}""",
         QueryFindingsArgs, query_findings),
]}
