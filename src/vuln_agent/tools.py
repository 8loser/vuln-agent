# src/vuln_agent/tools.py
import re
from dataclasses import dataclass
from typing import Annotated, Callable

import psycopg
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vuln_agent.db import connect
from vuln_agent.nvd import NVD_DAYS

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"
CveId = Annotated[str, Field(pattern=CVE_PATTERN, description="CVE 編號，例如 CVE-2021-44228")]
MAX_SQL_ROWS = 100

class ToolError(Exception):
    """要回給模型看的錯誤：訊息寫清楚哪裡錯、合法值是什麼，模型才能自己修正重試。"""

def query(sql: str, params=None) -> list[dict]:
    """用唯讀的 vuln_agent 角色執行一次查詢，每列轉成 dict。"""
    # ponytail: 每次呼叫開一條新連線，本機夠快；同時請求變多時改用 psycopg_pool
    with connect("agent") as conn:
        cur = conn.execute(sql, params)
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

# ---- 工具的參數：Pydantic model 同時產生給模型看的 JSON Schema，也負責驗證模型傳來的參數 ----

class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")  # 模型多傳不存在的參數時直接報錯，而不是默默忽略

class CveLookupArgs(Args):
    cve_id: CveId

class SearchVulnsArgs(Args):
    product: str | None = Field(None, description="產品或廠商名稱，小寫，對應 CPE 的 product 或 vendor，例如 nginx、openssl、microsoft")
    cwe: str | None = Field(None, pattern=r"^CWE-\d+$", description="弱點類型，例如 SQL injection 是 CWE-89、XSS 是 CWE-79")
    min_cvss: float | None = Field(None, ge=0, le=10, description="CVSS 下限；「高風險」用 7、「嚴重」用 9")
    in_kev: bool | None = Field(None, description="true 只看已被實際利用（在 CISA KEV）的")
    min_epss: float | None = Field(None, ge=0, le=1, description="EPSS 下限，0 到 1")
    days: int | None = Field(None, ge=1, description="只看最近幾天發布的")
    limit: int = Field(20, ge=1, le=50, description="最多回傳幾筆")

class PrioritizeArgs(Args):
    cve_ids: list[CveId] = Field(min_length=1, max_length=50, description="要排序的 CVE 編號")

class RunSqlArgs(Args):
    query: str = Field(description="單一條 PostgreSQL SELECT 查詢")

# ---- 工具本體：只管查詢，參數已經過驗證 ----

def cve_lookup(cve_id: str) -> dict:
    """單一 CVE 的完整資料；從輸入的編號 LEFT JOIN 三張表，所以只有 KEV 或 EPSS 有資料時也查得到。"""
    rows = query("""
        SELECT q.cve_id, c.published::date AS published, c.cvss_score, c.severity, c.cwe, c.description,
               (SELECT count(DISTINCT (p.vendor, p.product)) FROM cve_product p
                WHERE p.cve_id = q.cve_id) AS product_count,
               ARRAY(SELECT DISTINCT p.vendor || ':' || p.product FROM cve_product p
                     WHERE p.cve_id = q.cve_id ORDER BY 1 LIMIT 20) AS products,  -- 熱門 CVE 有上百個，只給前 20 個省 tokens
               k.cve_id IS NOT NULL AS in_kev, k.date_added AS kev_date_added, k.due_date AS kev_due_date,
               e.epss, e.percentile AS epss_percentile, c.cve_id IS NOT NULL AS has_nvd
        FROM (SELECT %s::text AS cve_id) q
        LEFT JOIN cve c USING (cve_id) LEFT JOIN kev k USING (cve_id) LEFT JOIN epss e USING (cve_id)""",
        [cve_id])
    r = rows[0]
    if not (r.pop("has_nvd") or r["in_kev"] or r["epss"] is not None):
        return {"cve_id": cve_id, "found": False,
                "message": f"資料庫裡沒有這個 CVE（只收最近 {NVD_DAYS} 天發布與在 KEV 裡的 CVE）"}
    return {"found": True, **r}

ORDER = "in_kev DESC, epss DESC NULLS LAST, cvss_score DESC NULLS LAST"  # KEV → EPSS → CVSS

def search_vulns(product, cwe, min_cvss, in_kev, min_epss, days, limit) -> dict:
    """依條件找 CVE，依 KEV → EPSS → CVSS 排序；total 是截斷前的總筆數。"""
    rows = query(f"""
        SELECT c.cve_id, c.published::date AS published, c.cvss_score, c.severity, c.cwe,
               k.cve_id IS NOT NULL AS in_kev, k.due_date AS kev_due_date, e.epss,
               count(*) OVER () AS total
        FROM cve c LEFT JOIN kev k USING (cve_id) LEFT JOIN epss e USING (cve_id)
        WHERE (%(product)s::text IS NULL
               OR EXISTS (SELECT 1 FROM cve_product p WHERE p.cve_id = c.cve_id
                          AND (p.product = %(product)s OR p.vendor = %(product)s))
               OR lower(k.vendor) = %(product)s OR lower(k.product) = %(product)s)
          AND (%(cwe)s::text IS NULL OR %(cwe)s = ANY(string_to_array(c.cwe, ',')))
          AND (%(min_cvss)s::float8 IS NULL OR c.cvss_score >= %(min_cvss)s)
          AND (%(in_kev)s::boolean IS NULL OR (k.cve_id IS NOT NULL) = %(in_kev)s)
          AND (%(min_epss)s::float8 IS NULL OR e.epss >= %(min_epss)s)
          AND (%(days)s::int IS NULL OR c.published >= now() - make_interval(days => %(days)s::int))
        ORDER BY {ORDER}
        LIMIT %(limit)s""",
        {"product": product and product.lower(), "cwe": cwe, "min_cvss": min_cvss, "in_kev": in_kev,
         "min_epss": min_epss, "days": days, "limit": limit})
    total = rows[0]["total"] if rows else 0
    for r in rows:
        del r["total"]
    return {"total": total, "returned": len(rows), "truncated": total > len(rows), "results": rows}

def prioritize(cve_ids: list[str]) -> dict:
    """把給定的 CVE 依 KEV → EPSS → CVSS 排序，每筆附一句用規則產生的理由。"""
    rows = query(f"""
        SELECT q.cve_id, k.cve_id IS NOT NULL AS in_kev, k.due_date AS kev_due_date, e.epss, c.cvss_score
        FROM unnest(%s::text[]) AS q(cve_id)
        LEFT JOIN cve c USING (cve_id) LEFT JOIN kev k USING (cve_id) LEFT JOIN epss e USING (cve_id)
        ORDER BY {ORDER}""", [list(dict.fromkeys(cve_ids))])
    for rank, r in enumerate(rows, 1):
        r["rank"], r["reason"] = rank, reason(r)
    return {"ranked": rows}

def reason(r: dict) -> str:
    parts = []
    if r["in_kev"]:
        parts.append(f"已在 KEV（確認被實際利用），修補期限 {r['kev_due_date']}")
    if r["epss"] is not None:
        parts.append(f"EPSS {r['epss']}（未來 30 天被利用的機率）")
    if r["cvss_score"] is not None:
        parts.append(f"CVSS {r['cvss_score']}")
    return "；".join(parts) or "資料庫查不到這個 CVE 的 KEV、EPSS、CVSS，排在最後"

def run_sql(query_text: str) -> dict:
    """執行模型寫的 SELECT。防護分三層：
    1. 字串檢查：只接受一條 SELECT / WITH，給模型清楚的錯誤訊息
    2. 包成子查詢再加 LIMIT：DELETE、多條語句放進子查詢都是語法錯誤，結果也不會超過 MAX_SQL_ROWS 筆
    3. 資料庫：vuln_agent 只有 SELECT 權限、唯讀交易、statement_timeout 5 秒（見 db/init.sh）"""
    q = query_text.strip().rstrip(";").strip()
    if ";" in q:
        raise ToolError("一次只能執行一條 SELECT，請拿掉分號與後面的語句")
    if not re.match(r"(?i)(select|with)\b", q):
        raise ToolError("run_sql 只接受 SELECT 查詢（可用 WITH 開頭），不能修改資料")
    try:
        # 換行包住原查詢，結尾的 -- 註解才不會把右括號註解掉
        rows = query(f"SELECT * FROM (\n{q}\n) AS q LIMIT {MAX_SQL_ROWS + 1}")
    except psycopg.errors.QueryCanceled:
        raise ToolError("查詢超過 5 秒被中止，請加上條件或改用索引欄位（published、cvss_score、product、epss）縮小範圍")
    except (psycopg.errors.InsufficientPrivilege, psycopg.errors.ReadOnlySqlTransaction):
        raise ToolError("沒有權限：只能 SELECT cve、cve_product、kev、epss、reports、findings")
    except psycopg.Error as e:  # 欄位名稱打錯、語法錯誤等，原始訊息最能幫模型修正
        raise ToolError(f"SQL 執行錯誤：{e}")
    return {"rows": rows[:MAX_SQL_ROWS], "truncated": len(rows) > MAX_SQL_ROWS}

# ---- 工具清單：描述就是給模型看的說明書，寫清楚何時用、何時不用，加上參數範例 ----

@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    args: type[Args]
    fn: Callable[..., dict]

TOOLS = {t.name: t for t in [
    Tool("cve_lookup", """查單一 CVE 的完整資料：描述、CVSS、CWE、受影響產品、是否在 KEV（已被實際利用）與修補期限、EPSS。
何時用：問題裡已經寫出明確的 CVE 編號。
何時不用：只有產品名稱、漏洞俗稱或條件時，改用 search_vulns；不要憑記憶把俗稱換成 CVE 編號。
範例：{"cve_id": "CVE-2021-44228"}""", CveLookupArgs, cve_lookup),
    Tool("search_vulns", f"""依條件搜尋漏洞，結果依 KEV → EPSS → CVSS 排序；total 是符合條件的總筆數，回答「有幾個」用 total。
資料範圍：最近 {NVD_DAYS} 天發布的 CVE，加上 KEV 收錄的 CVE；問更早的時間範圍時，要說明資料只涵蓋最近 {NVD_DAYS} 天。
何時用：用產品、弱點類型、CVSS、是否已被利用、EPSS、最近幾天找漏洞或算數量。
何時不用：問題有明確 CVE 編號時用 cve_lookup；要分組統計（例如每個廠商幾個）時用 run_sql。
範例：最近 30 天影響 nginx、CVSS 7 以上且已被利用 → {{"product": "nginx", "min_cvss": 7, "in_kev": true, "days": 30}}""",
         SearchVulnsArgs, search_vulns),
    Tool("prioritize", """把一組 CVE 依修補優先順序排好：先看是否在 KEV，再看 EPSS，最後看 CVSS，每筆附排序理由。
何時用：使用者給了多個 CVE，問先修哪個。
何時不用：還不知道有哪些 CVE 時，先用 search_vulns（它的結果已經排好序）。
範例：{"cve_ids": ["CVE-2024-3400", "CVE-2023-4966"]}""", PrioritizeArgs, prioritize),
    Tool("run_sql", f"""對漏洞資料庫執行一條唯讀的 PostgreSQL SELECT，最多回傳 {MAX_SQL_ROWS} 筆，超過 5 秒會被中止。
何時用：其他工具做不到的統計，例如分組計數、依週統計、排名。
資料範圍：cve 表只有最近 {NVD_DAYS} 天發布的 CVE，加上 KEV 收錄的 CVE。
何時不用：查單一 CVE 或依條件找漏洞時，用 cve_lookup 或 search_vulns。
資料表：
- cve(cve_id, published timestamptz, last_modified, description, cvss_score, severity, cwe)；cwe 是逗號分隔字串，例如 'CWE-79,CWE-89'
- cve_product(cve_id, cpe, vendor, product)；vendor、product 是小寫
- kev(cve_id, vendor, product, date_added, due_date)；vendor、product 是原始大小寫，例如 'Microsoft'
- epss(cve_id, epss, percentile, score_date)
- reports(report_id, path, imported_at)、findings(id, report_id, cve_id, pkg_name, src_name, installed_version, fixed_version, severity, target)：import_report 匯入的掃描報告，查 findings 一定要加 report_id 條件
範例：{{"query": "SELECT vendor, count(*) AS n FROM kev GROUP BY vendor ORDER BY n DESC LIMIT 10"}}""",
         RunSqlArgs, lambda query: run_sql(query)),
]}

def schemas(tools: dict[str, Tool]) -> list[dict]:
    """轉成 Messages API 的 tools 參數。"""
    return [{"name": t.name, "description": t.description, "input_schema": t.args.model_json_schema()}
            for t in tools.values()]

def call_tool(tools: dict[str, Tool], name: str, raw_args: dict) -> dict:
    """驗證參數後執行工具；不存在的工具、參數不合法都丟 ToolError，訊息寫給模型看。"""
    tool = tools.get(name)
    if tool is None:
        raise ToolError(f"沒有 {name} 這個工具，可用的有：{', '.join(tools)}")
    try:
        args = tool.args.model_validate(raw_args)
    except ValidationError as e:
        problems = "；".join(f"{'.'.join(map(str, err['loc'])) or '參數'}：{err['msg']}（收到 {err.get('input')!r}）"
                             for err in e.errors())
        raise ToolError(f"{name} 的參數不合法，請修正後重試：{problems}")
    return tool.fn(**args.model_dump())
