# src/vuln_agent/queries.py
from pathlib import Path
import duckdb

from vuln_agent.intent import QueryIntent

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "vuln.duckdb"

# 每種 intent 一個寫死的 SQL 樣板，條件一律用具名參數帶入，不拼接字串。
# 沒給的條件傳 NULL，`$x IS NULL OR ...` 讓那一行條件不起作用，所以同一個樣板能處理任意組合。
FROM = """
FROM cve c
LEFT JOIN kev k ON k.cve_id = c.cve_id
LEFT JOIN epss e ON e.cve_id = c.cve_id
"""
WHERE = """
WHERE ($product IS NULL OR c.products ILIKE '%:' || $product || ':%')
  AND ($cwe IS NULL OR c.cwe LIKE '%' || $cwe || '%')
  AND ($min_cvss IS NULL OR c.cvss_score >= $min_cvss)
  AND ($in_kev IS NULL OR (k.cve_id IS NOT NULL) = $in_kev)
  AND ($min_epss IS NULL OR e.epss >= $min_epss)
  AND ($days IS NULL OR c.published >= current_date - $days::INTEGER)
"""
COLUMNS = """
SELECT c.cve_id, c.published::DATE AS published, c.cvss_score, c.severity, c.cwe,
       k.cve_id IS NOT NULL AS in_kev, k.due_date, e.epss, c.description
"""

SQL = {
    "cve_lookup": COLUMNS + FROM + "WHERE c.cve_id = $cve_id",
    # 排序：已被利用（KEV）優先，再看被利用機率（EPSS），最後看嚴重度（CVSS）
    "search": COLUMNS + FROM + WHERE + """
ORDER BY in_kev DESC, e.epss DESC NULLS LAST, c.cvss_score DESC NULLS LAST
LIMIT 20""",
    "count": "SELECT count(*) AS n" + FROM + WHERE,
}

FILTERS = ("product", "cwe", "min_cvss", "in_kev", "min_epss", "days")

def connect():
    """唯讀開啟資料庫；load_data.py 寫入時要先關掉 API。"""
    return duckdb.connect(str(DB_PATH), read_only=True)

def run(db, intent: QueryIntent) -> list[dict]:
    """依 intent 選樣板執行，回傳每列一個 dict；unsupported 不查，回傳空 list。"""
    if intent.intent == "unsupported":
        return []
    if intent.intent == "cve_lookup":
        params = {"cve_id": intent.cve_id}
    else:
        params = {k: getattr(intent, k) for k in FILTERS}
        if params["product"]:
            params["product"] = params["product"].lower()
    cur = db.execute(SQL[intent.intent], params)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]
