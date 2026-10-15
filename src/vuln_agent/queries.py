# src/vuln_agent/queries.py
from vuln_agent.intent import QueryIntent
from vuln_agent.tools import cve_lookup, search_vulns

FILTERS = {"product", "cwe", "min_cvss", "in_kev", "min_epss", "days"}

def run(intent: QueryIntent) -> list[dict]:
    """依 intent 選寫死的查詢，回傳每列一個 dict；unsupported 不查，回傳空 list。
    SQL 樣板在 tools.py 的 cve_lookup()、search_vulns()，階段 2 的 agent 也用同樣的函式。"""
    if intent.intent == "unsupported":
        return []
    if intent.intent == "cve_lookup":
        r = cve_lookup(intent.cve_id)
        return [r] if r["found"] else []
    filters = intent.model_dump(include=FILTERS)
    if intent.intent == "count":
        return [{"n": search_vulns(**filters, limit=1)["total"]}]
    return search_vulns(**filters, limit=20)["results"]
