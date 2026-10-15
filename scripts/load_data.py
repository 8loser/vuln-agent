import os, time
from datetime import datetime, timedelta, timezone
import duckdb, httpx
from vuln_agent.nvd import nvd_get, NVD_SLEEP

os.makedirs("data", exist_ok=True)
db = duckdb.connect("data/vuln.duckdb")

def cvss(metrics):
    """取 CVSS 分數與等級：優先 v3.1，沒有就用 v4.0、v3.0；同一版本優先用 NVD 自己評的 Primary。"""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        items = metrics.get(key)
        if items:
            m = next((i for i in items if i["type"] == "Primary"), items[0])
            return m["cvssData"]["baseScore"], m["cvssData"]["baseSeverity"]
    return None, None

def cwes(weaknesses):
    """取 CWE 編號，略過 NVD-CWE-Other、NVD-CWE-noinfo 這兩個佔位值。"""
    ids = {d["value"] for w in weaknesses for d in w["description"] if d["value"].startswith("CWE-")}
    return ",".join(sorted(ids)) or None

def cpes(configurations):
    """取受影響產品的 CPE 字串；vulnerable 為 false 的是執行平台，不是有漏洞的產品。"""
    found = {m["criteria"] for c in configurations for n in c["nodes"]
             for m in n["cpeMatch"] if m["vulnerable"]}
    return " ".join(sorted(found)) or None

def load_nvd(days=90):  # NVD 一次查詢的日期範圍最多 120 天
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    rows, start_index = [], 0
    while True:
        data = nvd_get({
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "startIndex": start_index,
            "resultsPerPage": 2000,
        })
        for item in data["vulnerabilities"]:
            cve = item["cve"]
            desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            score, severity = cvss(cve.get("metrics", {}))
            rows.append((cve["id"], cve["published"], desc, score, severity,
                         cwes(cve.get("weaknesses", [])), cpes(cve.get("configurations", []))))
        start_index += data["resultsPerPage"]
        print(f"NVD {min(start_index, data['totalResults'])} / {data['totalResults']}")
        if start_index >= data["totalResults"]:
            break
        time.sleep(NVD_SLEEP)
    db.execute("CREATE OR REPLACE TABLE cve (cve_id TEXT, published TIMESTAMP, description TEXT, "
               "cvss_score DOUBLE, severity TEXT, cwe TEXT, products TEXT)")
    db.executemany("INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

def load_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = httpx.get(url, timeout=60).json()
    rows = [(v["cveID"], v["vendorProject"], v["product"], v["dateAdded"], v["dueDate"])
            for v in data["vulnerabilities"]]
    db.execute("CREATE OR REPLACE TABLE kev (cve_id TEXT, vendor TEXT, product TEXT, "
               "date_added DATE, due_date DATE)")
    db.executemany("INSERT INTO kev VALUES (?, ?, ?, ?, ?)", rows)

def load_epss():
    # 每天更新的全量檔；第一行是 #model_version 註解，第二行才是欄位名稱 cve,epss,percentile
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    path = "data/epss_scores-current.csv.gz"
    with open(path, "wb") as f:
        f.write(httpx.get(url, timeout=120, follow_redirects=True).content)
    # 幾十萬筆用 executemany 很慢，直接讓 DuckDB 讀 gzip CSV
    db.execute("CREATE OR REPLACE TABLE epss AS "
               "SELECT cve AS cve_id, epss, percentile FROM read_csv(?, skip=1, header=true)", [path])

if __name__ == "__main__":
    load_kev(); load_epss(); load_nvd()
    for t in ("cve", "kev", "epss"):
        print(t, db.execute(f"SELECT count(*) FROM {t}").fetchone()[0])
