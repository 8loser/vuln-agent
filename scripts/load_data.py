import gzip, io, csv, os
from datetime import datetime, timedelta, timezone
import duckdb, httpx
from dotenv import load_dotenv

load_dotenv()
os.makedirs("data", exist_ok=True)
db = duckdb.connect("data/vuln.duckdb")

def load_nvd(days=90):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    rows, start_index = [], 0
    while True:
        r = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "startIndex": start_index,
                "resultsPerPage": 2000,
            },
            headers=headers, timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        for item in data["vulnerabilities"]:
            cve = item["cve"]
            desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            # TODO 1：從 cve["metrics"] 取 CVSS v3.1 的 baseScore、baseSeverity（可能不存在）
            # TODO 2：從 cve["weaknesses"] 取 CWE 編號
            # TODO 3：從 cve["configurations"] 取 CPE 字串，串成 products
            rows.append((cve["id"], cve["published"], desc, None, None, None, None))
        start_index += data["resultsPerPage"]
        if start_index >= data["totalResults"]:
            break
        # TODO 4：沒有 API key 時要 sleep；處理 403 / 503 重試
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
    day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    url = f"https://epss.cyentia.com/epss_scores-{day}.csv.gz"
    raw = gzip.decompress(httpx.get(url, timeout=120, follow_redirects=True).content).decode()
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = [(r["cve"], float(r["epss"]), float(r["percentile"])) for r in reader]
    db.execute("CREATE OR REPLACE TABLE epss (cve_id TEXT, epss DOUBLE, percentile DOUBLE)")
    db.executemany("INSERT INTO epss VALUES (?, ?, ?)", rows)

if __name__ == "__main__":
    load_kev(); load_epss(); load_nvd()
    for t in ("cve", "kev", "epss"):
        print(t, db.execute(f"SELECT count(*) FROM {t}").fetchone()[0])
