# scripts/etl.py：把 KEV、EPSS、NVD 更新進 PostgreSQL，每個來源在 etl_runs 留一筆紀錄
# 用法：uv run scripts/etl.py [kev] [epss] [nvd]，不給參數就三個都跑；排程每天跑一次
import gzip, re, sys, time
from datetime import datetime, timedelta, timezone
import httpx

from vuln_agent.db import connect
from vuln_agent.nvd import nvd_get, NVD_DAYS, NVD_SLEEP, cvss, cwes, cpes

MAX_RANGE = timedelta(days=120)    # NVD 一次查詢的日期範圍最多 120 天
# NVD 每小時整批寫入一次變更；查詢當下可能有一批還沒寫完，增量往前多抓一小時，重複的由 upsert 覆蓋
OVERLAP = timedelta(hours=1)
NVD_TIME = "%Y-%m-%dT%H:%M:%S.000+00:00"  # 明確標 UTC；httpx 會把 + 編碼成 %2B

CVE_UPSERT = """
INSERT INTO cve (cve_id, published, last_modified, description, cvss_score, severity, cwe)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (cve_id) DO UPDATE SET
    published = EXCLUDED.published, last_modified = EXCLUDED.last_modified,
    description = EXCLUDED.description, cvss_score = EXCLUDED.cvss_score,
    severity = EXCLUDED.severity, cwe = EXCLUDED.cwe"""

def vendor_product(cpe: str) -> tuple[str, str]:
    """CPE 格式 cpe:2.3:類型:廠商:產品:版本:...，取第 4、5 段。
    欄位裡的特殊字元會用反斜線跳脫（例如 \\: 、\\&），所以只在沒跳脫的冒號切開，再拿掉反斜線。"""
    parts = re.split(r"(?<!\\):", cpe)
    return parts[3].replace("\\", ""), parts[4].replace("\\", "")

def upsert_cves(conn, items) -> int:
    """把一頁 NVD 結果 upsert 進 cve 與 cve_product；被撤銷（Rejected）的 CVE 從資料庫刪掉。"""
    cves, products, ids, rejected = [], [], [], []
    for item in items:
        cve = item["cve"]
        if cve.get("vulnStatus", "").lower() == "rejected":  # 官方文件裡大小寫都出現過
            rejected.append(cve["id"])
            continue
        desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        score, severity = cvss(cve.get("metrics", {}))
        cves.append((cve["id"], cve["published"], cve["lastModified"], desc, score, severity,
                     cwes(cve.get("weaknesses", []))))
        ids.append(cve["id"])
        products += [(cve["id"], cpe, *vendor_product(cpe)) for cpe in cpes(cve.get("configurations", []))]
    with conn.cursor() as cur:
        cur.executemany(CVE_UPSERT, cves)
        # 受影響產品整組換掉，比逐筆比對新舊差異簡單，重跑結果也一樣
        cur.execute("DELETE FROM cve_product WHERE cve_id = ANY(%s)", [ids])
        cur.executemany("INSERT INTO cve_product VALUES (%s, %s, %s, %s)", products)
        cur.execute("DELETE FROM cve WHERE cve_id = ANY(%s)", [rejected])  # cve_product 由外鍵 CASCADE 一起刪
    return len(cves)

def fetch_nvd(conn, params: dict) -> int:
    """依 params 分頁抓 NVD，每頁 upsert 一次，回傳寫入筆數。"""
    start_index, n = 0, 0
    while True:
        time.sleep(NVD_SLEEP)  # 每個請求前都等，連續呼叫 fetch_nvd 也不會超過速率限制
        data = nvd_get({**params, "startIndex": start_index, "resultsPerPage": 2000})
        n += upsert_cves(conn, data["vulnerabilities"])
        start_index += data["resultsPerPage"]
        print(f"  NVD {min(start_index, data['totalResults'])} / {data['totalResults']}")
        if start_index >= data["totalResults"]:
            return n

def load_nvd(conn):
    """第一次抓最近 NVD_DAYS 天發布的；之後只抓上次成功之後修改過的（增量）。KEV 收錄的 CVE 每次都整批再抓一次。"""
    end = datetime.now(timezone.utc)
    last = conn.execute("SELECT max(watermark) FROM etl_runs "
                        "WHERE source = 'nvd' AND status = 'success'").fetchone()[0]
    n = 0
    if last is None:
        n += fetch_nvd(conn, {"pubStartDate": (end - timedelta(days=NVD_DAYS)).strftime(NVD_TIME),
                              "pubEndDate": end.strftime(NVD_TIME)})
    else:
        start = last - OVERLAP
        while start < end:  # 超過 120 天沒跑就切成多段
            stop = min(start + MAX_RANGE, end)
            n += fetch_nvd(conn, {"lastModStartDate": start.strftime(NVD_TIME),
                                  "lastModEndDate": stop.strftime(NVD_TIME)})
            start = stop
    # KEV 的 CVE 多半發布很久了，不在上面的時間範圍；hasKev 一次只有一兩千筆，每次全抓確保 kev 都對得到 cve
    n += fetch_nvd(conn, {"hasKev": ""})
    return n, end

def load_kev(conn):
    """KEV 整份 upsert，CISA 從清單移除的項目也一起刪掉。watermark 是清單的發布時間。"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = httpx.get(url, timeout=60).json()
    rows = [(v["cveID"], v["vendorProject"], v["product"], v["dateAdded"], v["dueDate"])
            for v in data["vulnerabilities"]]
    with conn.cursor() as cur:
        cur.executemany("""
            INSERT INTO kev VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET vendor = EXCLUDED.vendor, product = EXCLUDED.product,
                date_added = EXCLUDED.date_added, due_date = EXCLUDED.due_date""", rows)
        cur.execute("DELETE FROM kev WHERE cve_id <> ALL(%s)", [[r[0] for r in rows]])
    return len(rows), data["dateReleased"]

def load_epss(conn):
    """EPSS 全量檔有幾十萬筆：先用 COPY 灌進暫存表，再一次合併進 epss，比逐筆 INSERT 快很多。"""
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    text = gzip.decompress(httpx.get(url, timeout=120, follow_redirects=True).content).decode()
    # 第一行是 #model_version:...,score_date:2026-10-15T00:00:00Z，第二行起才是 CSV
    first, csv_text = text.split("\n", 1)
    score_date = first.split("score_date:")[1].strip()
    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE epss_new (cve_id text, epss float8, percentile float8) ON COMMIT DROP")
        with cur.copy("COPY epss_new FROM STDIN (FORMAT csv, HEADER true)") as copy:
            copy.write(csv_text)
        cur.execute("""
            INSERT INTO epss SELECT cve_id, epss, percentile, %s FROM epss_new
            ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
                score_date = EXCLUDED.score_date""", [score_date])
        return cur.rowcount, score_date

LOADERS = {"kev": load_kev, "epss": load_epss, "nvd": load_nvd}

def run(conn, source: str):
    """跑一個來源，前後寫 etl_runs。資料寫入跟「標成 success」在同一個交易：
    中途失敗或被中斷，資料整批不寫入，下次從上次成功的 watermark 重來；upsert 讓重跑不會重複。"""
    run_id = conn.execute("INSERT INTO etl_runs (source, status) VALUES (%s, 'running') RETURNING id",
                          [source]).fetchone()[0]
    conn.commit()  # 先提交 running，被 kill 時這一列會停在 running，看得出有一次沒跑完
    t = time.time()
    print(f"{source}：開始")
    try:
        rows, watermark = LOADERS[source](conn)
        conn.execute("UPDATE etl_runs SET status = 'success', finished_at = now(), rows = %s, watermark = %s "
                     "WHERE id = %s", [rows, watermark, run_id])
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.execute("UPDATE etl_runs SET status = 'failed', finished_at = now(), error = %s WHERE id = %s",
                     [repr(e), run_id])
        conn.commit()
        raise
    print(f"{source}：寫入 {rows} 筆，{time.time() - t:.0f} 秒")

if __name__ == "__main__":
    with connect("etl") as conn:
        for source in sys.argv[1:] or LOADERS:
            run(conn, source)
        for t in ("cve", "cve_product", "kev", "epss"):
            print(t, conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0])
