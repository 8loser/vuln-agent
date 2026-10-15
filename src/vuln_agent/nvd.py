# src/vuln_agent/nvd.py
import os, time
import httpx
from dotenv import load_dotenv

load_dotenv()
NVD_KEY = os.getenv("NVD_API_KEY")
# NVD 速率限制：沒有 key 每 30 秒 5 次（官方建議每次間隔 6 秒），有 key 每 30 秒 50 次
NVD_SLEEP = 0.6 if NVD_KEY else 6
# 資料庫收錄的範圍：最近 NVD_DAYS 天發布的 CVE，加上 KEV 收錄的 CVE；etl.py 與工具說明共用
NVD_DAYS = 30

def nvd_get(params):
    """呼叫 NVD API；被限速、伺服器忙碌或逾時時等 30 秒（一個速率限制窗口）再試，最多 5 次。"""
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    for attempt in range(5):
        try:
            r = httpx.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                          params=params, headers=headers, timeout=60)
            # 官方文件沒寫限速時回哪個狀態碼，403、429、503 都當成要等一下再試
            if r.status_code not in (403, 429, 503):
                r.raise_for_status()
                return r.json()
        except httpx.TimeoutException:
            # NVD 忙碌時可能超過 60 秒都不回應，跟限速一樣等一下再試
            if attempt == 4:
                raise
        time.sleep(30)
    r.raise_for_status()

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
    """取受影響產品的 CPE 字串清單；vulnerable 為 false 的是執行平台，不是有漏洞的產品。"""
    found = {m["criteria"] for c in configurations for n in c["nodes"]
             for m in n["cpeMatch"] if m["vulnerable"]}
    return sorted(found)
