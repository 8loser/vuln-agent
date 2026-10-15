# src/vuln_agent/nvd.py
import os, time
import httpx
from dotenv import load_dotenv

load_dotenv()
NVD_KEY = os.getenv("NVD_API_KEY")
# NVD 速率限制：沒有 key 每 30 秒 5 次（官方建議每次間隔 6 秒），有 key 每 30 秒 50 次
NVD_SLEEP = 0.6 if NVD_KEY else 6

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
