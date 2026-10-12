# 階段 2：Tool use、Agent 雛形與資料管線（約 12 小時）

階段 1 的流程是固定的：模型把問題解析成意圖，程式再套寫死的 SQL 樣板。這個階段把「下一步做什麼」交給模型決定：手寫一個 tool-use loop，讓模型自己挑 `cve_lookup`、`search_vulns`、`prioritize`、`run_sql` 這些工具，看結果再決定要不要繼續查。同時把資料從手動執行的 DuckDB 腳本升級成排程更新的 PostgreSQL，NVD 做增量更新、重試與速率限制，KEV、EPSS 每天自動更新。做完之後，作品第一次有了 agent 的雛形，資料也會自己保持在最新狀態。階段 1 的 10 題測試題繼續沿用，這次拿來比較不同工具設計的選擇正確率。

### 要學的概念

- **Tool-use loop**：模型回「要呼叫工具」→ 程式執行 → 把結果送回 → 重複到模型給出最終答案。agent 的核心就這幾行，先手寫一次，之後用框架才知道它替你做了什麼。
- **錯誤也是給模型看的訊息**：工具出錯時回一段模型看得懂的錯誤（哪個參數錯、合法值是什麼），模型多半能自己修正重試；直接丟 exception 只會讓整個 loop 中斷。
- **停止條件**：最大步數、單一工具逾時、整體逾時與 token 上限，少了這些，模型反覆呼叫同一個工具時花費會失控。
- **工具設計就是 prompt 設計**：工具的粒度、名稱、描述、參數 schema 會直接影響模型選對工具的機率，要用測試題量化比較，不能憑感覺。
- **唯讀的 `run_sql` 要靠資料庫權限把關**：只檢查 SQL 字串擋不住所有寫入，要用唯讀角色、唯讀交易、`statement_timeout` 和筆數上限多層防護。
- **ETL 的冪等與增量**：NVD 有速率限制，每次全量重抓不實際；記錄上次成功的時間點、只抓變更、用 upsert 寫入，重跑幾次結果都一樣。

### 步驟 1：PostgreSQL 與 schema（約 1.5 小時）

- [ ] 寫 `docker-compose.yml` 起 PostgreSQL（掛 volume，密碼放 `.env`，不 commit），`uv add` 一個 PostgreSQL 驅動（例如 psycopg，用法以官方文件為準）
- [ ] 設計 schema：`cve`、`cve_product`（一個 CVE 對多個 CPE，拆表）、`kev`、`epss`，加上記錄每次 ETL 的 `etl_runs`（來源、開始與結束時間、筆數、狀態、增量的時間點）
- [ ] 建索引：`cve.published`、`cve.cvss_score`、`cve_product.product`、`epss.epss`；主鍵都用 `cve_id`，方便 upsert
- [ ] 建兩個角色：ETL 用的可寫角色、agent 用的唯讀角色（只有 SELECT 權限，預設唯讀交易、設 `statement_timeout`）
- [ ] 把階段 1 的 `load_data.py` 改成寫進 PostgreSQL，跑一次全量匯入，跟 DuckDB 的筆數對照
- [ ] 記下四張表各幾筆、階段 1 那 3 條 SQL 在 PostgreSQL 上的結果是否一致

### 步驟 2：ETL 排程：增量、重試、速率限制（約 2 小時）

- [ ] NVD 改成增量：從 `etl_runs` 取上次成功的時間點，用 NVD API 的「最後修改時間」區間參數只抓變更（參數名稱與單次查詢的最大天數以官方文件為準），寫入用 `INSERT ... ON CONFLICT DO UPDATE`
- [ ] 實作速率限制與重試：依有沒有 API key 調整請求間隔（實際上限以官方文件為準），遇到 403、429、503 用指數退避重試，超過次數就把這次 run 標成失敗，下次從同一個時間點重來
- [ ] KEV、EPSS 改成每日更新：KEV 整份 upsert；EPSS 用 PostgreSQL 的 `COPY` 匯入暫存表再合併，比逐筆 insert 快很多
- [ ] 排程二選一並寫下理由：本機 cron 呼叫 `docker compose run etl`，或 GitHub Actions 排程（要注意 Actions 連不到本機的資料庫，需要雲端 DB 或 self-hosted runner；API key 放 repository secrets）
- [ ] 刻意中斷一次（例如跑到一半 kill），確認重跑後資料不重複、時間點正確接續
- [ ] 記下：增量一次抓了幾筆、花多久、`etl_runs` 最近幾筆的紀錄

### 步驟 3：實作四個工具（約 1.5 小時）

- [ ] `cve_lookup(cve_id)`：回單一 CVE 的描述、CVSS、CWE、受影響產品，以及是否在 KEV、EPSS 分數；查不到時回明確的「not found」，不要回空字串
- [ ] `search_vulns(product, min_cvss, in_kev, min_epss, days, limit)`：用參數化 SQL 組條件，`limit` 有上限，回傳附上總筆數，讓模型知道結果有被截斷
- [ ] `prioritize(cve_ids)`：依 KEV → EPSS → CVSS 排序，每筆附一句排序理由（先用規則產生，不用 LLM）
- [ ] `run_sql(query)`：用唯讀角色連線，只接受單一 SELECT，自動加 LIMIT，逾時就回錯誤訊息；故意送 `DELETE`、`DROP`、多條語句、跑很久的查詢，確認都被擋下
- [ ] 每個工具寫 JSON Schema（`input_schema`）和 Pydantic 驗證，參數錯誤時回「哪個欄位錯、合法值是什麼」
- [ ] 每個工具寫 2 到 3 個 pytest，不經過 LLM 直接測

### 步驟 4：手寫 tool-use loop（約 1.5 小時）

- [ ] 用官方 SDK 寫 `run_agent(question)`：送出工具清單 → 模型要求呼叫工具就執行 → 把結果包成 tool result 送回 → 重複到模型給出最終答案（下面是骨架，SDK 欄位名稱以官方文件為準）
- [ ] 錯誤處理：工具丟 exception 或驗證失敗時，回傳標成錯誤的 tool result，內容寫清楚原因；測一題故意讓模型傳錯參數，看它會不會自己修正
- [ ] 停止條件：最大步數（例如 8）、單一工具逾時、整體逾時，碰到就回「查詢未完成」加上已查到的部分
- [ ] 每一步記 log：第幾步、呼叫哪個工具、參數、耗時、tokens、花費，整題結束記總計
- [ ] 把 `/ask` 改成走 agent，`/ask/stream` 串流每一步的工具呼叫事件和最後的中文說明
- [ ] system prompt 保留階段 1 的規則：只能提工具結果裡出現的 CVE、拒絕 exploit 與範圍外問題

```python
def run_agent(question: str, max_steps: int = 8) -> str:
    messages = [{"role": "user", "content": question}]
    for step in range(max_steps):
        resp = client.messages.create(model=MODEL, max_tokens=2048, system=SYSTEM,
                                      tools=TOOL_SCHEMAS, messages=messages)
        log_usage(step, resp.usage)
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            try:
                output = call_tool(block.name, block.input, timeout=10)  # 驗證 + 執行
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": json.dumps(output, ensure_ascii=False)})
            except ToolError as e:  # 驗證失敗、逾時、查無資料
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": str(e), "is_error": True})
        messages.append({"role": "user", "content": results})
    return "查詢未完成：已達最大步數"
```

### 步驟 5：工具設計比較（約 1 小時）

- [ ] 擴充 `evals/seed.jsonl`：每題加上「預期會呼叫的工具」（例如問單一 CVE 應該用 `cve_lookup`，不該用 `run_sql`）
- [ ] 準備三種工具組：A. 只有一個大工具 `query_vulns(intent, ...)`；B. 四個小工具、描述只有一行；C. 四個小工具、描述寫清楚何時用與何時不用，加上參數範例
- [ ] 寫小腳本跑 10 題 × 3 種工具組，記錄工具選擇正確率、平均步數、tokens、花費，各跑 2 到 3 次看穩定度
- [ ] 挑出選錯的題目，看是描述、命名還是 schema 造成的，改一版再跑一次
- [ ] 決定作品要用哪一組，把理由寫進 README

### 步驟 6：最小評測（約 4 小時）

把階段 1 開始收集的 seed 題變成「能跑」的測試。先只用程式斷言，不用 LLM 當評審；完整的 error analysis、LLM-as-judge 和大型評測集留在階段 6。之後每加一個 harness 功能，都先跑這組測試看數字有沒有變。

- [ ] 結構化擷取：`seed.jsonl` 每題的 `QueryIntent` 欄位跟標準答案逐欄比對（intent、產品、時間範圍、門檻）
- [ ] ETL 斷言：各表筆數在合理範圍、`cve_id` 都符合 `CVE-\d{4}-\d{4,}`、KEV 裡的 CVE 都找得到對應的 `cve` 資料
- [ ] Agent 斷言：每題有沒有呼叫預期的工具、步數沒超過上限、回答裡的 CVE 都出現在工具結果裡
- [ ] 用 pytest 包起來，輸出一張「通過率 / 平均 tokens / 花費」摘要表，結果存成 jsonl 方便跟上一次比
- [ ] 放進 GitHub Actions：程式斷言每次 push 都跑；要呼叫 LLM 的題目先手動觸發，API key 放 GitHub secrets
- [ ] seed 題補到 20 題以上，之後每碰到一個答錯的問題就加進來

### 步驟 7：收尾（約 30 分鐘）

- [ ] README：架構圖（ETL → PostgreSQL → 工具 → agent loop → FastAPI）、`docker compose up` 與排程設定方式、工具清單、工具設計比較表
- [ ] （選做）寫一篇文章：「不用框架手寫 agent loop：用 NVD / KEV / EPSS 練 tool use、工具設計與 ETL 增量更新」

**完成標準**：`docker compose up` 能起 PostgreSQL，ETL 排程每天更新 KEV、EPSS，NVD 增量更新中斷後重跑不會重複，`etl_runs` 有紀錄；四個工具都有 pytest，`run_sql` 擋得住寫入、多條語句和長時間查詢；`/ask` 走 agent loop，log 看得到每一步的工具、參數、tokens 與花費，碰到最大步數或逾時會正常結束；有三種工具組的比較表（選擇正確率、步數、花費），並能說明為什麼選定的那一組比較好，以及錯誤訊息怎麼寫才能讓模型自己修正。
