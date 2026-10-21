# 階段 2：Tool use、Agent 雛形與資料管線

階段 1 的流程是固定的：模型把問題解析成意圖，程式再套寫死的 SQL 樣板。這個階段把「下一步做什麼」交給模型決定：手寫一個 tool-use loop，讓模型自己挑 `cve_lookup`、`search_vulns`、`prioritize`、`run_sql` 這些工具，看結果再決定要不要繼續查。同時把階段 1 手動跑過一次的 ETL 變成每天排程更新：NVD 做增量更新、重試與速率限制，KEV、EPSS 每天自動更新。做完之後，作品第一次有了 agent 的雛形，資料也會自己保持在最新狀態。階段 1 的測試題補到 20 題，這次拿來比較不同工具設計的選擇正確率。

程式都已經寫好。資料庫與 ETL（步驟 1、2）是一般後端工作，階段 1 已經跑起來，這裡看懂設計、設好排程就好；時間留給步驟 3 以後的工具設計、agent loop 與評測。

**做完後的樣子**：問 `/ask/stream`「最近 30 天影響 nginx、CVSS 7 以上而且已經被利用的漏洞？」

1. 模型自己決定呼叫 `search_vulns`，參數是 `{"product": "nginx", "min_cvss": 7, "in_kev": true, "days": 30}`
2. 工具結果送回模型，模型判斷資料夠了，用中文說明，只提工具結果裡的 CVE
3. 串流看得到每一步：呼叫哪個工具、參數、結果，最後是說明文字
4. 參數傳錯時，模型看到錯誤訊息會自己修正再查；查到第 8 步還沒結束就停下來，回「查詢未完成」
5. log 每一步記下工具、參數、耗時、tokens、花費
6. 資料每天由排程更新，`etl_runs` 看得到每次更新的筆數與狀態

架構：`etl.py`（每天排程）→ PostgreSQL → `tools.py`（唯讀角色）→ `agent.py` 的 loop → `agent_api.py`（FastAPI）。

### 要學的概念

- **Tool-use loop**：模型回「要呼叫工具」→ 程式執行 → 把結果送回 → 重複到模型給出最終答案。agent 的核心就這幾行，先手寫一次，之後用框架才知道它替你做了什麼。
- **錯誤也是給模型看的訊息**：工具出錯時回一段模型看得懂的錯誤（哪個參數錯、合法值是什麼），模型多半能自己修正重試；直接丟 exception 只會讓整個 loop 中斷。
- **停止條件**：最大步數、單一工具逾時、整體逾時，少了這些，模型反覆呼叫同一個工具時花費會失控。
- **工具設計就是 prompt 設計**：工具的粒度（同一組功能拆成幾個工具，例如一個大工具包辦所有查詢，或拆成四個各做一件事）、名稱、描述、參數 schema 會直接影響模型選對工具的機率，要用測試題量化比較，不能憑感覺。
- **唯讀的 `run_sql` 要靠資料庫權限把關**：只檢查 SQL 字串擋不住所有寫入，要用唯讀角色、唯讀交易、`statement_timeout` 和筆數上限多層防護。
- **ETL 的冪等與增量**：NVD 有速率限制，每次全量重抓不實際；記錄上次成功的時間點、只抓變更、用 upsert 寫入，重跑幾次結果都一樣。

### 開始前

所有指令都在 repo 根目錄執行。

1. `uv sync`：這個階段新增 `pytest`
2. `docker compose up -d` 起 PostgreSQL，並確認階段 1 的 `uv run scripts/etl.py` 跑過，資料庫裡有資料

### 步驟 1：PostgreSQL 與 schema

這一步要理解資料庫怎麼替 agent 把關。`run_sql` 執行的是模型寫的 SQL，所以 agent 用獨立的唯讀角色連線，權限、唯讀交易、逾時都設在資料庫這層，程式的檢查漏了也不會出事；ETL 用另一個可寫的角色。

- 讀 [`docker-compose.yml`](../docker-compose.yml)：PostgreSQL 16，只綁 `127.0.0.1:5432`，資料放在 `pgdata` volume
- 讀 [`db/init.sh`](../db/init.sh)：volume 是空的時候自動執行
  - 兩個角色：`vuln_etl` 擁有資料表；`vuln_agent` 只能 SELECT 四張資料表，連線預設唯讀交易、`statement_timeout` 5 秒，看不到 `etl_runs`
  - `cve_product` 把一個 CVE 對多個 CPE 拆成一對多，`vendor`、`product` 取自 CPE 字串，`search_vulns` 用它比對產品
  - `kev` 不設外鍵到 `cve`：KEV 收的 CVE 可能很舊，不一定在 `cve` 的時間範圍
  - `etl_runs` 的 `watermark` 是增量更新的起點
- 讀 [`src/vuln_agent/db.py`](../src/vuln_agent/db.py)：`connect("etl")`、`connect("agent")` 分別用兩個角色連線
- 改了 `init.sh` 要重建時，`docker compose down -v` 刪掉 volume 再 `docker compose up -d`，資料要重新跑 ETL

### 步驟 2：ETL：增量、重試、速率限制

這一步要理解資料怎麼自己保持在最新狀態。重點是冪等：同一段時間抓兩次、跑到一半被中斷再重跑，結果都一樣。做法是每個來源的寫入和「標成成功」放在同一個交易，失敗就整批不寫入；下次從上次成功的時間點重抓，用 upsert 寫入，重複的資料只會覆蓋不會多一筆。

- 讀 [`scripts/etl.py`](../scripts/etl.py)：
  - `run()`：先寫一筆 `running` 並提交，再執行來源的載入函式；成功就在同一個交易裡標成 `success`，失敗就 rollback、標成 `failed` 並記下錯誤。被 kill 時那一列會停在 `running`
  - `load_nvd()`：第一次抓最近 30 天（`nvd.py` 的 `NVD_DAYS`）發布的 CVE；之後從上次成功的 `watermark` 往前一小時開始，用 `lastModStartDate`、`lastModEndDate` 只抓這段時間修改過的，超過 120 天就切段。NVD 每小時整批寫入一次變更，查詢當下可能有一批還沒寫完，多抓的一小時由 upsert 覆蓋，不會重複。增量會抓到修改過的舊 CVE，所以 `cve` 表會慢慢長大。每次也用 `hasKev` 把 KEV 收錄的 CVE 整批再抓一次，確保 `kev` 的每一筆都對得到 `cve`
  - `fetch_nvd()`：分頁抓，每頁 2,000 筆，每個請求前等 `NVD_SLEEP` 秒（速率限制）
  - `upsert_cves()`：`INSERT ... ON CONFLICT DO UPDATE` 寫入 `cve`，受影響產品整組換掉；被撤銷（Rejected）的 CVE 從資料庫刪掉
  - `load_kev()`：整份 upsert，CISA 從清單移除的也一起刪掉
  - `load_epss()`：幾十萬筆，先用 `COPY` 灌進暫存表再一次合併，比逐筆 INSERT 快很多
- 讀 [`src/vuln_agent/nvd.py`](../src/vuln_agent/nvd.py)：`nvd_get()` 遇到 403、429、503 或逾時等 30 秒（一個速率限制窗口）再試，5 次都失敗就丟例外，`run()` 把這次標成 `failed`
- 階段 1 已經跑過第一次全量，再執行 `uv run scripts/etl.py` 就是增量：NVD 只抓上次之後修改過的，一天份大約幾千筆，加上每次重抓的 KEV 一千多筆，幾分鐘內跑完
- 中斷實驗：再跑一次 `uv run scripts/etl.py nvd`，跑到一半按 Ctrl+C，再重跑一次，確認：
  - 被中斷的那一列停在 `running`，下一次從上一個成功的 `watermark` 接續
  - `SELECT count(*), count(DISTINCT cve_id) FROM cve` 兩個數字一樣
- 排程用本機 cron，因為資料庫在本機，GitHub Actions 的雲端 runner 連不到。`crontab -e` 加一行（路徑換成自己的；cron 的 PATH 很短，`uv` 要寫完整路徑，用 `which uv` 查）：

  ```text
  0 7 * * * cd /path/to/vuln-agent && /path/to/uv run scripts/etl.py >> data/etl.log 2>&1
  ```

- 記下：四張表各幾筆、增量一次抓了幾筆、花多久（`SELECT * FROM etl_runs ORDER BY id DESC LIMIT 5`）

### 步驟 3：四個工具

這一步要理解工具怎麼設計。每個工具有三個部分：給模型看的描述、給模型看也負責驗證的參數 schema、實際查詢的函式。描述寫清楚「何時用、何時不用」，參數錯誤時回一段模型看得懂的錯誤，模型才選得對、改得回來。

- 讀 [`src/vuln_agent/tools.py`](../src/vuln_agent/tools.py)：
  - 參數 model（`CveLookupArgs` 等）：同一個 Pydantic model 產生 `input_schema`，也驗證模型傳來的參數；`extra="forbid"` 讓模型多傳不存在的參數時直接報錯
  - `cve_lookup()`：從輸入的編號 LEFT JOIN 三張表，只有 KEV 或 EPSS 有資料的舊 CVE 也查得到；都沒有就回 `found: false` 與原因
  - `search_vulns()`：參數化 SQL，沒給的條件傳 NULL；用 `count(*) OVER ()` 回傳截斷前的總筆數，模型才知道結果不完整，問「有幾個」也直接用 `total`
  - `prioritize()`：依 KEV → EPSS → CVSS 排序，`reason()` 用規則產生排序理由
  - `run_sql()`：三層防護，字串檢查、包成子查詢加 LIMIT、資料庫角色；每種錯誤回不同的訊息，告訴模型下一步怎麼改
  - `TOOLS`：四個工具的描述；`schemas()` 轉成 API 的 `tools` 參數；`call_tool()` 驗證參數後執行，錯誤一律包成 `ToolError`
- 讀 [`tests/test_tools.py`](../tests/test_tools.py)，跑 `uv run pytest tests/test_tools.py`：不經過 LLM 直接測，`run_sql` 那組送 `DELETE`、多條語句、`WITH ... DELETE`、沒授權的表、`pg_sleep(10)`，確認都被擋下而且資料還在

### 步驟 4：手寫 tool-use loop

這一步要理解 agent 的核心：一個迴圈。每一輪把對話和工具清單送給模型，`stop_reason` 是 `tool_use` 就執行模型要的工具，把結果包成 `tool_result` 接在對話後面再送一次；不是 `tool_use` 就代表模型答完了。其餘的程式都在處理迴圈出錯和停不下來的情況。

- 讀 [`src/vuln_agent/agent.py`](../src/vuln_agent/agent.py)：
  - `SYSTEM`：保留階段 1 的規則，只能提工具結果裡的 CVE、拒絕 exploit 與範圍外問題，另外要求依錯誤訊息修正參數
  - `run_agent()`：generator，每發生一件事就 yield 一個事件（`text`、`tool_use`、`tool_result`、`done`），串流和非串流共用。工具丟任何例外都包成 `is_error` 的 tool result 送回模型；停止條件是模型答完、`max_steps`（預設 8）、`timeout`（預設 120 秒），單一工具的逾時由資料庫的 `statement_timeout` 負責。每一步寫一行 JSON log（工具、參數、耗時、tokens、花費），結束時再寫一行總計
  - `ask()`：跑完整個迴圈，收成一個結果
- 讀 [`src/vuln_agent/agent_api.py`](../src/vuln_agent/agent_api.py)：`/ask` 回傳回答與每次工具呼叫，`/ask/stream` 用 SSE 送出每個事件
- 讀 [`tests/test_agent.py`](../tests/test_agent.py)：用假的 client 測「參數錯誤變成 error result、模型接著回答」和「撞到最大步數會停」，不花錢
- 用 `uv run uvicorn vuln_agent.agent_api:app --reload` 啟動，另開一個終端機試：

  ```bash
  curl -s localhost:8000/ask -H 'content-type: application/json' \
    -d '{"question": "最近 30 天影響 nginx、CVSS 7 以上而且已經被利用的漏洞？"}' | jq
  curl -sN localhost:8000/ask/stream -H 'content-type: application/json' \
    -d '{"question": "KEV 裡哪個廠商的漏洞最多？"}'
  ```

- 觀察：
  - 統計類問題模型會改用 `run_sql`，看它寫的 SQL 對不對
  - 問「CVSS 15 分以上的漏洞」，可能出現兩種結果：模型從工具 schema 的 `"maximum": 10`（`SearchVulnsArgs` 的 `le=10`）看出條件不合理，不呼叫工具直接說明分數範圍；或是傳 `min_cvss: 15`，收到 `call_tool()` 的錯誤訊息後修正參數或說明。用 `/ask` 看 `tool_calls` 是空的，還是有一筆 `is_error: true`
  - 問「log4shell 現在 EPSS 多少」，看模型是先用工具查出 CVE，還是憑記憶直接 `cve_lookup`
  - 啟動服務的終端機裡，每一步的 log 與總計

### 步驟 5：工具設計比較

這一步要理解工具設計的三個面向各自影響什麼：粒度決定模型會不會傳錯參數，描述決定模型要花幾步摸清楚資料，命名在描述與參數 schema 都寫清楚時幾乎沒有影響。五種工具組是控制變因的設計，每兩組之間只差其中一項，兩兩比較才能把差異歸因到單一面向。

- 讀 [`evals/seed.jsonl`](../evals/seed.jsonl)：20 題，每題的 `expected_tools` 是可以接受的工具；空的代表應該拒絕、不呼叫工具。後 10 題加入排序、統計、payload 這類題目，排序與統計題不在 `QueryIntent` 的範圍，所以沒有 `expected`
- 讀 [`evals/toolsets.py`](../evals/toolsets.py)：
  - A：只有一個 `query_vulns(intent, ...)`，所有參數攤在同一個 schema
  - B：四個小工具，描述只有一行（參數 schema 跟 C 一樣）
  - C：作品用的 `TOOLS`，描述寫清楚何時用、何時不用，加上參數範例
  - D、E：把 B、C 的工具名稱換成沒有意義的 `tool_1` 到 `tool_4`，其他不變。`renamed()` 同時換掉描述裡提到的其他工具名稱，以及參數類別的名稱（schema 的 `title` 是類別名稱，例如 `SearchVulnsArgs`，不換會透露原本的工具名稱）
  - `tool_names()`：把 A 的 `query_vulns` 依 `intent`、D 和 E 的 `tool_N` 換回對應的工具名稱，五組才能用同一份 `expected_tools` 評分
- 讀 [`evals/run_agent.py`](../evals/run_agent.py)：`check()` 做三項斷言（工具選擇、沒撞到步數上限、回答裡的 CVE 都出自工具結果）
  - 摘要表的「錯誤呼叫」是回傳 `is_error` 的工具呼叫總數，只計數、不算沒過：模型收到錯誤訊息後修正參數是合理行為，但每次都多花一步。`tools` 斷言只看呼叫過哪些工具，選錯再改對也會過，要靠這一欄看出差別
- 執行 `uv run evals/run_agent.py --toolsets A B C D E --runs 2`，會呼叫付費 API（20 題 × 5 組 × 2 次）。終端機印出摘要表與沒過的題目，逐題結果存在 `evals/results/`

重點：

- **粒度（A 對 B）：參數限制要能寫進 schema**
  - A 的錯誤呼叫明顯比 B 多，B 通常是 0
  - 攤平成一個大工具後，表達不了「這個參數屬於哪個 `intent`」「用這個 `intent` 時哪些參數必填」：A 會對 `prioritize` 傳搜尋條件、對 `cve_lookup` 傳 `cve_ids`，靠錯誤訊息才改對
  - 拆成小工具，每個工具的必填、範圍、格式都在自己的 schema 裡，模型呼叫前就看得到
  - A 傳出超過上限的 `limit`，是 `QueryVulnsArgs` 少寫了限制，這類限制攤平的 schema 也寫得進去
- **描述（B 對 C）：寫模型自己推不出來的資訊**
  - 統計題（`expected_tools` 只有 `run_sql`）的步數是 A > B > C
  - C 的 `run_sql` 描述列出資料表，第一步就寫出正確的 SQL
  - B 從參數說明知道是 PostgreSQL，先查 `information_schema` 再寫
  - A 沒有任何資料庫資訊，直接猜表名，猜錯再去查
  - C 的描述比較長，每一步的 tokens 比較多，但步數少，總花費和 B 差距不大
- **命名（B 對 D、C 對 E）：描述與參數 schema 寫清楚時，名稱幾乎不影響選擇**
  - 換成 `tool_1` 到 `tool_4` 後，錯誤呼叫仍是 0，平均步數的差距遠小於粒度、描述造成的差距
  - 多出的步數來自個別題目多查一次，同樣的行為在沒改名的組也會出現
  - 名稱的影響出現在缺資訊的時候：A 猜的表名 `vulns`、條件 `in_kev = 1`，和工具名稱 `query_vulns`、參數 `in_kev` 對得上，模型拿名稱去推測工具以外的東西
- **錯誤訊息：寫出合法值或正確的參數名稱**
  - A 的錯誤呼叫都會被下一步修正，但修正的成本不同
  - `limit：Input should be less than or equal to 50（收到 1000）`、`cve_ids：Field required`：訊息裡有合法值或缺的參數，下一步就改對，或改用別的工具
  - `relation "vulns" does not exist`：訊息只說表不存在，沒說有哪些表，模型下一步都先查 `information_schema`，多花兩步才寫出正確的 SQL
  - `call_tool()` 把 Pydantic 的驗證錯誤整理成「哪個參數、哪裡錯、收到什麼」，就是讓模型一步修好
- **評測：沒過的題目先判斷是模型錯還是標準窄**
  - 「最近 14 天被利用的 XSS」：`search_vulns` 的 `days` 過濾的是發布日期，模型會再用 `run_sql` 依加入 KEV 的日期（`date_added`）查一次。這種解讀更貼近「最近被利用」，所以 `expected_tools` 列了 `run_sql`
  - 「EPSS 超過 0.9 而且 CVSS 9 以上」：有時會多用 `run_sql` 分組計數，但 `search_vulns` 的 `total` 已經回答了數量，這一步是多餘的，而且時有時無，維持判為沒過

用這兩條指令對照自己的結果：

```bash
f=$(ls -t evals/results/*.jsonl | head -1)
# 每次出錯的工具呼叫（看 A 的錯誤屬於哪一類）
jq -c '.toolset as $t | .tool_calls[] | select(.is_error) | {toolset: $t, input, result: .result[:60]}' $f
# 統計題在各組的第一步（看 A、B、C 分別怎麼開始）
jq -c 'select(.question == "KEV 裡的漏洞，平均 EPSS 是多少？") | {toolset, run, first: .tool_calls[0].input}' $f
```

- 記下：五組的比較表（含錯誤呼叫數），步驟 7 收尾會用到

### 步驟 6：最小評測

這一步要理解評測怎麼變成每次改動後都跑一次的回歸測試。先只用程式斷言，不用 LLM 當評審；完整的 error analysis、LLM-as-judge 和大型評測集留在階段 6。之後每加一個 harness 功能，都先跑這組測試看數字有沒有變。

- 三組不呼叫 LLM 的測試，`uv run pytest` 一次跑完：
  - [`tests/test_tools.py`](../tests/test_tools.py)：四個工具
  - [`tests/test_data.py`](../tests/test_data.py)：ETL 資料斷言，各表有資料、`cve_id` 格式正確、KEV 的 CVE 幾乎都找得到 `cve` 資料、分數在合法範圍
  - [`tests/test_agent.py`](../tests/test_agent.py)：loop 的停止條件與錯誤處理
- 兩組呼叫 LLM 的評測：
  - 結構化擷取：`uv run evals/run_seed.py`（階段 1 的腳本），`QueryIntent` 逐欄比對 `expected`
  - Agent 斷言：`uv run evals/run_agent.py`，就是步驟 5 用 C 跑的那組
- 之後每碰到一個答錯的問題，就加進 `seed.jsonl`

### 步驟 7：收尾

- 記下這個階段的架構（ETL → PostgreSQL → 工具 → agent loop → FastAPI）、工具清單與工具設計比較表，之後階段 3 會在這個 loop 上加 harness
- （選做）寫一篇文章：「不用框架手寫 agent loop：用 NVD / KEV / EPSS 練 tool use、工具設計與 ETL 增量更新」

**完成標準**：`docker compose up` 能起 PostgreSQL，ETL 排程每天更新，NVD 增量更新中斷後重跑不會重複，`etl_runs` 有紀錄；`uv run pytest` 全過，`run_sql` 擋得住寫入、多條語句和長時間查詢；`/ask` 走 agent loop，log 看得到每一步的工具、參數、tokens 與花費，碰到最大步數或逾時會正常結束；有五種工具組的比較表（選擇正確率、錯誤呼叫數、步數、花費），能說明粒度、描述、命名各自影響哪個指標、為什麼選定的那一組比較好，以及錯誤訊息怎麼寫才能讓模型自己修正。
