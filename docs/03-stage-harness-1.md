# 階段 3：Harness（一）：context、狀態、權限

> 實驗 notebook：[`notebooks/03_context_budget.ipynb`](../notebooks/03_context_budget.ipynb)，步驟 1、2 的量測與比較。

這個階段要把階段 2 的手寫 agent loop 補成一個像樣的 harness，也就是替作品加上「Harness 本體」。階段 2 的 loop 能選工具、執行、回傳結果，但工具結果會原封不動塞回 context，程式一中斷就得從頭來，每個工具也都直接執行。這個階段補三件事：一是 context 管理，上千筆的 Trivy 報告要先裁剪、摘要，再放進有 token 預算的 context；二是把對話與 agent 狀態存進階段 2 的 PostgreSQL，中斷後從上一步續跑；三是權限分級和執行前後的 hooks，唯讀工具直接跑，寫入或對外動作要人工確認，每次呼叫都記 log、檢查參數。做完後可以拿 Claude Code 對照，看它的 hooks 和 permissions 怎麼解決同樣的問題。階段 4 的子 agent 和 MCP server 都會沿用這一層。

### 要學的概念

- **Context 是有限又要花錢的資源**：每一輪都會把整段歷史重送一次，工具結果越長，成本和延遲越高，答案品質也可能變差，模型容易漏看中間的內容。
- **工具結果要先裁剪再回給模型**：回摘要、前 N 筆和分頁游標，完整資料存在資料庫，模型需要時再查。這是 harness 的責任，不能指望模型自己忽略。
- **Token 預算與壓縮**：替單一工具結果和整段對話各設上限，超過時把舊的輪次壓成摘要，並決定哪些內容不能丟（使用者原始問題、已確認的結論）。
- **檢查點讓 agent 可以續跑**：每一步之後把狀態寫進資料庫，程式掛掉、API 逾時或等人工確認時，都能從上一步接著做，不用重花 token。
- **權限分級**：依副作用把工具分成唯讀、寫入、對外三級，分別對應允許、詢問、拒絕。這是 agent 能放心交給別人用的前提，也是階段 7 防護的基礎。
- **Hooks 讓規則寫在模型之外**：在工具執行前後插入確定性的程式碼，負責記 log、檢查參數、擋掉危險操作。prompt 寫「不要做」不保證有效，hook 擋下來的就一定擋得住。

### 步驟 1：準備測試報告與量出基準

- 用 Trivy 掃自己的 Docker image，輸出 JSON：例如 `trivy image --format json --output data/reports/trivy-myapp.json <你的 image>`。想要多一點結果，可以用舊版 base image 另 build 一個練習用 image。只掃自己的 image，`data/reports/` 加進 `.gitignore`（參數以 Trivy 官方文件為準）
- 寫小腳本統計報告內容：各 severity 筆數、不重複 CVE 數、有 `FixedVersion` 的比例，再算一下整份 JSON 有多少 tokens
- 新增工具 `read_scan_report(path)`，先寫成最天真的版本，直接回傳整份 JSON
- 準備 5 題報告相關問題（例如「有幾個 Critical？」「哪些在 KEV 裡、要先修？」「openssl 相關的有哪些、修到哪一版？」），寫進 `evals/report.jsonl`，附上用 SQL 或腳本算出的標準答案
- 用天真版跑這 5 題，記錄每題的 input tokens、花費、延遲、答對與否；如果超過模型的 context 上限或直接報錯，也記下來

### 步驟 2：Context 管理：裁剪、摘要、token 預算

- 改寫匯入流程：`import_report` 把報告解析成扁平的列（CVE、套件、目前版本、修補版本、severity）存進 PostgreSQL 的 `findings` 表，只回傳一個 `report_id` 和統計摘要（各等級筆數、前 10 筆）
- 新增 `query_findings(report_id, severity, package, in_kev, limit, cursor)`，`limit` 有上限，回傳結果附 `total` 和下一頁的 `cursor`，讓模型知道還有多少筆沒看
- 在 loop 裡加一層通用的工具結果裁剪：任何工具結果超過 N tokens 就截斷，並在結果中寫明「已截斷，共 X 筆，請用篩選條件縮小範圍」
- 加對話層級的 token 預算：每輪呼叫前估算 context 大小，超過門檻時把較早的工具結果換成一行摘要，保留使用者原始問題和已確認的結論
- 實驗：天真版、裁剪版、裁剪加壓縮版各跑一次 5 題，做一張表比較每題 tokens、花費、延遲、答對數；另外刻意把對話拉長到 20 輪，觀察答案品質何時開始下降

### 步驟 3：狀態與檢查點

- 在 PostgreSQL 建 `sessions`（狀態：running / waiting\_approval / done / failed）、`messages`（每則訊息依序存，含工具呼叫與結果）、`steps`（第幾步、呼叫哪個工具、參數、結果摘要、tokens、耗時）
- loop 每完成一步就寫入資料庫，把 commit 放在「呼叫模型」和「執行工具」之間，記清楚哪一步已經做完
- `resume(session_id)`：從資料庫重建 messages，從最後一個完成的步驟接著跑；已執行完的工具不要重跑
- 測試：在 agent 執行到一半時用 Ctrl+C 或 `docker kill` 中斷，再 resume，確認結果正確，並比較從頭跑和續跑花的 tokens
- 想清楚並寫進 README：工具執行到一半就中斷時怎麼辦？唯讀工具可以安全重跑，寫入工具要有 idempotency key，才不會寫兩次

### 步驟 4：權限分級與人工確認

- 替每個工具標上等級：`read`（`cve_lookup`、`search_vulns`、`query_findings`、`run_sql`）、`write`（新增一個 `save_triage_note`，把排序結論寫進資料庫）、`external`（新增一個 `create_ticket_draft`，這個階段只寫進本機檔案或資料表，不真的呼叫 GitHub）
- 寫權限設定檔，格式仿照 Claude Code 的 allow / ask / deny：`read` 預設 allow，`write` 和 `external` 預設 ask，可以針對單一工具覆寫
- 遇到 ask 時，把 session 狀態改成 `waiting_approval` 並存檔，CLI 顯示工具名稱和參數讓你按 y / n；拒絕的話，把「使用者拒絕，原因：…」當成工具結果回給模型，讓它換個做法
- 測試：等待確認時直接關掉程式，隔天 resume 還能接著問；確認一次「被拒絕後模型不會換個工具繞過去做同一件事」

### 步驟 5：執行前後 hooks，並與 Claude Code 對照

- 在執行工具的地方加 `pre_tool_use` 和 `post_tool_use` 兩組 hook，hook 可以放行、修改參數或擋下，擋下時要附原因
- 實作 3 個 hook：每次呼叫都寫一行 JSONL log（session、工具、參數、耗時、tokens、結果大小）；`run_sql` 只允許單一 `SELECT`，沒有 `LIMIT` 就自動補上；路徑類參數只能在 `data/reports/` 底下
- 寫 3 個「應該被擋」的測試案例（例如要求 `DROP TABLE`、讀 `../.env`、一次撈十萬筆），確認都被 hook 擋下，log 裡也有紀錄
- 讀 Claude Code 的 hooks 與 permissions 官方文件（PreToolUse / PostToolUse、settings.json 裡的 allow / ask / deny，細節以官方文件為準），列一張表對照你的實作：哪些概念一樣，它多做了什麼，你的哪裡比較簡陋

下面是步驟 4、5 的核心骨架，權限檢查和 hooks 都包在同一個執行函式裡：

```python
def run_tool(session, name: str, args: dict):
    tool = TOOLS[name]
    for hook in PRE_HOOKS:                      # 檢查參數、補 LIMIT、擋危險操作
        verdict = hook(session, tool, args)
        if verdict.block:
            return error_result(f"被 hook 擋下：{verdict.reason}")
        args = verdict.args or args
    decision = policy.decide(tool.level, name)  # allow / ask / deny
    if decision == "deny":
        return error_result("此工具不允許使用")
    if decision == "ask" and not session.approved(name, args):
        session.set_status("waiting_approval", pending=(name, args))
        raise PauseForApproval                  # 存檔後停下，確認後由 resume 接著跑
    result = tool.fn(**args)
    result = trim_to_budget(result, max_tokens=2000)
    for hook in POST_HOOKS:                     # 記 log、統計 tokens 與耗時
        hook(session, tool, args, result)
    return result
```

### 步驟 6：收尾

- README：harness 架構圖（loop → 權限 → hooks → 工具 → 裁剪 → 檢查點）、三種 context 策略的比較表、中斷續跑的示範步驟、與 Claude Code 的對照表
- （選做）寫一篇文章：「自己蓋 agent harness：用一份上千筆的 Trivy 報告練 context 預算、檢查點與權限 hooks」

**完成標準**：自己 Docker image 的 Trivy 報告能匯入資料庫，agent 只透過摘要和分頁查詢回答，5 題報告問題有標準答案，三種 context 策略有 tokens、花費、答對數的比較表；agent 執行到一半被中斷後，能從資料庫 resume，並且不重跑已完成的工具；`write` 和 `external` 工具一定會停下來等人工確認，等待期間關掉程式也能續跑；3 個危險案例都被 hook 擋下，JSONL log 記錄了每次工具呼叫；README 有和 Claude Code hooks / permissions 的對照表。
