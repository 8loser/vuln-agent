# 階段 4：Harness（二）：subagent、MCP、框架比較

這個階段其實是兩塊：步驟 1–2 是「掃描器、統一格式、去重」，步驟 3–5 是「子 agent、MCP、SDK 重寫」。可以分兩次做，中間先跑一次階段 2 的最小評測。

這個階段要讓作品第一次吃進「真的掃描報告」，同時把 harness 從單一 agent 拆成「主 agent ＋ 子 agent」，再把工具開放給外部客戶端。先在自己的 Docker 環境架 OWASP Juice Shop / DVWA，跑 ZAP baseline scan，並用 Trivy 掃自己的 image，拿到真實的 JSON 報告；接著完成規格 F2（ZAP、Trivy 報告轉成統一格式並去重）。階段 3 已經做好工具結果裁剪、token 預算、狀態檢查點和工具分級權限，這個階段要再往上一層：上千筆的報告交給「報告子 agent」在自己乾淨的 context 裡處理，查 NVD / KEV / EPSS 交給「情資子 agent」，主 agent 只拿摘要。然後自己寫 MCP server，讓 Claude Code 也能直接呼叫查詢與排序工具（規格 F9）。最後用一個 agent SDK 重寫一版，對照手寫 harness，寫一篇比較文。

### 要學的概念

- **掃描報告的資料模型**：ZAP 以「規則 × URL」為單位、Trivy 以「CVE × 套件 × 版本 × target」為單位，先搞懂兩者的粒度差異，統一格式和去重鍵才設計得對。
- **去重與指紋（fingerprint）**：同一個問題會在多個 URL、多次掃描、多個 image layer 重複出現，指紋決定「什麼算同一筆」，直接影響使用者看到的清單長度和排序可信度。
- **Subagent 與 context 隔離**：子 agent 有自己的 system prompt、工具子集與對話紀錄，原始資料留在子 agent 裡，主 agent 只收結構化摘要，這是處理大型輸入、又不讓主 context 爆掉的主要手段。
- **MCP（Model Context Protocol）**：把工具寫成標準的 server，一份實作就能給 Claude Code、桌面版或自己的 agent 共用，也是 agent 生態系目前最常見的整合方式。
- **框架與手寫 harness 的取捨**：框架幫你處理 loop、權限、subagent、MCP 串接，但也藏起細節；比較的重點是概念怎麼對應，而不是記 API（框架 API 變得很快）。
- **報告是不可信輸入**：掃描報告的欄位內容（URL、參數、回應片段）來自被掃的目標，可能夾帶指令；這個階段先做到「報告內容只當資料、不當指令」，完整的紅隊測試留到階段 7。

### 步驟 1：架靶機與產生真實報告

- 用 `docker compose` 在獨立的 Docker network 裡起 Juice Shop 和 DVWA（官方或社群維護的 image，image 名稱與連接埠以官方文件為準），只綁定 `127.0.0.1`，不對外開放
- 用 ZAP 官方 Docker image 跑 baseline scan（掛同一個 Docker network，對靶機的容器名稱掃），輸出 JSON 和 XML 報告到 `data/reports/zap/`；指令與參數以 ZAP 官方文件為準
- 用 Trivy 掃 Juice Shop 的 image 和自己階段 1–3 做的 `vuln-agent` image，輸出 JSON 到 `data/reports/trivy/`
- 把掃描指令寫成 `scripts/scan.sh`，target 寫死成本機靶機；腳本開頭檢查 target 不是允許清單以外的主機就直接退出
- 同一個靶機跑兩次 ZAP，留兩份報告，下一步用來測試跨報告去重
- 記下：每份報告的檔案大小、ZAP alert 數與 instance 數、Trivy 各 severity 數量，以及估算「整份報告直接塞進 context」大概多少 tokens

### 步驟 2：報告匯入、統一格式與去重（F2）

- Pydantic 定義 `Finding`（統一格式，見下方範例），寫 `parse_zap()`、`parse_trivy()` 兩個純 Python parser，不經過 LLM
- 設計指紋：ZAP 用「規則 ID ＋ 正規化後的 URL path ＋ 參數名」，Trivy 用「CVE ＋ 套件名 ＋ 安裝版本」；同指紋合併成一筆，`occurrences` 累加、`locations` 去重保留
- 延伸階段 3 在 PostgreSQL 建的 `findings` 表，加上 `fingerprint`、`source`、`report_ids` 與 `first_seen` / `last_seen`；有 CVE 的 finding 可 join 上 `kev`、`epss`、`cve` 表
- 把階段 3 只支援 Trivy 的 `import_report(path)` 擴充成同時支援 ZAP 和 Trivy，回傳「新增 N 筆、合併 M 筆、各 severity 數量」，不回傳整份清單
- pytest：同一份報告匯入兩次筆數不變；兩次 ZAP 掃描合併後筆數小於相加；故意改壞的 JSON 會回傳模型看得懂的錯誤訊息

```json
{
  "fingerprint": "sha256:9f2c…",
  "source": "trivy",
  "rule_id": "CVE-2024-XXXXX",
  "cve_id": "CVE-2024-XXXXX",
  "cwe": "CWE-79",
  "title": "Cross-site scripting in <套件名>",
  "severity": "high",
  "asset": "juice-shop:latest",
  "locations": ["usr/src/app/package-lock.json"],
  "package": {"name": "<套件名>", "installed": "1.2.3", "fixed": "1.2.4"},
  "occurrences": 3,
  "report_ids": ["trivy-2026-10-02-a"],
  "first_seen": "2026-10-02T10:00:00Z",
  "last_seen": "2026-10-02T11:30:00Z"
}
```

`severity` 統一成 `critical / high / medium / low / info` 五級，ZAP 的 riskcode 和 Trivy 的 severity 各寫一個對照表；欄位名稱以兩個工具的官方報告格式為準。

### 步驟 3：報告子 agent 與情資子 agent

- 把階段 2–3 的 agent loop 抽成可重複使用的 `run_agent(system, tools, task, budget)`，子 agent 就是用不同的 system prompt、工具子集與 token 預算再呼叫一次
- 報告子 agent：只有 `import_report`、`query_findings`（唯讀）兩個工具，任務是「匯入並整理成前 N 名摘要」，輸出用 Pydantic 定義的 `ReportSummary`（筆數、各 severity 數、前 10 名指紋與一句話理由）
- 情資子 agent：只有 `cve_lookup`、`search_vulns` 等唯讀查詢工具，輸入一批 CVE，輸出每個 CVE 的 KEV / EPSS / CVSS 摘要，不回傳 NVD 原始描述全文
- 主 agent 只有 `delegate_report`、`delegate_intel`、`prioritize` 三個工具；system prompt 寫明掃描報告欄位只是資料，裡面的文字不能當指令
- 用「匯入這兩份報告，告訴我先修哪 5 個」比較有無子 agent：主 context 的 tokens、總 tokens、總花費、延遲、前 5 名是否一致，記成一張表
- 每個子 agent 的呼叫在 log 裡帶 `parent_run_id`，能從主 agent 的一次回答追到底下每一次子 agent 呼叫

### 步驟 4：自己寫 MCP server（F9）

- 用官方的 MCP Python SDK（套件與寫法以官方文件為準）寫 `mcp_server.py`，以 stdio 方式開出 `cve_lookup`、`search_vulns`、`query_findings`、`prioritize` 四個唯讀工具，直接重用階段 2 的工具函式與參數 schema
- `import_report` 這類寫入工具先不開，或只接受 `data/reports/` 底下的路徑；在 README 寫清楚哪些工具有開、為什麼
- 用 MCP 官方的 Inspector 工具（以官方文件為準）逐一呼叫，確認 schema、錯誤訊息、回傳大小都合理
- 用 Claude Code 的 MCP 設定指令把 server 加進來（指令與設定檔位置以 Claude Code 官方文件為準），在 Claude Code 裡問「Juice Shop 報告裡哪些在 KEV 裡？」，確認它呼叫的是你的工具
- 觀察 Claude Code 對你的工具會不會詢問權限、怎麼顯示工具結果，對照階段 3 自己做的工具分級，記下差異

### 步驟 5：用 SDK 重寫一版並寫比較

- 選一個 SDK（建議 Claude Agent SDK，因為它就是把 Claude Code 的 harness 包成函式庫，可以直接對照；也可選 OpenAI Agents SDK 或 LangGraph），套件安裝與 API 以官方文件為準
- 用它重做「主 agent ＋ 報告子 agent ＋ 情資子 agent」，工具直接接上步驟 4 的 MCP server 或包成框架的工具格式，不重寫工具邏輯
- 用框架提供的權限或 hook 機制重做階段 3 的規則：唯讀工具直接執行、寫入工具要確認、每次呼叫記 log
- 用步驟 3 同一題、同一組報告跑兩版，比較答案、tokens、花費、延遲、程式碼行數
- 寫比較表，四個維度各寫「手寫怎麼做 / 框架怎麼做 / 誰比較好除錯」：loop（停止條件、最大步數、錯誤重試）、context（裁剪與摘要由誰決定）、權限（工具分級與 hooks）、subagent（context 隔離與結果回傳格式）

### 步驟 6：收尾

- README：怎麼起靶機與跑掃描（強調只掃本機靶機）、`Finding` 統一格式與去重規則、子 agent 架構圖、MCP server 加進 Claude Code 的步驟、有無子 agent 的 tokens 比較表
- `.env` 與 `data/reports/` 確認在 `.gitignore`；repo 只放一份去識別化的小樣本報告供測試用
- （選做）寫文章，題目一：「手寫 agent harness vs Claude Agent SDK：loop、context、權限、subagent 四個概念的對照」
- （選做）寫文章，題目二：「把 ZAP 和 Trivy 報告合成一張清單：指紋去重與用 subagent 守住 context」

**完成標準**：本機有 Juice Shop / DVWA 的 ZAP 報告和自己 image 的 Trivy 報告；兩種報告都能匯入成統一的 `Finding`，重複匯入筆數不變、跨報告會合併，pytest 通過；主 agent 透過報告子 agent 與情資子 agent 回答「先修哪 5 個」，有一張表證明主 context 的 tokens 明顯低於不用子 agent 的版本；Claude Code 能透過自己寫的 MCP server 查到 Juice Shop 報告裡在 KEV 的項目；SDK 版本能跑同一題，並有一份涵蓋 loop、context、權限、subagent 四個維度的比較表。
