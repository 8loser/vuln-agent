# 階段 1：LLM 基本功（約 7 小時）

這個階段的目標是直接用官方 SDK 呼叫 LLM，做出作品的第一塊「問題解析器」：把中文漏洞問題轉成結構化查詢意圖，再用寫死的 SQL 查小型漏洞資料庫回答。一步一步做，每做完一步把文件裡的方框打勾。

**做完後的樣子**：問 `/ask/stream`「最近 30 天影響 nginx、CVSS 7 以上而且已經被利用的漏洞？」

1. 模型把問題解析成查詢條件：產品 nginx、CVSS ≥ 7、在 KEV 裡、30 天內
2. 程式用寫死的 SQL 查 DuckDB，依 KEV → EPSS → CVSS 排好
3. 中文說明逐字串流出來，只提查到的 CVE；查不到就說查不到
4. 問「幫我寫 nginx 的 exploit」會被拒絕
5. log 記下這次用了多少 token、花了多少錢、各段幾秒
6. 10 題測試跑完，看得到大小兩個 Claude 模型各答對幾題

### 行前知識

這個階段的資料來自三個來源，各自回答一個問題：CVSS 看「多嚴重」，KEV 看「已經被利用了嗎」，EPSS 看「多可能被利用」。步驟 4 排序用 KEV → EPSS → CVSS，就是因為「已經發生」比「理論上嚴重」更急。

| 名詞 | 是什麼 | 這階段的作用 |
| --- | --- | --- |
| CVE | 公開漏洞的統一編號，格式 `CVE-年份-流水號`，由 MITRE 維護 | 三張表共用的 key；步驟 2 用 regex 驗證 `cve_id` 格式 |
| NVD | 美國 NIST 的漏洞資料庫，替每個 CVE 補上 CVSS 分數、CWE、CPE | `cve` 主表的來源；骨架的 TODO 1–3 就是從它的 JSON 取欄位 |
| CVSS | 0–10 的嚴重程度分數（v3.1），對應 LOW / MEDIUM / HIGH / CRITICAL | `min_cvss` 條件、排序最後一層 |
| CWE | 弱點類型分類，例如 CWE-89 是 SQL injection | TODO 2 的欄位；階段 5 的修補建議會用它對應 OWASP |
| CPE | 產品的標準命名字串，如 `cpe:2.3:a:f5:nginx:1.25.3:...` | TODO 3 的 `products` 欄位；問「影響 nginx」就是靠它比對 |
| CISA KEV | 美國 CISA 的清單，只收已確認被實際利用的 CVE，附修補期限 | `kev` 表、`in_kev` 條件、排序第一層 |
| EPSS | FIRST 每天發布的機率（0–1），預測 CVE 未來 30 天被利用的可能性 | `epss` 表、`min_epss` 條件、排序第二層 |
| DuckDB | 單檔的嵌入式 SQL 資料庫，不用架伺服器 | 放三張表；階段 2 換成 PostgreSQL |

### 本階段用到的檔案

整個學習路線共用同一個 repo，各資料夾的用途見總覽的「Repo 結構」。標「已提供」的是 repo 裡已經有的檔案，其餘由這個階段新增：

```text
vuln-agent/
├── .env                        # 步驟 1：API key，不進 git
├── src/vuln_agent/
│   ├── llm.py                  # 已提供：呼叫模型；步驟 1 補完 cost()，之後每個階段都用
│   ├── intent.py               # 步驟 2：QueryIntent 與問題解析
│   ├── queries.py              # 步驟 4：寫死的 SQL 樣板
│   └── api.py                  # 步驟 4：FastAPI /parse、/ask、/ask/stream
├── notebooks/
│   └── 01_llm_basics.ipynb     # 已提供：步驟 1–3 的實驗（token、effort、解析、幻覺）
├── scripts/
│   └── load_data.py            # 已提供骨架：步驟 3 補完 TODO，抓 NVD / KEV / EPSS 進 DuckDB
├── data/
│   └── vuln.duckdb             # 步驟 3 產生，不進 git
└── evals/
    ├── seed.jsonl              # 步驟 5：10 題
    └── run_seed.py             # 步驟 5：跑 10 題比較兩個模型
```

所有指令都在專案根目錄執行，例如 `uv run scripts/load_data.py`。套件在用到的那一步才裝。

### 步驟 1：環境與第一次呼叫（約 1.5 小時）

**學什麼**：直接用官方 SDK，看懂 messages、`usage`、`stop_reason`。每次呼叫都要算錢，成本主要看輸出長度與 thinking，同樣的意思中英文 token 數其實差不多。同一題每次回答不一定一樣；effort 調高會多花 token 與時間，結論不一定跟著改變。

實驗都在 [`notebooks/01_llm_basics.ipynb`](../notebooks/01_llm_basics.ipynb)：每項一個 Markdown 標題格加程式格，結果會存在 notebook 裡，之後打開不用重跑。少用 Run All，每次重跑都會重新呼叫 API 花錢。

- [ ] 裝好 [`uv`](https://docs.astral.sh/uv/)，在 repo 根目錄跑 `uv sync`；建 `.env` 放 `ANTHROPIC_API_KEY`（`.env` 已在 `.gitignore`）
  - `uv`：管理 Python 版本、虛擬環境和套件；專案用 `src/` 版面，notebook 和 API 都能 `import vuln_agent`
  - 已裝的套件：`anthropic`（官方 SDK）、`python-dotenv`（從 `.env` 讀 API key）、`jupyterlab`（開發用，跑 notebook）
  - 自己從零建的話，對應的指令是 `uv init --package vuln-agent`、`uv add anthropic python-dotenv`、`uv add --dev jupyterlab`
- [ ] 讀 [`src/vuln_agent/llm.py`](../src/vuln_agent/llm.py)：`ask()` 送訊息、`text()` 只取文字 block、`cost()` 留給你補完
- [ ] `uv run jupyter lab` 開 notebook，做 1.1 第一次呼叫
- [ ] 1.2 中英文 token 比較
- [ ] 1.3 穩定度與 effort
- [ ] 1.4 補完 `cost()`，換小模型比成本

模型名稱與價格以[官方模型列表](https://platform.claude.com/docs/en/about-claude/models/overview)與[定價頁](https://platform.claude.com/docs/en/about-claude/pricing)為準。

### 步驟 2：結構化輸出（約 1.5 小時）

**學什麼**：用 API 原生的 structured outputs（Python SDK 的 `client.messages.parse(output_format=...)`，底層是 `output_config.format` 給 JSON Schema；工具參數則加 `strict: true`），由 constrained decoding 保證輸出符合 schema，再用 Pydantic 驗證。以前常用「強制呼叫某個 tool 來拿 JSON」，但目前的 Sonnet 5.5、Opus 5.5 不接受強制 `tool_choice`（回 400），知道有這個舊做法就好。參數名稱以[官方文件](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)為準。這步還不需要資料庫。

- [ ] `uv add pydantic`；在 `src/vuln_agent/intent.py` 定義 `QueryIntent`，`cve_id` 用 regex 驗證格式；`intent` 先做 4 種：`cve_lookup`、`search`、`count`、`unsupported`（要求攻擊程式、範圍外問題）
- [ ] 寫 `parse(question)`：用 structured outputs 讓模型直接回傳 `QueryIntent`，Pydantic 驗證失敗就把錯誤丟回模型重試一次
- [ ] notebook 2.2：用 strict tool use 寫一版對照，比較兩者的失敗率與 token 數
- [ ] notebook 2.3：測刁鑽問題

### 步驟 3：準備漏洞資料（約 1 小時）

**學什麼**：模型會編出不存在的 CVE 編號，所以資料一定要從資料庫查。這步把真資料抓進來，再親眼看模型亂編。

- [ ] `uv add duckdb httpx`（`data/` 已在 `.gitignore`）；`NVD_API_KEY` 選用，有的話速率限制寬鬆很多
- [ ] 補完 [`scripts/load_data.py`](../scripts/load_data.py) 的 4 個 TODO，用 `uv run scripts/load_data.py` 把 NVD 最近 90 天、CISA KEV、EPSS 抓進 DuckDB。資料庫不用另外建：第一次執行時 `duckdb.connect("data/vuln.duckdb")` 會自動建檔，三張表由腳本裡的 `CREATE OR REPLACE TABLE` 建立

  提示：EPSS 有幾十萬筆，`executemany` 會慢，可以改用 DuckDB 的 `read_csv` 直接讀。
- [ ] notebook 3.1：手寫 3 條 SQL
- [ ] notebook 3.2：不給資料直接問模型，記下它編了幾個 CVE

### 步驟 4：串起來：SQL 樣板、FastAPI 與串流（約 2 小時）

**學什麼**：模型只負責產生查詢條件，SQL 由程式用參數化樣板組出來，不讓模型寫 SQL；SSE 串流讓使用者不用等整段回答。

- [ ] `uv add fastapi uvicorn`
- [ ] `src/vuln_agent/queries.py`：每種 intent 一個 SQL 樣板（參數化，不字串拼接），依 KEV → EPSS → CVSS 排序
- [ ] `src/vuln_agent/api.py`：`POST /parse` 回傳意圖，`POST /ask` 回傳查詢結果；用 `uv run uvicorn vuln_agent.api:app --reload` 啟動
- [ ] `POST /ask/stream` 用 SSE 串流中文說明，prompt 要求只能提查詢結果裡的 CVE
- [ ] 每個請求記 tokens、花費（用 `llm.py` 的 `cost()`）、各段延遲；處理逾時與 429 重試

### 步驟 5：測試與收尾（約 1 小時）

- [ ] 寫 10 題存成 `evals/seed.jsonl`，4 種 intent 都要有，加 2 到 3 題刁鑽的
- [ ] 寫 `evals/run_seed.py` 跑這 10 題，比較大小兩個 Claude 模型的命中數、平均延遲、總花費
- [ ] README：怎麼跑、API 範例、比較表
- [ ] （選做）寫一篇文章：「不用 LangChain 直接呼叫 LLM：用 NVD / KEV / EPSS 練 structured output 與串流」

**完成標準**：`/ask` 能拿到真實查詢結果、`/ask/stream` 逐字串流且提到的 CVE 都在表格裡、log 有 tokens 與延遲、有 10 題與比較表，並能解釋為什麼 CVE 資料不能讓模型憑記憶回答。
