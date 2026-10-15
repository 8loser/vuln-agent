# 階段 1：LLM 基本功

這個階段的目標是直接用官方 SDK 呼叫 LLM，做出作品的第一塊「問題解析器」：把中文漏洞問題轉成結構化查詢意圖，再用寫死的 SQL 查小型漏洞資料庫回答。程式都已經寫好，每一步先讀這一步要理解什麼，再讀對應的程式、跑 notebook 的實驗。

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
| NVD | 美國 NIST 的漏洞資料庫，替每個 CVE 補上 CVSS 分數、CWE、CPE | `cve` 主表的來源；`load_data.py` 從它的 JSON 取 CVSS、CWE、CPE |
| CVSS | 0–10 的嚴重程度分數（優先用 v3.1），對應 LOW / MEDIUM / HIGH / CRITICAL | `min_cvss` 條件、排序最後一層 |
| CWE | 弱點類型分類，例如 CWE-89 是 SQL injection | `cwe` 條件；階段 5 的修補建議會用它對應 OWASP |
| CPE | 產品的標準命名字串，如 `cpe:2.3:a:f5:nginx:1.25.3:...` | `products` 欄位；問「影響 nginx」就是靠它比對 |
| CISA KEV | 美國 CISA 的清單，只收已確認被實際利用的 CVE，附修補期限 | `kev` 表、`in_kev` 條件、排序第一層 |
| EPSS | FIRST 每天發布的機率（0–1），預測 CVE 未來 30 天被利用的可能性 | `epss` 表、`min_epss` 條件、排序第二層 |
| DuckDB | 單檔的嵌入式 SQL 資料庫，不用架伺服器 | 放三張表；階段 2 換成 PostgreSQL |

### 本階段用到的檔案

整個學習路線共用同一個 repo，各資料夾的用途見總覽的「Repo 結構」。這個階段的檔案都已經提供，只有 `.env` 和資料庫要自己建：

```text
vuln-agent/
├── .env                        # 步驟 1：API key，自己建，不進 git
├── src/vuln_agent/
│   ├── llm.py                  # 步驟 1：呼叫模型與算花費，之後每個階段都用
│   ├── intent.py               # 步驟 2：QueryIntent 與問題解析
│   ├── nvd.py                  # 步驟 3：呼叫 NVD API，抓資料與查證 CVE 共用
│   ├── queries.py              # 步驟 4：寫死的 SQL 樣板
│   └── api.py                  # 步驟 4：FastAPI /parse、/ask、/ask/stream
├── notebooks/
│   └── 01_llm_basics.ipynb     # 步驟 1–3 的實驗（token、effort、解析、幻覺）
├── scripts/
│   └── load_data.py            # 步驟 3：抓 NVD / KEV / EPSS 進 DuckDB
├── data/
│   └── vuln.duckdb             # 步驟 3 執行 load_data.py 產生，不進 git
└── evals/
    ├── seed.jsonl              # 步驟 5：10 題
    └── run_seed.py             # 步驟 5：跑 10 題比較兩個模型
```

所有指令都在專案根目錄執行，例如 `uv run scripts/load_data.py`。

### 步驟 1：環境與第一次呼叫

這一步要理解一次 API 呼叫的完整樣貌。回應的 `content` 是一串 block，回答放在 text block 裡；`stop_reason` 說明模型為什麼停下來，是判斷回答有沒有被截斷的依據，階段 2 的 tool-use loop 也靠它決定要不要繼續；`usage` 記錄這次用了多少 token，花費由它換算。模型的回答不固定，每次呼叫都要花錢，所以也要知道同一題重跑、調 effort、換模型時，回答和成本會怎麼變，步驟 4 記錄花費、步驟 5 比較大小模型都建立在這上面。實驗在 [`notebooks/01_llm_basics.ipynb`](../notebooks/01_llm_basics.ipynb) 的步驟 1。

- 裝好 [`uv`](https://docs.astral.sh/uv/)，在 repo 根目錄跑 `uv sync`；建 `.env` 放 `ANTHROPIC_API_KEY`（`.env` 已在 `.gitignore`）
  - `uv`：管理 Python 版本、虛擬環境和套件；專案用 `src/` 版面，notebook 和 API 都能 `import vuln_agent`
  - 這個階段用到的套件：`anthropic`（官方 SDK）、`python-dotenv`（從 `.env` 讀 API key）、`pydantic`（驗證解析結果）、`duckdb`、`httpx`（抓資料）、`fastapi`、`uvicorn`（API），開發用的 `jupyterlab`
- 讀 [`src/vuln_agent/llm.py`](../src/vuln_agent/llm.py)：`ask()` 送訊息、`text()` 只取文字 block、`cost()` 把 `usage` 換算成美元；`client` 設了逾時與自動重試
- 用 `uv run jupyter lab` 開 notebook

模型名稱與價格以[官方模型列表](https://platform.claude.com/docs/en/about-claude/models/overview)與[定價頁](https://platform.claude.com/docs/en/about-claude/pricing)為準。

### 步驟 2：結構化輸出

這一步要理解怎麼讓模型的輸出變成程式能直接用的資料。模型回答的是文字，程式要的是固定格式：structured outputs 讓 API 保證輸出符合 JSON Schema，schema 表達不了的規則（例如 CVE 編號格式）再用 Pydantic 驗證，驗證失敗就請模型修正後重試。問題先解析成結構化的查詢條件，SQL 才能由程式組出來，不用讓模型寫 SQL。這套做法之後會一直用到：階段 2 的工具參數也是 JSON Schema，階段 5 從 PDF 擷取弱點時沿用「驗證失敗就重試」。實驗在 notebook 的步驟 2，這步還不需要資料庫。

- 讀 [`src/vuln_agent/intent.py`](../src/vuln_agent/intent.py)，各部分的說明在 notebook 步驟 2 的開頭

拿結構化 JSON 有兩種做法，用的是同一份 JSON Schema，差在 schema 放在哪裡、結果從哪裡取：

| 面向 | `output_config.format`（notebook 2.1，`parse()`） | strict tool use（notebook 2.2） |
|---|---|---|
| schema 放在 | `output_config.format` | 工具的 `input_schema`，加上 `strict: True` |
| 一定拿得到結果嗎 | 是，回答本身就照 schema 輸出 | 要模型呼叫工具才有；`tool_choice` 用 auto 時，模型可以選擇不呼叫 |
| 格式保證 | constrained decoding 保證回答符合 schema | `strict: True` 保證工具參數符合 schema |
| 取結果 | text block 裡的 JSON 字串，用 `model_validate_json()` 驗證 | `tool_use` block 的 `.input`（dict），用 `model_validate()` 驗證 |
| 程式量 | 少，送出 schema、驗證回答即可 | 多，要定義工具、在 system prompt 要求呼叫、處理沒呼叫的情況 |
| 適合的情境 | 每次都要一份固定結構的輸出，例如解析問題 | 模型有多個工具可選，由它決定用哪個、填什麼參數，也就是階段 2 agent 的寫法 |

### 步驟 3：準備漏洞資料

這一步要理解為什麼漏洞情資一定要從資料庫查，這也是整個作品的核心理由。模型會憑記憶答出 CVE 編號，看起來合理，但不保證每個都存在；把 NVD、CISA KEV、EPSS 抓進 DuckDB 之後，就能逐一查證模型的回答。步驟 4 的 SQL 樣板查的就是這三張表，階段 6 會把「編造 CVE 的比率」變成評測指標。先跑 `load_data.py` 建好資料庫，再做 notebook 的步驟 3。

三份資料都是公開的官方來源，不用登入就能下載：

| 資料 | `load_data.py` 抓的網址 | 維護單位 | 為什麼有這些資料 |
| --- | --- | --- | --- |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0`（CVE API 2.0） | 美國 NIST | CVE 編號與描述由 CVE Program 發布，實際分配編號的是廠商、資安研究單位這些 CNA（CVE Numbering Authority）。NVD 收錄每一筆 CVE，NIST 再分析補上 CVSS、CWE、CPE；CNA 自己評的 CVSS 也一起收錄，標成 `Secondary` |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 美國 CISA | CISA 依約束性作業指令 BOD 22-01 建立這份清單，要求聯邦機關在 `dueDate` 前修補。收錄要同時符合三個條件：有 CVE 編號、有可靠證據顯示已在實際環境被利用、有明確的修補方式，只有公開 PoC 的不收 |
| EPSS | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | FIRST（全球資安事件應變組織論壇）的 EPSS SIG | 模型用資料夥伴的感測器偵測到的實際攻擊活動訓練，每天依 exploit 程式碼是否公開、有沒有偵測特徵、被討論的程度和 CVE 本身的特性算出機率。分數由 Empirical Security 產生並託管，[FIRST 的資料頁](https://www.first.org/epss/data)就連到這個網址 |

NIST 自 2026 年 4 月起只優先分析部分 CVE，例如列在 KEV 裡的、聯邦政府使用的軟體，其他的狀態標成 `Deferred`（說明見 [NVD 首頁](https://www.nist.gov/itl/nvd)）。所以很多新 CVE 只有 CNA 評的 CVSS，`products` 欄位也常是空的；問「影響 nginx」靠 CPE 比對，這類 CVE 就查不到。

- `NVD_API_KEY` 選用，放 `.env`；有的話 NVD 的速率限制從每 30 秒 5 次放寬到 50 次，抓資料快很多
- 讀 [`scripts/load_data.py`](../scripts/load_data.py)，再用 `uv run scripts/load_data.py` 把 NVD 最近 90 天、CISA KEV、EPSS 抓進 DuckDB。資料庫不用另外建：第一次執行時 `duckdb.connect("data/vuln.duckdb")` 會自動建檔，三張表由腳本裡的 `CREATE OR REPLACE TABLE` 建立
  - `cvss()`：同一個 CVE 可能同時有 NVD 評的 `Primary` 和廠商評的 `Secondary` 分數，也可能只有廠商評的，所以優先取 `Primary`，沒有就取第一個
  - `cwes()`：略過 `NVD-CWE-Other`、`NVD-CWE-noinfo` 這兩個佔位值
  - `cpes()`：只取 `vulnerable` 為 true 的 CPE，false 的是漏洞產品執行的平台
  - `load_epss()`：EPSS 有幾十萬筆，直接讓 DuckDB 用 `read_csv` 讀下載的 gzip 檔，比逐筆 `INSERT` 快
- 讀 [`src/vuln_agent/nvd.py`](../src/vuln_agent/nvd.py)：`load_data.py` 和 notebook 3.2 查證 CVE 都用這裡的 `nvd_get()`
  - `nvd_get()`：被限速或逾時時等 30 秒再試；官方文件沒寫限速時回哪個狀態碼，所以 403、429、503 都重試

### 步驟 4：串起來：SQL 樣板、FastAPI 與串流

這一步要理解作品的基本架構：模型只負責把問題變成查詢條件，SQL 由程式用寫死的參數化樣板執行，模型不碰 SQL，也就不會查出樣板以外的東西；回答時只把查詢結果交給模型，要求它只能提結果裡的 CVE。回答要等模型生成，用 SSE 串流讓使用者邊生成邊看。每個請求都記下 tokens、花費與各段耗時，之後階段 6 的可觀測性就是從這裡擴充。

- 讀 [`src/vuln_agent/queries.py`](../src/vuln_agent/queries.py)：每種 intent 一個 SQL 樣板，條件用具名參數帶入；沒給的條件傳 `NULL`，`$x IS NULL OR ...` 讓那一行不起作用。排序是 KEV → EPSS → CVSS
- 讀 [`src/vuln_agent/api.py`](../src/vuln_agent/api.py)：`POST /parse` 回傳意圖，`POST /ask` 回傳查詢結果，`POST /ask/stream` 用 SSE 依序送出 `intent`、`rows`、一段段的 `text`、`done`；每個請求寫一行 JSON log
- 用 `uv run uvicorn vuln_agent.api:app --reload` 啟動，另開終端機試：

  ```bash
  curl -N -X POST localhost:8000/ask/stream -H 'Content-Type: application/json' \
    -d '{"question": "最近 30 天影響 nginx、CVSS 7 以上而且已經被利用的漏洞？"}'
  ```

  API 用唯讀模式開資料庫，要重跑 `load_data.py` 時先停掉 API。

### 步驟 5：測試與收尾

這一步要理解怎麼用固定的測試題比較模型。同一組題目跑大小兩個模型，看命中數、延遲與花費，才知道換便宜的模型會不會掉品質；這 10 題在階段 2 之後繼續沿用，階段 6 擴充成完整的評測集。

- 讀 [`evals/seed.jsonl`](../evals/seed.jsonl)：10 題，4 種 intent 都有，包含要求 exploit、範圍外問題、漏洞俗稱這類刁鑽題；`expected` 只列要比對的欄位
- 用 `uv run evals/run_seed.py` 跑大小兩個模型，比較命中數、平均延遲、總花費；沒命中的題目會印出模型的解析結果
- （選做）寫一篇文章：「不用 LangChain 直接呼叫 LLM：用 NVD / KEV / EPSS 練 structured output 與串流」

**完成標準**：`/ask` 能拿到真實查詢結果、`/ask/stream` 逐字串流且提到的 CVE 都在查詢結果裡、log 有 tokens 與延遲、跑過 10 題的大小模型比較，並能解釋為什麼 CVE 資料不能讓模型憑記憶回答。
