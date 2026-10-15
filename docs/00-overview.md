# AI 應用工程師學習路線：從零做出弱點分析 Agent

## 總覽

分 9 個階段，邊學 AI 應用工程師的核心技能，邊做出一個能放進作品集、可以現場 demo 的作品：**弱點分析 Agent**（防守方資安工具）。照順序做，每個階段學一個技能，同時替作品加上一塊。

**最終作品**：上傳 ZAP、Trivy 掃描報告或滲透測試 PDF，Agent 合併去重、對照 NVD / CISA KEV / EPSS 排出修補優先順序，用中文回答漏洞問題，修補建議附 OWASP / CWE 引用，開工單前要人工確認。評測集證明它答得對；QLoRA 微調、自架的開源小模型負責 text-to-SQL，因為弱掃資料不能出公司。測試目標只用自己架的 Juice Shop / DVWA 和自己的 Docker image。

## 核心亮點：答案是算出來的，不是猜的

跟「把報告丟給聊天 AI 問怎麼修」最大的差別：風險判斷依據的是每天更新的 NVD / CISA KEV / EPSS 資料和 SQL 查詢結果，不靠模型記憶。「哪些已被實際利用」「被利用機率多高」「先修哪個」都是從資料庫查出來、由程式排序，模型只負責把問題轉成查詢、把結果講清楚。回答裡每個 CVE 編號和分數都必須出自這次的查詢結果，所以不會編造 CVE，也不會因為模型的知識截止日而漏掉新漏洞。

這件事有數字證明：階段 6 的評測直接量「SQL 執行結果與標準答案一致率」和「編造 CVE 或錯誤分數的比率」（目標 < 1%），拿這兩個數字對比「直接問聊天 AI」的結果（階段 1 步驟 3 就會先親眼看到模型編造 CVE 的情況）。

## 階段一覽

| 階段 | 學的技能 | 替作品加上的那一塊 | 實驗 notebook |
| --- | --- | --- | --- |
| [1](01-stage-llm-basics.md) | LLM API 基本功、structured output、串流、成本 | 問題解析器：漏洞問題轉 JSON，寫死的 SQL 查小型漏洞資料庫；前 10 題測試題 | [01_llm_basics](../notebooks/01_llm_basics.ipynb) |
| [2](02-stage-agent-data-pipeline.md) | Tool use、手寫 agent loop、工具設計、資料管線 | Agent 雛形：ETL 進 PostgreSQL；`cve_lookup`、`search_vulns`、`prioritize`、`run_sql`（唯讀）；第一版最小評測 | |
| [3](03-stage-harness-1.md) | Harness（一）：context 管理、狀態與檢查點、權限與 hooks | 長報告 context 壓縮與 token 預算、中斷續跑、工具權限分級、執行前後 hooks | [03_context_budget](../notebooks/03_context_budget.ipynb) |
| [4](04-stage-harness-2.md) | Harness（二）：subagent、MCP、框架比較 | 報告解析與情資查詢子 agent；MCP server；用 SDK 重寫一版做比較 | |
| [5](05-stage-docs-rag.md) | 文件處理、RAG | 滲透測試 PDF 擷取；OWASP / CWE / 廠商公告 RAG，附引用 | [05_pdf_rag](../notebooks/05_pdf_rag.ipynb) |
| [6](06-stage-evals-observability.md) | Evals 與可觀測性（重點） | 先做 error analysis；自動產生 200 題以上評測集；SQL 正確率、CVE 幻覺率、擷取正確率；回歸測試；tracing | [06_evals](../notebooks/06_evals.ipynb) |
| [7](07-stage-llm-security.md) | LLM 資安、治理、人工確認 | SQL 唯讀、prompt injection 測試、拒絕產生攻擊程式、人工確認、稽核 log | |
| [8](08-stage-finetune.md) | 開源模型、QLoRA 微調 | 微調 text-to-SQL，對大模型 API 比正確率、延遲、成本 | [08_finetune](../notebooks/08_finetune.ipynb) |
| [9](09-stage-deploy.md) | 自架推論、私有化部署、產品化 | vLLM 自架、Docker 部署到雲端（mTLS）、Web UI、README 與 demo 影片 | |

每個階段一份文件：目標、概念、步驟、完成標準。程式都已經寫好，文件說明每一步要理解什麼、該讀哪些程式；有實驗性質的階段另附一份 notebook，Markdown 格說明用到哪些程式，程式格直接跑，用實驗觀察程式與模型的行為。

### Repo 結構

這個 repo 包含整個作品的程式；各階段文件的「開始前」列出要先執行的指令，每個步驟寫明要讀哪些檔案。

| 資料夾 | 放什麼 |
| --- | --- |
| `docs/` | 各階段的教學文件 |
| `notebooks/` | 各階段的實驗 notebook，用階段編號命名，如 `01_llm_basics.ipynb` |
| `src/vuln_agent/` | 作品本身的程式：呼叫模型、解析、工具、API |
| `scripts/` | 手動或排程執行的工具，如抓資料的 `load_data.py`、`etl.py` |
| `db/` | PostgreSQL 的初始化腳本，從階段 2 開始使用 |
| `evals/` | 測試題與評測腳本，從階段 1 步驟 5 開始使用 |
| `tests/` | 不呼叫 LLM 的 pytest，從階段 2 開始使用 |
| `data/` | 掃描報告、知識來源、log 等本機檔案，不進 git；資料庫放在 Docker volume |

所有指令都在 repo 根目錄執行。

## 適合誰、需要先會什麼

這條路線是給「已經會寫後端，想轉成 AI 應用工程師」的人。AI 應用工程師的核心是「把 LLM 做進產品裡，並證明它可靠」，所以教程不重教一般軟體工程，時間都花在 LLM 特有的部分。

**預設你已經會**（教程不另外教）：

- **Python 後端**：FastAPI 或類似框架、Pydantic、寫爬蟲或呼叫外部 API
- **SQL 與資料庫**：PostgreSQL、索引、看得懂執行計畫；text-to-SQL 的 schema 設計與用 SQL 驗證答案（階段 2、6）會用到
- **DevOps 基礎**：Docker / Docker Compose、GitHub Actions、Nginx、TLS；階段 9 的部署與 mTLS 只帶重點
- **Web 資安基礎**：知道 OWASP Top 10、用過弱掃工具更好；階段 7 直接從 LLM 特有的風險開始
- **前端**：會一個前端框架（教程用 Vue 3，換 React 也行）
- **AI coding 工具**：用過 Claude Code 或類似工具更好，階段 3、4 會拿它的 hooks、permissions、MCP 對照自己寫的版本

**資安名詞**：CVE、CVSS、KEV、EPSS 這些漏洞情資的名詞不用先會，教材裡遇到時查[專有名詞](glossary.md)。

**不需要先會**：深度學習數學、從零訓練模型、LangChain。階段 1 刻意不經框架、直接呼叫官方 SDK；階段 5 假設你頂多做過「向量 top-k」的入門 RAG，直接從 chunking 比較開始。

**硬體**：有 6GB VRAM 以上的 NVIDIA GPU 最好，本機可以跑 1.5B 到 3B 的模型；7B 到 8B 的微調與推論用 Kaggle / Colab 的免費 GPU。沒有 GPU 也能完成大部分階段，階段 5、8 的本機模型部分改到雲端做。

### 這條路線要補的能力

| 能力 | 一般後端工程師的起點 | 要補的 |
| --- | --- | --- |
| 直接呼叫 LLM API | 多半透過框架或聊天介面 | messages、tool use、structured output、streaming、prompt caching、token 成本 |
| Agent / harness 自己蓋 | 用過 AI coding 工具，沒自己寫過 | tool-use loop、工具設計、context 管理、狀態與檢查點、權限與 hooks、subagent、MCP server |
| RAG 到能上線 | 入門教學（純向量 top-k） | chunking、hybrid search、rerank、相似度門檻、引用 |
| **Evals（最常見的缺口）** | 通常沒做過 | 測試集、LLM-as-judge、檢索指標、回歸測試 |
| 可觀測性 / 成本 | 傳統服務監控 | tracing、每次請求的成本與延遲 |
| LLM 資安 | OWASP 基礎 | prompt injection、工具權限、資料外洩、OWASP Top 10 for LLM |

## 作品規格：弱點分析 Agent

**把弱掃報告變成「先修哪個、為什麼、怎麼修」的 AI Agent**。定位是防守方工具：只分析、排序、建議修補，不產生攻擊程式、不對未授權目標掃描。名稱暫定。

### 要解決的問題

1. **報告太多、格式各不相同**：ZAP、Trivy、Semgrep、滲透測試 PDF 各有格式，同一個漏洞常重複出現
2. **不知道先修哪個**：CVSS 高不等於風險高，要再對照 CISA KEV（已被實際利用）和 EPSS（被利用機率）
3. **查情資和寫修補建議很花時間**：每個 CVE 要去 NVD、廠商公告、OWASP 來回查
4. **弱掃資料不能外流**：不能直接丟給外部 AI API，所以自架開源模型

### 核心功能

| # | 功能 | 使用者故事 | 階段 |
| --- | --- | --- | --- |
| F1 | 自然語言查漏洞情資 | 問「最近 30 天影響 nginx、而且在 KEV 裡的 CVE」，得到表格和說明 | 1 → 2–4 |
| F2 | 掃描報告匯入與去重 | 上傳 ZAP、Trivy 報告，轉成統一格式並合併重複 | 2–4 |
| F3 | 風險排序 | 依 KEV、EPSS、CVSS、是否對外排出修補順序並說明理由 | 2–4 |
| F4 | 查詢透明 | 每個答案能展開看 SQL 與原始資料、下載 CSV | 1–4，UI 9 |
| F5 | PDF 報告擷取 | 從滲透測試 PDF 擷取弱點清單成結構化資料 | 5 |
| F6 | 修補建議與引用 | 「這個 SQL injection 怎麼修？」回答附 OWASP / CWE 引用 | 5 |
| F7 | 誠實拒答與防護 | 查不到就說清楚；要求攻擊程式時拒絕 | 1 → 7 |
| F8 | 開工單與人工確認 | 產生修補工單草稿，送出前要確認，留稽核 log | 7 |
| F9 | MCP server | 在 Claude Code 裡直接呼叫這些工具 | 4 |
| F10 | 模型切換與成本顯示 | 選大模型 API 或自架微調小模型，顯示延遲和花費 | 8，UI 9 |
| F11 | 評測報告 | 各模型的 SQL 正確率、幻覺率、擷取正確率、延遲、成本 | 6 |
| F12 | Web 介面 | 上傳報告、看優先清單、聊天查詢、逐字串流 | 9 |

**不做**：產生攻擊程式、對未授權目標掃描、自動修改正式環境、帳號與付費。

### 延伸功能：攻擊鏈分析與管理層摘要（主線完成後再做）

要解決的問題：弱掃報告一筆一筆列，各自看都是「中風險」，但串起來可能是「外網一個 SSRF，讀到雲端憑證，再進到資料庫」。管理層看不到這條路，就不會撥資源修。

- **F13 攻擊鏈分析**：用圖把弱點和資產建模（哪台主機、是否對外、有什麼權限、能連到哪裡），由程式計算「從外網走到重要資料」的路徑。路徑是算出來的，不是 LLM 想像的，延續「答案是算出來的」這個核心亮點。
- **F14 管理層摘要**：LLM 只根據算出的路徑，用商業語言寫一頁報告：可能損失什麼、哪一個修補能切斷最多條路徑、大概要花多少工。摘要裡的每條路徑和弱點都要對得回計算結果。
- **範圍**：屬於防守方的攻擊路徑分析，只描述風險和修補點，不產生攻擊程式，資產資料一樣只用自己的靶機和環境。

### 資料來源

| 資料 | 來源 | 用途 |
| --- | --- | --- |
| CVE 詳細資料 | NVD CVE API 2.0（可申請免費 API key） | 主資料庫 |
| 已被實際利用的漏洞 | CISA KEV catalog（JSON / CSV） | 風險排序 |
| 被利用機率 | [FIRST EPSS](https://www.first.org/epss/api)（API 與每日 CSV） | 風險排序 |
| 開源套件漏洞 | OSV.dev（選用） | 對照 Trivy |
| 修補知識 | OWASP Cheat Sheet、CWE、廠商公告 | RAG |
| 掃描報告 | 自己對 Juice Shop / DVWA 跑 ZAP、對自己的 image 跑 Trivy | 匯入與測試 |

### 品質目標（階段 6 建立 baseline 後再調整）

| 指標 | 目標 |
| --- | --- |
| SQL 執行正確率 | 大模型 API ≥ 90%；微調小模型 ≥ 80% |
| 幻覺率（不存在的 CVE 或錯誤分數） | < 1% |
| PDF 擷取正確率 | ≥ 90% |
| 回應延遲 p50 | < 5 秒 |
| 每題成本 | 微調小模型 ≤ 大模型 API 的 1/10 |

### Demo 腳本（3 分鐘）

1. 上傳 Juice Shop 的 ZAP 報告和 Docker image 的 Trivy 報告，合併成一張清單
2. 看優先順序：「這 3 個在 KEV 裡，要先修」，點開看理由
3. 問「最近 30 天影響 nginx 且 EPSS 大於 0.5 的 CVE？」，展開看 SQL
4. 問「第一個漏洞怎麼修？」，回答附 OWASP 引用
5. 請它開修補工單，跳出人工確認
6. 要求「幫我寫攻擊程式」，拒絕並說明
7. 切換到自架微調小模型，比較延遲和花費
8. 打開評測報告：「微調讓 text-to-SQL 正確率從 X% 到 Y%，成本是 1/N」

**架構**：Web UI 與 MCP 都接到 FastAPI 上的 agent loop；agent 呼叫查詢、匯入、排序、開工單等工具，加上 OWASP / CWE 的 RAG，LLM 可切換大模型 API 或 vLLM 自架模型；ETL 排程把 NVD / KEV / EPSS 拉進 PostgreSQL；全程有 tracing、成本 log、稽核 log 和回歸評測。
