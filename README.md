# vuln-agent：從零做出弱點分析 Agent 的 AI 應用工程師學習路線

一條給後端工程師的 AI 應用工程師（AI Engineer）學習路線。9 個階段，每個階段學一個核心技能，同時替同一個作品加上一塊，最後做出一個能 demo 的**弱點分析 Agent**（防守方資安工具）：

- 匯入 ZAP / Trivy 掃描報告與滲透測試 PDF，統一格式並去重
- 對照 NVD / CISA KEV / EPSS 排出修補優先順序，並說明理由
- 用中文自然語言查漏洞資料庫（text-to-SQL），每個答案都能展開看 SQL
- 修補建議附 OWASP / CWE 引用（RAG），開工單前要人工確認
- QLoRA 微調開源小模型負責 text-to-SQL，弱掃資料不出公司
- 評測集量化 SQL 正確率與 CVE 幻覺率

**核心理念：答案是算出來的，不是猜的。** 風險判斷依據即時的 NVD / KEV / EPSS 資料和 SQL 查詢結果，不靠模型記憶，所以不會編造 CVE。

## 適合誰

會寫 Python 後端、熟 SQL、用過 Docker 的工程師，想學會「把 LLM 做進產品裡，並證明它可靠」。不需要深度學習背景，也不需要先會 LangChain。詳細的前置知識與硬體需求見 [`docs/00-overview.md`](docs/00-overview.md#適合誰需要先會什麼)。

## 怎麼開始

fork 或 clone 這個 repo 之後，照[階段 1 的「開始前」](docs/01-stage-llm-basics.md#開始前)裝套件、建 `.env`、起 PostgreSQL、抓資料。

先讀 [`docs/00-overview.md`](docs/00-overview.md) 看全貌，再從[階段 1](docs/01-stage-llm-basics.md) 照步驟往下做。CVE、KEV、EPSS 這些資安名詞可以隨時查[專有名詞](docs/glossary.md)。程式都已經寫好：每個階段先讀文件了解要理解什麼，再讀對應的程式、跑 notebook 的實驗。

想用網頁版閱讀，可以在本機預覽（用 [Jupyter Book](https://jupyterbook.org/) 建置，notebook 不會被執行）：

```bash
uvx jupyter-book@2.1.7 start
```

## 階段

| 階段 | 技能 | 實驗 notebook |
| --- | --- | --- |
| [1](docs/01-stage-llm-basics.md) | LLM API 基本功、structured output、串流、成本 | [01_llm_basics](notebooks/01_llm_basics.ipynb) |
| [2](docs/02-stage-agent-data-pipeline.md) | Tool use、手寫 agent loop、工具設計、資料管線 | |
| [3](docs/03-stage-harness-1.md) | Harness（一）：context 管理、狀態與檢查點、權限與 hooks | [03_context_budget](notebooks/03_context_budget.ipynb) |
| [4](docs/04-stage-harness-2.md) | Harness（二）：subagent、MCP、框架比較 | |
| [5](docs/05-stage-docs-rag.md) | 文件處理、RAG | [05_pdf_rag](notebooks/05_pdf_rag.ipynb) |
| [6](docs/06-stage-evals-observability.md) | Evals 與可觀測性 | [06_evals](notebooks/06_evals.ipynb) |
| [7](docs/07-stage-llm-security.md) | LLM 資安、治理、人工確認 | |
| [8](docs/08-stage-finetune.md) | 開源模型、QLoRA 微調 | [08_finetune](notebooks/08_finetune.ipynb) |
| [9](docs/09-stage-deploy.md) | 自架推論、私有化部署、產品化 | |

## Repo 結構

| 路徑 | 內容 |
| --- | --- |
| `docs/` | 總覽與各階段文件：目標、概念、步驟、完成標準 |
| `notebooks/` | 有實驗性質的階段各一份 notebook，用實驗觀察程式與模型的行為 |
| `src/vuln_agent/` | 作品本身的程式 |
| `scripts/` | 手動或排程執行的工具，如抓資料的 `load_data.py`、`etl.py` |
| `db/` | PostgreSQL 的初始化腳本 |
| `evals/` | 測試題與評測腳本 |
| `tests/` | 不呼叫 LLM 的 pytest |

## 規則

- **只做防守**：不產生攻擊程式，不掃描未授權的目標。測試目標只用自己架的 OWASP Juice Shop、DVWA 和自己的 Docker image。
- API key、憑證、掃描報告放 `.env` 與 `data/`，都不進 git。
- 文件裡的 API、套件版本與價格以官方文件為準；寫作時間是 2026-10，模型與 SDK 更新後可能要調整。
