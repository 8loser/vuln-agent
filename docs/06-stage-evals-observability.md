# 階段 6：Evals 與可觀測性

> 實驗 notebook：[`notebooks/06_evals.ipynb`](../notebooks/06_evals.ipynb)，error analysis 工作台，以及題目產生器與評分函式的原型。

這個階段是整條路線的重點，也是多數人轉 AI 應用工程師時最大的缺口：把「感覺變好了」換成「數字變好了」。前面五個階段做出了 agent、工具、報告匯入、PDF 擷取和 RAG，但只有階段 2 那二十幾題程式斷言。漏洞資料最大的好處是**標準答案能用程式從資料庫算出來**，所以這個階段以 `evals/seed.jsonl` 的 10 題當種子，自動產生 200 題以上「問題 → SQL → 標準答案」，量測 SQL 正確率、工具選擇、CVE 幻覺率、PDF 擷取、排序品質、修補建議與 RAG 檢索，放進 GitHub Actions 當回歸測試，再加上 tracing 看每個請求的成本與延遲。這裡建立的 baseline 會直接寫進作品的評測報告（F11），階段 8 微調時用同一套評測集比較。

### 要學的概念

- **先看資料再定指標（error analysis）**：先讀幾十筆真實 trace，把失敗分類、計數，再決定要量什麼。直接套現成指標，常常量到的是不重要的東西。這是 Hamel Husain 與 Shreya Shankar 評測方法的核心（[Evals FAQ](https://hamel.dev/blog/posts/evals-faq/)）。
- **可計算的標準答案**：題目由樣板加參數產生、答案由程式跑 SQL 算出，評測集才能做大又不靠人工標註；但自動產生的標準答案也會錯，公開的 text-to-SQL 基準有一半以上標註有誤（[arXiv 2601.08778](https://arxiv.org/html/2601.08778v3)），所以要人工抽查。
- **比結果、不比 SQL 字串**：同一個問題有很多種正確 SQL，要比「執行結果的集合」是否相同（execution accuracy），並決定排序與欄位要不要算進去。
- **幻覺要能自動抓**：回答裡每個 CVE 編號和分數都必須出自本次查詢結果，這是資安工具能不能被信任的底線。
- **LLM-as-judge 用二元判斷並校正**：評審模型對每個標準只回 pass / fail，不打 1 到 5 分；再用人工標註算它抓到真失敗的比例（TPR）和放行真正好答案的比例（TNR），才知道它能信幾成。
- **CI 門檻只放確定性檢查**：程式算得出對錯的指標擋 PR；LLM judge 比較慢、比較貴、也會飄，改成每晚或手動跑。
- **評測要可重現**：資料每天更新，標準答案會跟著變；評測要對固定的資料快照跑，才分得出是模型退步還是資料變了。
- **Tracing 是除錯工具，不只是儀表板**：每個請求拆成 LLM 呼叫、工具執行、SQL、檢索各段，才看得出延遲和花費卡在哪，也是 error analysis 的原料。

### 步驟 1：接上 tracing，做 error analysis

- 選 Langfuse（可用 Docker 自架，資料不出本機）或 OpenTelemetry 擇一，照官方文件把 SDK 接進 agent loop；設定與金鑰放 `.env`。OTel 的 GenAI 語意慣例還沒定案，屬性名稱可能會變
- 每個請求建一條 trace，底下切 span：意圖解析、每次 LLM 呼叫、每次工具執行、SQL、RAG 檢索；span 上記 model、tokens、花費、錯誤
- 準備約 50 題多樣的問題：seed 題、實際使用時會問的真實問題、刁鑽題、應該拒答的題，各種功能（查詢、報告匯入、PDF、修補建議）都要有
- 一筆一筆讀 trace，每筆用一兩句寫下「哪裡不對」（open coding），先不要分類
- 把筆記歸成 5 到 8 種失敗類型（例如選錯工具、SQL 條件漏掉、編出 CVE、引用不支持說法、該拒答沒拒答），算每種出現幾次
- 依出現次數和嚴重度排序，決定後面步驟的指標優先順序；把失敗類型表存成 `evals/error_analysis.md`

### 步驟 2：資料快照與評測集產生器

- 從 PostgreSQL 匯出一份固定的資料快照（例如挑 2,000 筆 CVE 加上對應的 KEV、EPSS），存成 `evals/fixtures/`，評測一律對這份快照跑；快照產生腳本 commit，資料本身依大小決定放 repo 還是 CI 時產生
- 把 `seed.jsonl` 的 10 題抽象成 8 到 12 種樣板（查單一 CVE、產品 + CVSS 門檻、KEV 篩選、EPSS 排序、時間區間、各 severity 計數、CWE 篩選、組合條件），每種樣板寫好參數化 SQL
- 寫 `evals/generate.py`：從快照抽參數（真實存在的產品、CVE、CWE），每種樣板產生 20 題以上，總數 200 題以上；每題存 `question`、`gold_sql`、`gold_result`、`expected_tool`、`template`、`difficulty`
- 每種樣板準備 3 到 5 種中文問法（口語、俗稱、相對時間），避免模型只學會一種句型；另外加 20 題 `unsupported`（要求攻擊程式、範圍外）測拒答
- 過濾掉答案為空或超過 100 筆的題目，或刻意保留少量「查無資料」題，測模型會不會硬掰
- 每種樣板隨機抽 5 題（總共 40 題以上）人工檢查題目與標準答案是否合理；問法有歧義的題目標成 `ambiguous`，統計時分開算；記下每種樣板的題數分布與抽查發現的錯誤率

範例樣板（實際欄位依你階段 2 設計的 schema 調整；notebook 裡有可以直接跑的版本）：

```python
import random

TEMPLATES = [
    {
        "id": "product_kev_cvss",
        "questions": [
            "影響 {product} 而且已經被利用、CVSS {cvss} 以上的漏洞有哪些？",
            "{product} 有哪些在 KEV 裡的高風險 CVE（CVSS ≥ {cvss}）？",
        ],
        "sql": """SELECT c.cve_id FROM cve c JOIN kev k USING (cve_id)
                  WHERE c.products ILIKE %(pattern)s AND c.cvss_score >= %(cvss)s""",
        "expected_tool": "search_vulns",
    },
]

def make_case(tpl, params, conn):
    gold = sorted(r[0] for r in conn.execute(tpl["sql"], params).fetchall())
    q = random.choice(tpl["questions"]).format(**params)
    return {"question": q, "gold_sql": tpl["sql"], "params": params,
            "gold_result": gold, "expected_tool": tpl["expected_tool"],
            "template": tpl["id"]}
```

### 步驟 3：SQL 正確率、工具選擇與幻覺率

- 寫 `evals/run.py`：對每題呼叫 agent，記下選了哪個工具、產生的 SQL、執行結果、最後回答、tokens、延遲；結果存成 `evals/results/<日期>-<模型>.jsonl`
- SQL 正確率：把模型 SQL 的執行結果和 `gold_result` 比集合是否相等；問題有要求排序（「前 5 名」）的題目才比順序；比對時忽略欄位別名與欄位順序；SQL 執行失敗算錯並記錯誤類型
- 工具選擇正確率：比對 `expected_tool`，另外列出混淆矩陣，看最常選錯成哪個工具
- 幻覺率：用 regex 抓回答裡所有 `CVE-\d{4}-\d{4,}`，不在本次查詢結果裡就算幻覺；回答裡的 CVSS、EPSS 數字也要跟資料比對（允許四捨五入誤差）
- 依樣板、難度分組統計，找出最弱的兩種樣板，記下 baseline 數字

### 步驟 4：PDF 擷取、排序品質、RAG 與修補建議

- PDF 擷取：從階段 5 用過的報告中挑 5 到 10 份，人工標註正確的弱點清單（名稱、等級、位置、建議）；擷取結果逐欄比對，算每份報告的 precision、recall 與欄位正確率
- 排序品質：用快照產生 20 組假資產清單（混入 KEV 與非 KEV 的 CVE），檢查 `prioritize` 的前 10 名是否涵蓋所有 KEV 項目（KEV 超過 10 個時改看前 N 名），順序是否符合 KEV → EPSS → CVSS 規則
- RAG 檢索：寫 30 題「問題 → 應該找到的 OWASP / CWE 段落 id」，算 recall@5、recall@10；比較階段 5 的純向量、hybrid、加 rerank 三種設定
- 修補建議 LLM-as-judge：依步驟 1 找到的失敗類型寫評分標準（建議是否正確、有沒有引用、引用是否支持說法、有沒有給出攻擊步驟），每個標準由另一個模型回 pass / fail 並附理由
- 自己人工標註 30 到 50 題 pass / fail，分成調整用和驗證用兩組；用驗證組算 judge 的 TPR 和 TNR，太低就改評分標準或換評審模型，記下調整過程

### 步驟 5：放進 GitHub Actions 當回歸測試

- 把評測分成兩組：`smoke`（約 30 題，只放確定性檢查，例如 SQL 執行結果、工具選擇、CVE 幻覺、排序規則，每個 PR 跑並當門檻）和 `full`（全部題目加 LLM judge，每晚或手動觸發，只出報告不擋 PR），控制 CI 花費
- Workflow：建好快照資料庫（PostgreSQL service container 載入快照）→ 跑評測 → 輸出 Markdown 摘要表；API key 放 GitHub Actions secrets，不寫進 repo，也不要在 log 印出
- 設門檻：SQL 正確率、幻覺率、排序品質低於規格品質目標就讓 job 失敗；初期可以先設成比 baseline 低 5% 才失敗，避免一直紅燈
- 把摘要表貼到 PR 留言或 job summary，並保留結果 jsonl 當 artifact，方便跟上一次比較
- 故意改壞一個工具描述或 prompt，確認 CI 真的會擋下來

### 步驟 6：成本、延遲與快取

- 沿用步驟 1 接好的 tracing，加上 prompt caching 命中率：記下每個請求的快取讀取 / 寫入 tokens，比較開快取前後的成本與首字延遲
- 修完問題後重跑一次步驟 1 的 50 題，看各失敗類型的次數有沒有下降，更新 `evals/error_analysis.md`
- 把 `llm.py` 的 `cost(usage, model)` 接上，每個請求算總花費；評測跑完時輸出 p50、p95 延遲與每題平均成本
- 讓評測結果每題帶 trace id，答錯的題目可以直接點進 trace 看是哪一步出錯
- 挑 3 題答錯的題目，從 trace 找出原因並修好，修完重跑評測確認數字變化

### 步驟 7：收尾

- README：評測集怎麼產生、怎麼跑 `smoke` / `full`、指標定義、baseline 結果表（各模型的 SQL 正確率、工具選擇正確率、幻覺率、PDF 擷取正確率、排序品質、RAG recall@k、judge 一致率、p50 延遲、每題成本），並附一張 trace 截圖
- （選做）寫一篇文章：「標準答案能用程式算出來：替漏洞分析 Agent 自動產生 200 題 text-to-SQL 評測集，放進 GitHub Actions」

**完成標準**：`evals/` 裡有固定的資料快照與 200 題以上自動產生的題目（每題有 gold SQL 與 gold result）；跑一次指令就能得到 SQL 正確率、工具選擇正確率、幻覺率、PDF 擷取正確率、排序品質、RAG recall@5 / recall@10 與修補建議 judge 分數，以及 judge 對人工標註的 TPR / TNR；PR 會自動跑 smoke 評測並在退步時失敗；每個請求在 Langfuse 或 OTel 裡看得到分段延遲、tokens 與花費；有一份 error analysis 整理出的失敗類型表；README 有 baseline 表，並能說明哪些指標已達規格品質目標、哪些還沒有、下一步打算怎麼改。
