# 階段 5：文件處理與 RAG（約 16 小時）

> 實驗 notebook：[`notebooks/05_pdf_rag.ipynb`](../notebooks/05_pdf_rag.ipynb)，PDF 解析、擷取評分、chunking 與檢索指標、門檻選擇。

這個階段替作品加上**知識層**，分兩半。前半做 F5：把滲透測試 PDF 報告擷取成跟 ZAP / Trivy 匯入結果同一種格式的弱點清單，交給階段 4 的「報告解析」子 agent 一起去重、排序。後半做 F6：把入門版的 RAG（例如 LangChain + 向量資料庫、純向量 top-k）升級到能上線的程度，讓 agent 回答「這個 SQL injection 怎麼修？」時引用 OWASP Cheat Sheet、CWE、廠商公告，查不到就直接說不知道。兩半都要先做一份小型人工標註，有了基準才能比較各種做法，階段 6 的評測集也會直接沿用。

```python
from typing import Literal
from pydantic import BaseModel, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]

class Finding(BaseModel):
    title: str = Field(min_length=3)
    severity: Severity
    location: str            # URL、主機:port、檔案路徑或參數名稱
    recommendation: str
    cwe: str | None = None   # 例如 "CWE-89"，報告沒寫就留 None，不要讓模型猜
    source_page: int         # 出自 PDF 第幾頁，方便人工核對

    @field_validator("severity", mode="before")
    @classmethod
    def normalize(cls, v: str) -> str:
        return {"嚴重": "critical", "高": "high", "中": "medium", "低": "low",
                "資訊": "info", "informational": "info"}.get(str(v).strip().lower(), str(v).strip().lower())

class FindingList(BaseModel):
    report_name: str
    findings: list[Finding]
```

上面是擷取結果的骨架：等級正規化寫在 validator 裡，不靠 prompt；`source_page` 讓每一筆都能對回原文。

### 要學的概念

- **PDF 不是文字檔**：PDF 存的是排版指令，表格、跨頁、頁首頁尾、雙欄都會打亂順序；先把版面還原好，LLM 擷取的品質才上得去。
- **擷取 = schema + 驗證 + 重試**：Pydantic 擋下格式錯誤，把錯誤訊息丟回模型重試，比把 prompt 寫得很長可靠。
- **沒有標註就沒有正確率**：自己標幾份報告當 ground truth，逐欄位算 precision / recall，才知道改了 prompt 或 chunking 到底有沒有變好。
- **Chunking 決定檢索上限**：切太碎會丟掉上下文，切太大會稀釋相關性；Cheat Sheet 這種有標題層級的文件，照標題切通常比固定長度好，但要用數字證明。
- **Hybrid search 與 reranker**：向量擅長語意（「怎麼防注入」），BM25 擅長精確詞（「CWE-89」、「PreparedStatement」）；兩者融合後再用 cross-encoder 重排，取前幾名。
- **門檻、拒答、引用**：分數低於門檻就說不知道，回答的每一句都要對得回某個 chunk 的來源網址，這是 RAG 能不能上線的關鍵。

### 步驟 1：PDF 解析與練習資料（約 3 小時）

- [ ] 準備 4 到 6 份 PDF：把階段 4 跑出來的 Juice Shop / DVWA ZAP 結果匯出成 PDF（ZAP 報告功能可選的模板以官方文件為準，或把 HTML 報告用瀏覽器列印成 PDF），再找 2 到 3 份公開的滲透測試報告範本（例如 GitHub 上整理公開報告的 repo），只在本機練習，不放進 repo
- [ ] 至少要有一份是「表格式」（弱點列在表格裡），一份是「段落式」（每個弱點一節），一份是中文報告
- [ ] 用一個 PDF 函式庫（例如 pdfplumber 或 PyMuPDF，函式名以官方文件為準）抽出每頁文字和表格，存成 `data/pdf_parsed/<name>.json`，保留頁碼
- [ ] 處理頁首頁尾（重複出現的公司名、頁碼）與跨頁表格，比較處理前後的輸出差異
- [ ] 記下：每份 PDF 的頁數、抽出幾張表、哪一份最難處理以及原因

### 步驟 2：LLM 擷取與人工標註基準（約 3.5 小時）

- [ ] 依上面的骨架寫 `Finding` / `FindingList`，用 structured outputs（`client.messages.parse(output_format=FindingList)`）讓模型回傳 `FindingList`，延用階段 1 的「驗證失敗 → 把錯誤丟回模型 → 最多重試 2 次」
- [ ] 長報告先依章節或頁數分段擷取再合併，每段控制在階段 3 定的 token 預算內，合併時用 `title + location` 去重
- [ ] 人工標註 3 份報告存成 `evals/pdf_gold/<name>.json`（格式跟 `FindingList` 一樣），一份至少 8 筆弱點
- [ ] 寫 `eval_extract.py`：以 `title + location` 配對，算每份的 precision、recall，以及配對成功後 severity、recommendation 是否正確，產出一張表
- [ ] 同一套流程比較大模型 API 與本機 Ollama 小模型（1.5B–3B），記錄正確率、重試次數、延遲、花費
- [ ] 擷取結果轉成階段 4 的統一格式存進資料庫，讓報告解析子 agent 能跟 ZAP / Trivy 的結果一起去重

### 步驟 3：知識庫與 chunking 比較（約 3 小時）

- [ ] 下載知識來源存成 `data/kb/`：OWASP Cheat Sheet Series（官方 GitHub repo 有 Markdown 原檔）、CWE（MITRE 提供 XML 下載）、2 到 3 個廠商公告（例如 nginx security advisories），每筆記下來源網址與抓取日期
- [ ] 寫 ingest 腳本：每個 chunk 帶 metadata（`source`、`url`、`title`、`section`、`cwe`），重跑時用內容 hash 判斷要不要更新，做到能「重建索引」
- [ ] 實作 3 種 chunking：固定長度加重疊、依 Markdown 標題切、CWE 依條目切（一個 CWE 一到數個 chunk）
- [ ] 寫 20 題檢索測試題存成 `evals/rag_seed.jsonl`，每題標出應該命中的文件與段落；混合中英文、俗稱（「SQL 注入」）、精確詞（「CWE-79」），加 3 題知識庫裡沒有答案的
- [ ] 換 embedding 模型（例如多語的 bge-m3 或 multilingual MiniLM，6GB VRAM 的 GPU 跑得動，CPU 也行但慢），用 recall@5 和 MRR 比較 3 種 chunking，選一種當預設

### 步驟 4：Hybrid search、reranker 與門檻（約 3.5 小時）

- [ ] 加上 BM25（可以用 Qdrant 的 sparse vector，或另外用一個 BM25 函式庫，做法以官方文件為準），跟向量結果用 RRF（reciprocal rank fusion）融合
- [ ] 加一個 cross-encoder reranker（例如 bge-reranker 系列），先取前 20 再重排到前 5，記錄增加的延遲
- [ ] 用 20 題比較 4 種組合：只用向量（入門版的 top-k）、只用 BM25、hybrid、hybrid + rerank，列 recall@5、MRR、p50 延遲
- [ ] 用 reranker 分數設相似度門檻：畫出「有答案的題目」和「沒答案的題目」的分數分布，選一個門檻讓沒答案的 3 題都被擋下、有答案的題目盡量不被誤擋
- [ ] 記下比較表和選定的門檻，說明為什麼精確詞查詢（例如「CWE-89」）在純向量下容易失手

### 步驟 5：附引用的回答與接回 agent（約 2 小時）

- [ ] 包成工具 `search_remediation(query, cwe=None)`，回傳 chunk 內容與來源；分數全低於門檻時回傳「找不到」，不回傳勉強相關的內容
- [ ] 回答 prompt 要求每段建議後面標 `[1]`、`[2]`，對應到 chunk 的 `url` 與標題；找不到就說「知識庫裡沒有相關資料」，不准用模型記憶補
- [ ] 寫一個檢查函式：回答裡每個引用編號都要存在於這次檢索結果，引用的網址都要出自 metadata，不符就記 log
- [ ] 跑完整流程：匯入一份 PDF → 擷取出 SQL injection → 問「第一個漏洞怎麼修？」→ 回答附 OWASP / CWE 引用
- [ ] 防守方檢查：知識庫只收修補與防禦內容，問「給我 payload」時照階段 1 的 `unsupported` 規則拒絕

### 步驟 6：收尾（約 1 小時）

- [ ] README：PDF 擷取怎麼跑、擷取正確率表（API vs 本機小模型）、RAG 架構圖、4 種檢索組合的比較表、門檻怎麼選、怎麼重建索引
- [ ] （選做）寫一篇文章：「把入門 RAG 升級到能上線：用 OWASP 與 CWE 練 chunking、hybrid search、rerank 與附引用的拒答」，或拆成兩篇，另一篇寫「從滲透測試 PDF 擷取弱點清單：Pydantic 驗證、重試與人工標註」

**完成標準**：3 份人工標註報告的擷取有 precision / recall 表，至少一個模型接近規格的 90% 目標（沒達到就寫出差在哪）；擷取結果能進資料庫跟 ZAP / Trivy 一起去重；20 題檢索測試有 4 種組合的比較表，hybrid + rerank 的 recall@5 優於只用向量的 top-k；知識庫沒有答案的 3 題都回答「不知道」；完整流程的回答每個引用都對得回檢索到的來源網址；知識庫能用一個指令重建。
