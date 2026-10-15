# 階段 8：開源模型微調

> 實驗 notebook：[`notebooks/08_finetune.ipynb`](../notebooks/08_finetune.ipynb)，資料切分、防洩漏檢查、baseline 與 QLoRA 訓練（可上傳到 Colab 跑）。

這個階段的目標是證明「弱掃資料不出公司」也能有夠用的 text-to-SQL：把階段 6 的題目產生器擴到數千題訓練集，先量出大模型 API few-shot 與開源小模型 zero-shot 的 baseline，再用 QLoRA 微調一個授權乾淨的開源小模型，用階段 6 的同一套評測集比較正確率、VRAM、延遲與成本。替作品加上的是 F10「模型切換與成本顯示」的後端：agent 可以在「大模型 API」與「自架微調小模型」之間切換，F11 評測報告多出微調後的那幾列。階段 7 做好的唯讀 SQL 與防護照樣套在小模型產生的 SQL 上；這裡先用 Ollama 或本機推論跑起來，階段 9 再換成 vLLM 正式服務。選模型要先看授權：Qwen2.5-Coder-3B-Instruct 的 model card 寫的是非商用的 qwen-research 授權，作品要公開展示就不要用；改用 Qwen2.5-Coder-1.5B / 7B 或 Qwen3 系列小模型，下手前自己確認 model card 的授權欄位。整個階段盡量收斂在同一個模型系列；RTX 20 系列與 T4 這類 Turing 架構 GPU 不支援 bf16，先避開 Gemma 這類在 fp16 下有數值問題的模型。

### 要學的概念

- **資料切分與洩漏**：產生器做出來的題目很像，只按隨機列切分會讓測試題的「近親」出現在訓練集，分數虛高；要依模板、產品名稱與正規化後的 SQL 分組切分。
- **Baseline 先行**：沒有 API few-shot 與開源 zero-shot 的數字，就說不出微調到底提升了多少，作品裡「從 X% 到 Y%」那句話也就沒有根據。
- **LoRA / QLoRA**：只訓練少量 adapter 參數，再把底模以 4-bit 載入，才能在 6GB VRAM 的消費級 GPU 上微調 1.5B–3B；要懂 rank、alpha、target modules 對品質與記憶體的影響。
- **精度與硬體限制**：Turing 架構（RTX 20 系列、Kaggle / Colab 常見的 T4）不支援 bf16，要用 fp16 與 loss scaling；較新的 GPU 可以用 bf16，但為了本機與雲端結果一致，整個階段統一用 fp16 比較單純。
- **量化的取捨**：同一個微調模型做 4-bit、8-bit、fp16 推論，正確率、VRAM、延遲會不同；部署時選哪個要用數字決定，不是憑感覺。
- **Chat template 一致**：訓練時與推論時的 prompt 格式（system、schema 描述、chat template）必須一模一樣，否則微調效果會在上線時消失。

### 步驟 1：擴充訓練資料集與切分

- 擴充階段 6 的產生器：加模板（排序、計數、時間範圍、多表 JOIN、KEV / EPSS 組合條件）與中文問法變化（口語、俗稱、相對時間），產出 3000–5000 題「問題 → SQL → 標準答案」
- 每題都實際在資料庫執行一次，丟掉執行失敗或結果為空的題目；SQL 正規化後去重
- 依「模板 + 產品名稱」分組切成訓練 / 驗證 / 測試（例如 80 / 10 / 10），並保留部分模板與產品只出現在測試集，量測泛化能力
- 寫檢查腳本：確認階段 6 的固定評測集（200 題以上）與手寫刁鑽題完全不在訓練集裡（比對問題文字與正規化 SQL）
- 轉成 chat 格式 JSONL（見下方範例），system prompt 放精簡 schema 描述，跟 agent 實際呼叫時用的一致
- 記下各集合題數、模板分布、去重前後數量

```json
{"messages": [
  {"role": "system", "content": "你把漏洞問題轉成 PostgreSQL 唯讀 SQL。只輸出 SQL。\n資料表：cve(cve_id, published, description, cvss_score, severity, cwe, products)、kev(cve_id, vendor, product, date_added, due_date)、epss(cve_id, epss, percentile)"},
  {"role": "user", "content": "最近 30 天影響 nginx、CVSS 7 以上而且在 KEV 裡的漏洞，依 EPSS 由高到低"},
  {"role": "assistant", "content": "SELECT c.cve_id, c.cvss_score, e.epss FROM cve c JOIN kev k ON k.cve_id = c.cve_id LEFT JOIN epss e ON e.cve_id = c.cve_id WHERE c.products ILIKE '%nginx%' AND c.cvss_score >= 7 AND c.published >= now() - INTERVAL 30 DAY ORDER BY e.epss DESC NULLS LAST"}
]}
```

範例裡的欄位沿用階段 1 的 schema，請換成你階段 2 之後實際的 PostgreSQL schema。

### 步驟 2：Baseline 評測

- 把階段 6 的評測腳本改成可以吃任何「OpenAI 相容端點 + 模型名稱」，同一份測試集、同一個 SQL 正確率判定（執行結果等於標準答案）
- 大模型 API few-shot：從訓練集挑 5–8 題當範例，量 SQL 正確率、幻覺率、p50 延遲、每題成本
- 開源 zero-shot：安裝 Ollama（本機跑開源模型、提供 OpenAI 相容 API），跑候選小模型（例如 Qwen2.5-Coder-1.5B 或 Qwen3 小模型，授權先確認），同樣的 prompt 不給範例；再加一組「prompting + self-correction」：SQL 執行失敗就把錯誤丟回模型重寫，最多兩次。微調要贏過這組才算値得
- 把錯誤分類（語法錯、欄位名錯、條件漏掉、JOIN 錯、時間計算錯），存成表格，之後對照微調是否改善
- 記下 baseline 表格

### 步驟 3：本機 QLoRA 微調 1.5B–3B

- 準備訓練環境：Hugging Face Transformers + PEFT + TRL（或 Unsloth），CUDA 版本與套件相容性以官方文件為準；`.env` 放 Hugging Face token，不 commit
- 先用 1.5B 跑通：4-bit 載入、LoRA（rank 先試 16）、fp16（不要開 bf16）、gradient checkpointing、batch 1 + gradient accumulation、序列長度依 schema prompt 長度設定
- 訓練時記錄 loss 曲線與 VRAM 峰值；每個 epoch 在驗證集跑 SQL 正確率，挑最好的 checkpoint，不要只看 loss
- VRAM 夠的話換同系列大一點的尺寸再跑一次（授權一樣要確認）；遇到 OOM 依序調低序列長度、rank、改 target modules，記下每次調整
- 用測試集評測兩個微調模型，對照步驟 2 的錯誤分類看哪些類型變少
- adapter 存檔並寫下訓練設定（底模版本、超參數、資料版本、訓練時數），確保可重現

### 步驟 4：雲端微調 7B–8B 與量化比較

- 在 Kaggle 或 Colab 的 T4 上用同一份資料與腳本微調同系列 7B–8B（例如 Qwen2.5-Coder-7B，授權先確認），一樣用 fp16；注意免費時數與 session 中斷，checkpoint 要存到雲端硬碟或 Hugging Face 私有 repo
- 訓練資料只用產生器產的題目與公開 NVD / KEV / EPSS 資料，不上傳任何真實掃描報告
- 把本機最好的微調模型合併 adapter 後，分別做 4-bit、8-bit、fp16 推論（例如轉 GGUF 給 Ollama / llama.cpp，工具與指令以官方文件為準）
- 每個組合量 SQL 正確率、VRAM、p50 / p95 延遲、每秒 tokens
- 整理一張表：模型大小 × 量化方式 × 正確率 × VRAM × 延遲

### 步驟 5：接回 agent 與評測報告

- 把呼叫 LLM 的部分抽成介面，同時支援 Claude API 和 OpenAI 相容端點，再加「模型設定檔」：可選大模型 API 或自架微調小模型（OpenAI 相容端點），text-to-SQL 工具依設定切換
- 小模型產生的 SQL 一樣經過階段 7 的唯讀檢查與防護；執行失敗時把錯誤回傳重試一次，或回退到大模型 API（可設定）
- 每次回答記錄並回傳使用的模型、延遲、花費（自架模型用 GPU 時間或電費估算，寫清楚估算方式）
- 用同一份評測集跑完整 agent（不只單獨 SQL）兩種模型各一輪，更新 F11 評測報告
- 算出成本比 1/N 和正確率差距，對照規格的品質目標（微調小模型 SQL 正確率 ≥ 80%、成本 ≤ 1/10）

### 步驟 6：收尾

- README：資料集產生與切分方式、防洩漏檢查、訓練設定、baseline vs 微調 vs 量化的比較表、怎麼切換模型
- 用實際數字寫一句作品摘要（放 README 開頭或作品集）：「QLoRA 微調開源小模型做漏洞資料庫 text-to-SQL，正確率從 X% 提升到 Y%，成本 1/N，弱掃資料不出公司」
- （選做）寫一篇文章：「在 6GB 顯卡上 QLoRA 微調 text-to-SQL：從資料切分、fp16 踩雷到量化取捨」

**完成標準**：有數千題且通過防洩漏檢查的訓練 / 驗證 / 測試集；有 API few-shot、開源 zero-shot、prompting + self-correction、本機微調小模型、雲端微調 7B–8B 在同一測試集上的 SQL 正確率表；有量化方式對正確率、VRAM、延遲的比較表；agent 能用設定切換大模型 API 與自架微調小模型，每次回答顯示模型、延遲與花費；F11 評測報告已更新，作品摘要裡的 X、Y、N 都是實測數字。
