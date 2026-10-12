# 階段 9：部署與產品化（約 12 小時）

這個階段把前面八個階段做出來的東西組成一個別人打得開、看得懂的產品。階段 8 微調好的小模型改用 vLLM 以 OpenAI 相容 API 提供服務，透過階段 8 抽好的 LLM 介面接回 agent，跟大模型 API 並列成可切換的兩個選項；FastAPI 後端、vLLM、資料庫一起用 Docker 部署到 GCP，內部存取用 mTLS 保護；再補上 Web UI（上傳報告、優先清單、串流聊天、展開 SQL、模型切換與成本顯示，對應規格 F4、F10、F12）和成本 / 延遲儀表板。最後把階段 6 起累積的評測結果整理進 README，照規格的 Demo 腳本錄一支 3 分鐘影片，整個作品到這裡收尾。

### 要學的概念

- **vLLM 與 OpenAI 相容 API**：同一套 client 程式碼只換 `base_url` 就能在大模型 API 和自架模型之間切換，這是 F10 能做得乾淨的前提。
- **LoRA adapter 的上線方式**：合併成完整權重或由 vLLM 動態載入 adapter，兩者在啟動時間、VRAM、管理多版本上的取捨不同，是部署自架模型時一定要想清楚的問題。
- **GPU 推論的成本模型**：自架模型是「按開機時間」付錢、API 是「按 token」付錢，要算出在什麼請求量以下自架反而比較貴，才能誠實回答「成本是 1/N」。
- **私有化部署與 mTLS**：弱掃資料不出公司是自架模型的主要賣點，用 mTLS 限制只有持有用戶端憑證的機器能連，是把這個賣點落實到架構上。
- **串流 UI 與可解釋性**：SSE 逐字輸出加上「展開 SQL、看原始資料」，讓使用者能驗證答案，而不是只能相信模型。
- **延遲與成本的可觀測性**：p50 / p95 延遲、每題成本、tokens 要能依模型分組比較，品質目標才有辦法驗證。

### 步驟 1：用 vLLM 服務微調模型並接回 agent（約 3 小時）

- [ ] 決定上線方式：把階段 8 的 LoRA adapter 合併成完整權重，或用 vLLM 的 LoRA 載入功能（參數名稱以官方文件為準），在 README 記下選擇理由
- [ ] 先在本機或 Kaggle / Colab 用 vLLM 起 OpenAI 相容服務；6GB VRAM 的 GPU 只試 1.5B–3B、fp16，注意 `max_model_len` 與 GPU 記憶體比例要調小，跑不動就改到雲端驗證
- [ ] 如果 agent 依賴 tool calling，確認 vLLM 對該模型的 tool call 解析設定（啟動參數以官方文件為準）；不支援就改成要求模型輸出 JSON 再由 Pydantic 驗證
- [ ] 在 LLM 介面新增 `vllm` provider，只改 `base_url` 與模型名稱，跑一次階段 6 的 eval，確認分數跟階段 8 離線評測的結果一致（差太多先查 chat template）
- [ ] 每個請求記錄 provider、模型、tokens、首字延遲、總延遲；自架模型的花費先用「GPU 每小時價格 ÷ 實測每小時可處理題數」估算

### 步驟 2：FastAPI + Docker 部署到雲端，加上 mTLS（約 2 小時，假設你已熟悉 Docker 與 TLS，時間主要花在 GPU VM 與成本控制）

- [ ] 寫 `docker-compose.yml`：`api`（FastAPI + agent）、`vllm`、`db`（PostgreSQL）、`proxy`（Nginx 或 Caddy 做 mTLS），只有 `proxy` 對外開 port，`vllm` 與 `db` 只在內部網路
- [ ] 用自建 CA 簽伺服器憑證與用戶端憑證，proxy 設定要求並驗證用戶端憑證；用 `curl` 測「有憑證能連、沒憑證被擋」
- [ ] 以 GCP 為例（AWS、Azure 的做法類似，名稱換成對應服務）：開一台小 GPU 的 Compute Engine VM（例如 T4 或 L4 等級，型號與價格以 GCP 官方文件為準），先確認 GPU 配額；可考慮 Spot VM 降低成本
- [ ] 成本控制：寫 `start.sh` / `stop.sh` 用 `gcloud` 開關 VM，只在 demo 或跑 eval 時開機；設定 GCP 預算警示
- [ ] Secrets（`ANTHROPIC_API_KEY`、DB 密碼）放 VM 上的 `.env` 或 Secret Manager，不進 image、不 commit；用 GitHub Actions 建 image 推到 Artifact Registry
- [ ] 部署後在雲端再跑一次 eval，確認結果跟本機一致

```yaml
services:
  proxy:
    image: nginx:stable
    ports: ["443:443"]
    volumes:
      - ./deploy/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./deploy/certs:/etc/nginx/certs:ro   # server.crt / server.key / ca.crt，不 commit
    depends_on: [api]
  api:
    build: .
    env_file: .env                          # 不 commit
    environment:
      VLLM_BASE_URL: http://vllm:8000/v1
      DATABASE_URL: postgresql://vuln:${DB_PASSWORD}@db:5432/vuln
    depends_on: [db, vllm]
  vllm:
    image: vllm/vllm-openai:latest          # 版本與啟動參數以官方文件為準
    command: ["--model", "/models/vuln-sql-merged", "--max-model-len", "4096"]
    volumes: ["./models:/models:ro"]
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, count: 1, capabilities: [gpu]}]
  db:
    image: postgres:16
    environment: {POSTGRES_USER: vuln, POSTGRES_PASSWORD: "${DB_PASSWORD}", POSTGRES_DB: vuln}
    volumes: ["pgdata:/var/lib/postgresql/data"]
volumes: {pgdata: {}}
```

### 步驟 3：Web UI（約 2.5 小時）

- [ ] 用 Vue 3（Vite 起專案，換成你熟的前端框架也行）做單頁應用，build 後由 FastAPI 或 proxy 提供靜態檔，不另開服務
- [ ] 上傳頁：拖放 ZAP / Trivy 報告（和 PDF），顯示匯入筆數與去重結果，接階段 4、5 的匯入 API（F2、F5）
- [ ] 優先清單頁：表格依 KEV → EPSS → CVSS 排序，每列可展開看排序理由（F3）
- [ ] 聊天頁：用 SSE 逐字顯示回答；每則回答下方可展開實際執行的 SQL、原始資料表格，並下載 CSV（F4）；開工單時跳出人工確認對話框（F8）
- [ ] 模型切換：下拉選「大模型 API / 自架微調模型」，每則回答顯示模型名稱、延遲、tokens、花費（F10）；自架 VM 沒開時要顯示清楚的錯誤而不是卡住
- [ ] 前端不放任何 API key；模型輸出一律當純文字或經過消毒的 Markdown 渲染，避免報告欄位裡的內容變成 XSS（呼應階段 7 的紅隊測試）

### 步驟 4：成本與延遲儀表板（約 2 小時）

- [ ] 從請求 log（或階段 6 接的 tracing）彙整出每個模型的請求數、p50 / p95 延遲、平均 tokens、每題平均花費
- [ ] 在 Web UI 加一頁儀表板，至少兩張圖：延遲分布依模型分組、累計花費趨勢
- [ ] 對照規格品質目標，算出「自架 / API 每題成本比」與 p50 延遲是否達標，未達標就寫下原因（例如 VM 開機時間沒分攤、冷啟動）
- [ ] 算損益平衡點：每天多少題以上，自架 GPU 才比 API 便宜，寫進 README

### 步驟 5：收尾：README、Demo 影片與文章（約 2.5 小時）

- [ ] README 重寫成作品首頁：一句話介紹、架構圖、截圖、一行指令本機啟動、部署方式與成本控制說明、範圍外事項（不寫 exploit、只測 Juice Shop / DVWA 和自己的 image）
- [ ] README 放評測結果表（F11）：各模型的 SQL 正確率、幻覺率、PDF 擷取正確率、排序品質、p50 延遲、每題成本，並註明 eval 集大小與跑的日期
- [ ] 照規格的 Demo 腳本 8 個步驟先排練一次，確認每步都在雲端版本跑得通，再錄 3 分鐘影片（先開 VM、預熱模型，錄完記得關機）
- [ ] 影片上傳後把連結放 README 最上方，並在 repo 加上 tag（例如 `v1.0`）
- [ ] （選做）寫一篇文章：「把微調小模型送上線：vLLM、Docker、mTLS 與 GPU 成本的取捨」

**完成標準**：雲端上的服務只有持有用戶端憑證才能連，沒憑證的請求被擋；Web UI 能上傳 ZAP 與 Trivy 報告、看到優先清單、聊天逐字串流、展開 SQL 並下載 CSV、在大模型 API 與 vLLM 自架微調模型之間切換且每則回答顯示延遲與花費；儀表板能依模型比較 p50 / p95 延遲與每題成本；雲端版本的 eval 分數與本機一致；README 有評測結果表、損益平衡點與 3 分鐘 demo 影片連結，且 repo 裡沒有任何 key 或憑證私鑰；VM 在 demo 以外的時間是關機狀態。
