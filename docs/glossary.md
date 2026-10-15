# 專有名詞

資安領域的名詞跟後端開發不太一樣，這頁列出教材裡會遇到的資安名詞，讀文件時隨時回來查。每個名詞附上它在教材的哪裡用到；AI 相關的概念在各階段文件裡說明。

## 漏洞的編號與評分

一個漏洞公開後會拿到 CVE 編號，再由不同單位補上不同角度的資料：CVSS 看「多嚴重」，KEV 看「已經被利用了嗎」，EPSS 看「多可能被利用」。作品排修補順序用 KEV → EPSS → CVSS，因為「已經發生」比「理論上嚴重」更急。

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| CVE（Common Vulnerabilities and Exposures） | 公開漏洞的統一編號，格式 `CVE-年份-流水號`，例如 `CVE-2021-44228`。由 CVE Program 發布，MITRE 負責營運 | 所有資料表共用的 key；回答裡的 CVE 編號都要出自查詢結果 |
| CNA（CVE Numbering Authority） | 獲授權分配 CVE 編號的單位，多半是軟體廠商與資安研究單位。CNA 也會自己評 CVSS | NVD 資料裡標成 `Secondary` 的分數就是 CNA 評的 |
| CVSS（Common Vulnerability Scoring System） | 0 到 10 的嚴重程度分數，常見的是 v3.1 與 v4.0。分數對應等級：0.1–3.9 LOW、4.0–6.9 MEDIUM、7.0–8.9 HIGH、9.0–10 CRITICAL | `cve.cvss_score`、`severity`；「高風險」對應 CVSS 7 以上 |
| EPSS（Exploit Prediction Scoring System） | 0 到 1 的機率，預測 CVE 未來 30 天被利用的可能性，每天更新。`percentile` 是這個分數在所有 CVE 裡的百分位 | `epss` 表；排序的第二層 |
| CWE（Common Weakness Enumeration） | 弱點類型的分類，由 MITRE 維護，例如 CWE-89 是 SQL injection、CWE-79 是 XSS。CVE 是「哪一個漏洞」，CWE 是「哪一類錯誤」 | `cve.cwe`；階段 5 用它對應 OWASP 的修補建議 |
| CPE（Common Platform Enumeration） | 產品的標準命名字串，格式 `cpe:2.3:類型:廠商:產品:版本:...`，類型 `a` 是應用程式、`o` 是作業系統、`h` 是硬體 | `cve_product` 表；問「影響 nginx」靠它比對 |

## 資料來源與機構

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| NVD（National Vulnerability Database） | 美國國家漏洞資料庫，由 NIST 維護。收錄所有 CVE，並補上 CVSS、CWE、CPE；有網站可以查，也有 API | `cve`、`cve_product` 表的來源；`nvd.py` 呼叫它的 CVE API 2.0 |
| NIST | 美國國家標準暨技術研究院，NVD 的維護單位 | 2026 年 4 月起只優先分析部分 CVE，其他的狀態標成 `Deferred` |
| CISA | 美國網路安全暨基礎設施安全局 | KEV 清單的發布單位 |
| KEV（Known Exploited Vulnerabilities） | CISA 維護的清單，只收已確認在實際環境被利用、而且有修補方式的 CVE。依 BOD 22-01（約束性作業指令）要求聯邦機關在修補期限（`dueDate`）前修好 | `kev` 表；排序的第一層 |
| FIRST | 全球資安事件應變組織論壇，EPSS 由它底下的 EPSS SIG（特別興趣小組）制定 | EPSS 的來源 |
| MITRE | 美國的非營利組織，營運 CVE Program 並維護 CWE | CVE、CWE 的來源 |
| 漏洞狀態 | NVD 裡每個 CVE 有狀態：`Analyzed` 是 NIST 分析完、`Deferred` 是 NIST 延後分析（只有 CNA 的資料）、`Rejected` 是編號被撤銷 | ETL 遇到 `Rejected` 就從資料庫刪掉 |

## 弱點類型與參考標準

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| SQL injection（SQL 注入） | 使用者輸入被拼接進 SQL，改變了查詢的意思，可能讀出或改掉不該碰的資料。CWE-89 | 測試題；作品的 SQL 一律用參數化查詢 |
| XSS（Cross-Site Scripting） | 網站把使用者輸入原樣輸出成 HTML，讓攻擊者的 script 在其他使用者的瀏覽器執行。CWE-79 | 測試題 |
| OWASP | 開放的 Web 應用程式安全社群，發布各種安全指引與工具 | Juice Shop、Cheat Sheet Series 都出自這裡 |
| OWASP Top 10 | OWASP 整理的十大 Web 應用程式安全風險 | 修補建議的參考分類 |
| OWASP Top 10 for LLM Applications | 同一個社群針對 LLM 應用整理的十大風險，例如 prompt injection、過度授權 | 階段 7 的威脅模型 |
| OWASP Cheat Sheet Series | OWASP 針對各種主題整理的防護做法，例如怎麼防 SQL injection | 階段 5 RAG 的知識來源 |
| 廠商公告（security advisory） | 軟體廠商針對自家產品漏洞發布的說明，通常有受影響版本與修補版本 | 階段 5 RAG 的知識來源 |

## 掃描與測試

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| 弱掃（弱點掃描） | 用工具自動找出已知的弱點，產出報告。同一個漏洞常被不同工具重複報告 | 作品要匯入的報告來源 |
| 滲透測試 | 經授權的人工測試，模擬攻擊者找出可以實際利用的漏洞，結果通常整理成 PDF 報告 | 階段 5 從 PDF 擷取弱點 |
| ZAP | 開源的 Web 應用程式掃描工具，對執行中的網站送出請求找弱點。baseline scan 是它的快速模式，只爬網站、觀察回應，不主動送攻擊請求 | 階段 4 掃 Juice Shop、DVWA |
| Trivy | 開源的掃描工具，找出 container image 與相依套件裡的已知 CVE | 階段 3、4 掃自己的 Docker image |
| Semgrep | 開源的原始碼靜態分析工具，用規則比對程式碼裡有風險的寫法 | 總覽提到的常見報告格式；作品實際匯入的是 ZAP、Trivy 與滲透測試 PDF |
| OWASP Juice Shop | OWASP 做的練習用網站，刻意放了各種漏洞 | 自己架的掃描目標 |
| DVWA（Damn Vulnerable Web Application） | 刻意做成有漏洞的 PHP 網站，用來練習 | 自己架的掃描目標 |
| 授權範圍 | 只能測試自己擁有、或拿到書面授權的系統；掃描別人的系統可能違法 | 教材只掃自己架的靶機與自己的 image |

## 攻擊相關用語

這個作品是防守方工具，只分析、排序與建議修補，不產生下列東西；認得這些名詞是為了看懂報告，以及設計拒絕規則。

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| exploit | 實際利用漏洞的程式或手法 | 要求寫 exploit 的問題，模型要拒絕 |
| PoC（Proof of Concept） | 證明漏洞存在的概念驗證程式。公開 PoC 會降低攻擊門檻，但 KEV 要有實際被利用的證據才收 | 判斷風險的參考 |
| payload | 攻擊時送出的惡意輸入，例如一段 SQL injection 字串 | 要求產生 payload 的問題，模型要拒絕 |
| WAF（Web Application Firewall） | 擋在網站前面、過濾惡意請求的防火牆 | 要求繞過 WAF 的問題，模型要拒絕 |
| 攻擊鏈 | 把多個漏洞串在一起達成目的，例如先拿到登入、再提權 | 延伸功能 F13 |
| prompt injection | 在輸入或資料裡藏指令，讓 LLM 偏離原本的規則。藏在掃描報告、網頁這類外部資料裡的叫間接 prompt injection | 階段 7 的測試；`run_sql` 用資料庫權限防護也是為了這個 |

## 資料管線

| 名詞 | 是什麼 | 教材裡用在 |
| --- | --- | --- |
| ETL（Extract、Transform、Load） | 把外部資料抓進自己資料庫的三個步驟：擷取原始資料、轉換成自己要的格式、載入資料庫 | `scripts/etl.py`；帳號 `vuln_etl` |
| 增量更新 | 只抓上次更新之後有變動的資料，不每次全部重抓 | NVD 依「最後修改時間」只抓變更 |
| watermark | 增量更新的起點，記錄上次成功抓到哪個時間點 | `etl_runs.watermark` |
