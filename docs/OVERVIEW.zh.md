# 專案總覽 — Prompt Injection Detector & LLM Guard Gateway

> Language: [English](OVERVIEW.md) · **繁體中文**

本文件說明這個專案是什麼、刻意涵蓋與刻意不涵蓋哪些範圍、如何建構,以及主要設計選擇背後的理由。這是專案範圍的權威參考文件。

## 這是什麼

同一套程式碼裡的兩個元件:

1. **Prompt Injection Detector(注入偵測器)** — 以 embedding 為基礎的分類器,對單一段文字評估其 prompt injection 意圖。它把三個獨立層合成一個 ensemble 分數:keyword/regex 規則引擎、sentence-transformer embedding 餵給 LogisticRegression 分類器、以及對已知攻擊語料做 cosine 相似度搜尋。對外提供 `POST /detect` API。

2. **LLM Guard Gateway(v1.0)** — 一個離線反向代理,擋在任意 AI 服務前。每個 request 與 response 都會通過一組 guard,每個 guard 對應一項 OWASP LLM Top 10(2025)類別。Gateway 採 fail-closed:若某個 guard 出錯,預設是 block 而非放行。上面那個偵測器就是 LLM01 guard 背後的引擎。

本專案是防禦工具。它源自實際的攻擊練習(Lakera Gandalf、red-team writeup),再把這些經驗重新框定為 runtime 控制。

## 範圍

### 涵蓋範圍

- 對 request/response 文字做 runtime 檢查,涵蓋在單一 request/response 中可觀察到的 OWASP LLM 類別(見覆蓋矩陣)。
- 單段文字的 prompt injection 偵測,提供可解釋、逐層的分數。
- 直接套用的反向代理,被保護的上游服務無需改動任何程式碼。
- 完全離線運作:唯一的對外呼叫是轉發給設定的上游服務。偵測使用本地 embedding 模型與本地規則,不呼叫任何第三方 LLM 或 API。

### 明確不涵蓋範圍

- **Indirect Prompt Injection(IPI)防禦。** 防禦 IPI 需要在 RAG/agent pipeline 中依信任來源標記內容,那是架構層級的控制,不是單段文字偵測器或 request/response 代理看得到的。IPI 由另一個專案處理。
- **Build-time 與 training-time 風險**(LLM03 Supply Chain、LLM04 Data & Model Poisoning)。單一 request 不會揭露被污染的資料集或被入侵的相依套件。這些以 runtime gap 明確登記,各自指向真正對應的控制(CI 相依掃描、SBOM、資料來源治理)。
- **檢索/向量庫弱點**(LLM08)。這些存在於檢索語料與存取模型中,不在被代理的流量裡。
- **多輪 / session 層級攻擊**(many-shot、crescendo、context drift)。偵測器是單輪的;session 監控屬未來工作。
- **對抗性後綴(adversarial-suffix)強健性。** GCG 式後綴可找出「不相似但有效」的 payload 繞過 embedding 偵測。這是已知弱點,不是已解決的問題。

## 架構

### 偵測器(三層 ensemble)

```
輸入文字
   ├─► 規則引擎        keyword + regex,6 類
   ├─► Embedder        nomic-embed-text-v1.5(768 維),MiniLM fallback
   │      ├─► 分類器        LogisticRegression P(injection)
   │      └─► 相似度搜尋    cosine vs 已知攻擊語料
   ▼
Ensemble 分數 = 0.30·規則 + 0.50·分類器 + 0.20·相似度
```

每一層都獨立,所以某一層失效或信心不足不會讓其他層失明,而 response 會帶上逐層分數以供解釋。

### Gateway(反向代理 + guards)

Gateway 在 inbound guard 通過後把流量轉發給 `upstream_url`,並在回傳前檢查 response。它有三種模式 — `block`(預設,fail-closed)、`monitor`(僅記錄,用於門檻調校)、`redact`(擋下 inbound 攻擊、遮罩 outbound 洩漏)— 並為每個被標記的 request 寫入稽核軌跡(JSONL + SQLite)。Guard 是 `src/guards/` 下的獨立模組;每個各自宣告自己的 fail 模式,由 gateway 依嚴重度彙整各 guard 的判定。

## OWASP LLM Top 10(2025)覆蓋

七項類別由專屬 guard 在 runtime 防禦;三項超出 runtime 代理可及範圍,以明確 gap 登記(在 `src/owasp_gaps.py`、啟動 log 與 `/owasp` endpoint),而非默默略過。

| OWASP | 類別 | 狀態 | 位置 |
|-------|------|------|------|
| LLM01 | Prompt Injection | 覆蓋 | `injection_guard` + ensemble 偵測器 |
| LLM02 | Sensitive Information Disclosure | 覆蓋 | `secret_guard`(block 或 redact) |
| LLM03 | Supply Chain | 已登記 gap | build-time — CI 掃描 / SBOM / pinned hash |
| LLM04 | Data & Model Poisoning | 已登記 gap | training-time — 資料來源 / 簽章 |
| LLM05 | Improper Output Handling | 覆蓋 | `output_guard`(含 SSRF pattern) |
| LLM06 | Excessive Agency | 覆蓋 | `agency_guard` |
| LLM07 | System Prompt Leakage | 覆蓋 | `sysprompt_guard` |
| LLM08 | Vector & Embedding Weaknesses | 已登記 gap | 檢索架構 — per-tenant 隔離 |
| LLM09 | Misinformation | 部分 | `misinfo_guard` |
| LLM10 | Unbounded Consumption | 覆蓋 | `consumption_guard`(rate + 併發 + 大小) |

對這三個 gap 保持誠實是刻意的:一個宣稱完整覆蓋 Top 10 的 runtime 代理,會誤述 request/response 檢查器實際能看見什麼。

## 偵測器效能(v0.1.0 benchmark)

**僅 classifier 單層**,在分布內(in-distribution)測試集上:

| 指標 | 數值 | MVP 目標 |
|------|------|----------|
| Accuracy | 0.9844 | — |
| Precision | 0.9657 | ≥ 0.85 |
| Recall | 0.9741 | ≥ 0.75 |
| F1 | 0.9699 | ≥ 0.80 |
| AUC | 0.9989 | ≥ 0.90 |

Train/test 切分 5385 / 1347。`scripts/train.py` 評的是 classifier 的預測,**不是**服務實際跑的三層 ensemble —— 兩者不可互換。完整 ensemble 在同一切分上是 F1 0.9723(`scripts/eval_ood.py --in-dist`)。

這些是分布內數字。對於模型沒見過的資料會發生什麼,見下方「已知限制」第 1 條與 `docs/reports/ood_benchmark_2026-07-28.md` —— 簡短版是:在 shipped threshold 下 recall 掉到 0.198。

## 資料集與訓練

6,732 筆樣本,整合自五個公開來源:Lakera(1,000)、AdvBench(520)、JailbreakBench(200)、Databricks Dolly 15k(5,000 筆良性負樣本),以及 12 筆由作者親手驗證的 Gandalf 攻擊 prompt。那 12 筆標記為 `author_validated=True`,涵蓋在 Lakera Gandalf 第 1–7 關親身觀察到的 12 個攻擊家族。所有訓練資料皆來自公開語料;未使用任何私人或正式環境資料。

另外三個公開來源登記為 **holdout(保留集)**,永遠不進訓練(`src/data_loader.py` 的 `HOLDOUT_LOADERS`):deepset/prompt-injections、tatsu-lab/alpaca、allenai/wildjailbreak。它們的存在是讓 `scripts/eval_ood.py` 能對模型沒看過的資料量測泛化能力。良性 holdout 刻意不沿用 Dolly —— Dolly 佔了 6,732 筆訓練樣本中的 5,000 筆,拿它量 OOD 誤報等於什麼都沒量。

所有 HuggingFace 資料集皆 pin 在固定 revision。未 pin 的資料集會在腳下改變,同時破壞兩件事:訓練語料與已產出的模型 artifact 不再對應,以及 benchmark 數字失去可重現性。

## 技術棧

Python 3.10+、FastAPI/Uvicorn、sentence-transformers(nomic-embed-text-v1.5)、scikit-learn、Pydantic v2、NumPy/pandas、httpx、PyYAML。以 Docker / docker-compose 容器化。CI 式安全檢查:Bandit(SAST)、detect-secrets、pip-audit。

## 測試

222 個測試函式,分佈於各層:187 unit、18 integration、3 stress、3 security(security 層會外呼 Bandit / detect-secrets / pip-audit,單獨執行;其餘 219 個一次跑完)。Unit 與 integration 涵蓋 schema、loader、規則引擎、各 guard、pipeline 以及 gateway 彙整邏輯;security 層跑 Bandit / detect-secrets / pip-audit。完整的 ML 測試在 Docker 內執行(偵測器與 embedder 需要模型權重);純邏輯子集則在不含重量級 ML 相依的隔離 venv 執行。

## 已知限制

1. **已量測的 out-of-distribution 弱點。** 在 holdout 攻擊集上,shipped threshold(0.50)下 recall 只剩 0.198,對比分布內的 0.960;對沒見過的良性文字,誤報率從 0.5% 升到 3.8%。AUC 仍維持 0.838,代表排序能力還在,**主要是門檻校準問題而非看不懂**。similarity 層對「沒見過的攻擊 vs 沒見過的良性」只差 0.054,撐不起它在 ensemble 中 20% 的權重。完整數字、注意事項與單一來源的限制:`docs/reports/ood_benchmark_2026-07-28.md`。
2. 僅以英文驗證;embedder 為多語但未針對其他語言的注入驗證過。
3. 無 IPI 防禦(不在範圍,見上)。
4. GCG 式對抗性後綴可繞過 embedding 偵測。
5. 僅單輪;多輪攻擊需要 session 層級監控。
6. 模型檔用 `pickle`(僅限可信來源);後續版本將改用 `joblib`。

## 如何執行

```bash
docker compose build
docker compose run --rm app bash scripts/download_data.sh   # 公開資料集
docker compose run --rm app python scripts/build_dataset.py # 整合為 JSONL
docker compose run --rm app python scripts/train.py         # 訓練 + benchmark
docker compose run --rm app pytest                          # 完整測試
docker compose up api                                       # 在 :8000 提供 /detect
```

Gateway 以自己的服務執行(預設 port 33707、`block` 模式、fail-closed),轉發給設定的 `upstream_url`;所有設定都在 `config.yaml`,可用 `GUARD_*` 環境變數覆寫。

### 不使用 Docker

Docker 是官方支援的路徑,但整套工具鏈也能在本機 virtualenv 跑 —— 在 Docker Desktop 沒開 WSL integration 的環境很有用。2026-07-28 的 OOD benchmark 就是這樣跑出來的。

```bash
python -m venv .venv-dev
.venv-dev/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch  # CPU 版,避免拉 CUDA
.venv-dev/bin/pip install -e ".[dev]"
.venv-dev/bin/python scripts/eval_ood.py --in-dist --sources deepset_pi alpaca_negative
.venv-dev/bin/python -m pytest tests/ --ignore=tests/security
```

兩個注意事項:若資料集當初是透過 Docker 下載,`data/raw/` 可能屬於 root —— 改傳不同的 `cache_dir` 比跟權限硬碰硬容易。另外 security 層會外呼 Bandit / detect-secrets / pip-audit,那些要另外安裝。

在 WSL 上,即使 Docker Desktop 的整合已啟用,`docker` 仍可能回 `Input/output error` —— 那是 ISO 掛載過期,不是設定錯誤。診斷與 `docker.exe` 的繞法見 `docs/issues/ISSUE_002.md`。

## 設計理由

- **離線優先。** 一個要打電話給第三方 API 判斷安全性的 guard,等於新增一個相依與一條資料外流路徑。偵測在本地執行,所以工具可以擋在敏感服務前而不擴大信任邊界。
- **Fail-closed。** 一個 fail-open 的安全控制比沒有還糟,因為它製造虛假信心。Guard 出錯預設視為 block。
- **反向代理,而非函式庫。** 上游服務無需改動任何程式碼,使 gateway 能部署在既有系統前。
- **明確 gap 勝過默默覆蓋。** 三個 runtime 無法偵測的 OWASP 類別被明確宣告並導向正確的控制,因此工具的覆蓋範圍不會被誇大。
