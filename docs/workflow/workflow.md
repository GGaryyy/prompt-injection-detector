# Development Workflow

> 流程變更時更新本檔。

## 環境設置(Windows PowerShell)

```powershell
# 1. 建虛擬環境
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. 安裝依賴(含 dev)
pip install -e ".[dev]"

# 3. 下載公開資料集(網路需要)
bash scripts/download_data.sh

# 4. 建構統一 dataset
python scripts/build_dataset.py    # (待實作)

# 5. 訓練分類器
python scripts/train.py            # (待實作)

# 6. 跑測試
pytest

# 7. 啟動 API(本地 dev)
uvicorn src.api:app --reload --host 0.0.0.0 --port 8000
```

## Docker 部署

```bash
# Build
docker build -t pi-detector:dev .

# Run
docker run -p 8000:8000 pi-detector:dev

# 或 docker-compose(待新增 docker-compose.yml)
docker-compose up
```

## 開發循環

```
寫 code (src/<module>.py)
  → 寫測試 (tests/unit/test_<module>.py)
  → pytest
  → 修 fail
  → pytest (再跑全套)
  → 全 pass → 等使用者確認 → commit
```

## 測試類型

依 `pyproject.toml` 設定的 marker 跑:

```bash
pytest -m unit              # 只跑 unit
pytest -m integration       # 只跑 integration
pytest -m "not slow"        # 略過慢測試
pytest --cov                # 含 coverage
```

| Marker | 目錄 | 說明 |
|--------|------|------|
| `unit` | `tests/unit/` | 個別 function / class 隔離測試 |
| `integration` | `tests/integration/` | API + 內部模組整合測試 |
| `stress` | `tests/stress/` | latency / 並發 / 大量資料 |
| `e2e` | `tests/e2e/` | 完整使用者流程 |
| `security` | `tests/security/` | 依賴 CVE、SAST、secret leak |

## 安全掃描

```bash
# 依賴 CVE
pip-audit

# 程式碼 SAST
bandit -r src/

# Secret leak
detect-secrets scan
```

## 報告產生(每個 sprint 結束)

依 CLAUDE.md Part 2「報告流程」:

1. `pytest --cov` 跑全套 → 產生 coverage 數據
2. 安全掃描三項都跑 → 產生 finding 清單
3. 在 `docs/reports/` 產出三份報告:
   - `test_report_YYYY-MM-DD.md`
   - `security_report_YYYY-MM-DD.md`
   - `code_review_YYYY-MM-DD.md`
4. 更新 `docs/changelog/CHANGELOG.md`
5. (使用者確認後)commit

## Sprint 詳細步驟

見 [`../../../docs/plans/plan_prompt_injection_detector.md`](../../../docs/plans/plan_prompt_injection_detector.md) § 5「實作步驟」

## 未來改善

(待實作後填入)
