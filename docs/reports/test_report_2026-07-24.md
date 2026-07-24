# Test Report — 2026-07-24

**Scope**: fail-closed / circuit-breaker 修正(`src/pipeline.py`)+ dead config 移除(`src/config.py`, `config.yaml`)+ `/_guard/health` 觀測性(`src/gateway.py`)+ 前置 P1 快修(`pyproject.toml` 版本、`docs/flow/system_flow.md` 資料集)。變更層級:小修正 → 要求 Unit + integration for touched code。

## Execution summary

| | Count |
|---|---|
| Total | 178 |
| Passed | **175** |
| Failed | 0 |
| Skipped | 3 |

指令:`pytest tests/unit tests/integration/test_gateway.py tests/stress tests/security --ignore=tests/unit/test_classifier.py --ignore=tests/unit/test_data_loader.py`(`.venv-dev` 離線環境)。

**排除說明(非失敗)**:`test_classifier.py` / `test_data_loader.py` / `test_api.py` / `test_detector.py` 依賴 numpy/ML stack,依 OVERVIEW 設計僅在 Docker 真 ML 環境執行(`.venv-dev` 為純邏輯快測環境)。本次變更未觸及 ML 偵測路徑(`detector.py`/`classifier.py`/`embedder.py`/`api.py` 皆未改),故不影響驗證有效性。**3 skipped** = security 掃描測試在工具缺席時 self-skip(`tests/security`)。

## Coverage(light suite)

| Module | Coverage |
|---|---|
| `src/pipeline.py`(主要變更) | **99%**(僅 line 58 未覆蓋 = 既有 consumption build 分支,與本變更無關) |
| `src/gateway.py`(健康端點) | 91% |
| `src/config.py` | 94% |
| `src/schema.py` / `owasp_gaps.py` / guards(rule/output/sysprompt/consumption) | 97–100% |
| Total(light,ML 模組計 0% 因未執行) | 73% |

## Touched-code test breakdown

**Unit — `tests/unit/test_pipeline.py`**（改 1、新增 2）
- `test_circuit_breaker_trips_after_threshold` — 改:斷言 trip 後 `tripped_guards()` 正確回報(移除舊 bug 的「tripped→PASS」斷言)。
- `test_tripped_fail_closed_guard_keeps_blocking` — 新:tripped 的 fail-closed guard 仍回 **BLOCK**,reason 含 `circuit tripped (fail-closed)`。這是本次修正的核心回歸保護。
- `test_tripped_fail_open_guard_passes` — 新:tripped 的 fail-open guard 回 PASS(確認不回歸)。

**Integration — `tests/integration/test_gateway.py`**（改 1）
- `test_management_endpoints` — 改:`/_guard/health` 現回 `{"status":"ok","tripped_guards":[]}`,斷言更新。

其餘 172 項既有測試全通過,確認 config 欄位移除與 pipeline 重構未波及其他模組。

## Failures fixed during run
無。首次執行即全綠(排除 ML-only 模組後)。

## Stress
本次未跑 stress 層(非 release/效能變更)。既有 stress 測試(`tests/stress`,3 項)在本次 light 套件中一併通過,無新測量數據產生,故不列效能數字。
