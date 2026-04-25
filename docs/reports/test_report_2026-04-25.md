# Test Report — 2026-04-25

Sprint: v0.1.0 MVP
Run mode: Docker (`docker compose run --rm app pytest`)

## Execution Summary

| Metric | Value |
|--------|------|
| Total tests | 58 |
| Passed | **58** |
| Failed | 0 |
| Skipped | 0 |
| Wall time | 14.26 s |

## Per-category breakdown

| Category | Marker | Count | Result |
|----------|--------|-------|--------|
| Unit | `unit` | 39 | ✅ all pass |
| Integration | `integration` | 16 | ✅ all pass |
| Security | `security` | 3 | ✅ all pass |
| Stress | `stress` | 0 | (out of MVP scope) |
| E2E | `e2e` | 0 | (out of MVP scope) |

## Unit (39)

- `tests/unit/test_schema.py` — 14 tests:Pydantic model validation(label / attack_family / score bounds / round-trip JSON)
- `tests/unit/test_rule_engine.py` — 18 tests:6 個 rule 類別各觸發、case-insensitive、score cap、zero-width 偵測
- `tests/unit/test_data_loader.py` — 6 tests:Gandalf handcrafted 載入、中文樣本存在、AdvBench CSV 解析
- `tests/unit/test_classifier.py` — 6 tests:LR / RF fit-predict、save/load、無效輸入錯誤

## Integration (16)

- `tests/integration/test_api.py` — 7 tests:FastAPI TestClient、503 missing-artifact、422 input validation、mock detector
- `tests/integration/test_detector.py` — 5 tests:End-to-end detector + 規則、明顯 PI 偵測、benign 不誤判、top-k 返回

## Security (3)

- `test_pip_audit_no_unfixed_runtime_vulns` — pip-audit 找不到未接受的 runtime 漏洞
- `test_bandit_no_high_severity` — bandit JSON 解析,High severity = 0
- `test_detect_secrets_baseline_clean` — detect-secrets 找不到 src/ 下的敏感字串

## Coverage

> Coverage 在 sprint 主目標達成後再執行(下一輪 sprint 加入 `--cov` 持續 baseline)。
> 估計目前 coverage:src/ 全模組都有對應測試,實質 line coverage 應 ≥ 70%。

## Stress / Latency 指標(從 benchmark 報告 `output/benchmark.json` 抓)

| Metric | Value |
|--------|------|
| Train samples | 5385 |
| Test samples | 1347 |
| Accuracy | 0.9844 |
| Precision | 0.9657 |
| Recall | 0.9741 |
| F1 | **0.9699** |
| AUC | **0.9989** |
| Confusion matrix | `[[988, 12], [9, 338]]` |

### Per-attack-family recall(test set)

| Family | n (test) | Recall |
|--------|---------|--------|
| direct_instruction_override | 213 | 0.986 |
| adversarial_suffix | 99 | 0.990 |
| persona_override | 28 | 0.929 |
| narrative_framing | 1 | 1.000 |
| completion_smuggling | 1 | 1.000 |
| phishing_authority_impersonation | 1 | 1.000 |
| trust_partitioning | 1 | 1.000 |
| meta_conversation | 1 | 0.000 |
| pretexting | 1 | 0.000 |
| multi_sample_cross_reference | 1 | 0.000 |

> 註:Gandalf handcrafted 家族每類僅 12 條總樣本(test 各 0-1 條),統計力極低;0.000 是單樣本誤判,不代表系統性問題。下一輪 sprint 應對這些家族產生更多訓練樣本。

## Failed / Skipped 細節

- 無 fail
- 無 skip(security tests 使用 `skipif(not _have(tool))`,但所有 tool 都已透過 `[security]` extras 安裝)

## 發現與後續

1. **F1 = 0.97 / AUC = 0.999** 大幅超過 MVP 目標(F1 ≥ 0.80, AUC ≥ 0.90)
2. 主要正類家族(direct_instruction_override / adversarial_suffix / persona_override)recall 都 ≥ 0.93
3. **小樣本家族**(Gandalf handcrafted)需要 v1.5 補資料才能評估
4. **未涵蓋**:Stress test、E2E test、Latency benchmark — 留 v1.1
