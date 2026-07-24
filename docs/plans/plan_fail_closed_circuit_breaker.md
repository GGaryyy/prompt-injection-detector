# Plan — 修正 fail-closed 與 circuit breaker 的矛盾

> 狀態:**✅ 已執行完成**(2026-07-24;175 測試綠、bandit 0 高危、reviewer Approved with Notes)| 決策:**A. 嚴格 fail-closed** | 範圍:`src/pipeline.py`(主)、`src/config.py`、`config.yaml`、`src/gateway.py`(健康端點)、`tests/unit/test_pipeline.py`、docs
>
> 前置(本次 session 已完成):P1 快修 — pyproject 版本 `0.0.1`→`1.0.0`、`system_flow.md` 資料集修正、committed 垃圾查證無誤。本 plan 為 P1 唯一剩餘的 code 改動。

## 1. Context / 問題

`GuardPipeline` 宣稱核心安全性質是 **fail-closed**(`pipeline.py:3-6` docstring、`config` 預設 `fail_mode="closed"`)。但 circuit breaker 破壞了這個保證:

- guard 連續錯 `CIRCUIT_TRIP_THRESHOLD=5` 次 → 加入 `self._tripped`(`pipeline.py:92-94`)。
- 之後 `run()` 對 tripped guard 直接 `continue` 跳過(`pipeline.py:77-78`)→ 該 guard **不再產生 verdict**。
- 對 `fail_mode="closed"` 的 guard:trip 前會 BLOCK,trip 後變**靜默放行**。docstring line 6 自承 "switching it to monitor"。
- 極端情況:所有 guard 都 tripped → `verdicts` 為空 → `_aggregate` 回 `PASS`(`pipeline.py:113-119`)→ gateway 全開。

**根因一句話**:circuit breaker 覆蓋了 guard 的 `fail_mode`,把 fail-closed 的 guard 在故障持續時翻成 fail-open。

附帶問題:gateway 級 `GatewayConfig.fail_mode`(`config.py:54`)載入但**無人讀取**(dead config;只有 per-guard `gc.fail_mode` 在 `pipeline.py:64` 被用)。

## 2. 設計原則(修正方向)

把兩個概念**解耦**:

- **Circuit breaker 的職責** = 停止「呼叫」一個持續故障的 guard 的 `check()`(省算力、止 log 洗版)。它**不該**決定安全語意。
- **`fail_mode` 的職責** = 決定 guard 無法給出正常判斷時的 verdict。這個語意對「錯誤中」與「已 tripped」必須**一致**:
  - `fail_mode="closed"` 的 tripped guard → 持續回 **BLOCK**(維持 fail-closed)。
  - `fail_mode="open"` 的 tripped guard → 回 **PASS**。

如此 tripped guard 仍會貢獻 verdict,`verdicts` 不會因 trip 而變空→誤判 PASS 的路徑自然消失。

## 3. 決策(已定):A 嚴格 fail-closed

修正後,一個 `fail_mode="closed"` 的關鍵 guard 若持續故障,會**擋掉全部流量(403)**直到修復。這是「真 fail-closed」的正確代價 —— 安全工具寧可自我 DoS 也不靜默放行。可用性代價由 operator 針對個別 guard 用 `fail_mode="open"` 自行承擔。

配套:dead 的 gateway 級 `GatewayConfig.fail_mode` **移除**(per-guard fail_mode 已完整涵蓋語意,gateway 級為冗餘)。

## 4. Steps(A 定案)

1. `src/pipeline.py::run`(`pipeline.py:74-80`)— tripped guard 不再 `continue` 跳過;改呼叫新的 `_tripped_verdict(guard, ctx)`,依 `guard.fail_mode` 回 BLOCK(closed)/PASS(open),reason 標 `circuit tripped (fail-closed|fail-open)`。新增 `tripped_guards()` 供健康端點查詢。
2. `src/pipeline.py` — 抽共用 `_failure_verdict(guard, ctx, start, reason, detail)`(依 fail_mode 建 verdict),供 `_run_one`(錯誤路徑)與 `_tripped_verdict`(tripped 路徑)共用,消除重複。`_run_one` 前 5 次錯誤邏輯與 trip 判定不變。
3. `src/pipeline.py::_aggregate`(`pipeline.py:113-119`)— 空 `verdicts` 的 PASS fallback 保留作防禦,加註:closed-guard 恆貢獻 verdict,不再靜默走到此 PASS。
4. docstring(`pipeline.py:3-7`)— 移除 "switching it to monitor",改述「breaker 只停呼叫、fail_mode 仍強制」。
5. 移除 dead config:`GatewayConfig.fail_mode`(`config.py:54`)+ `config.yaml:20-22`(含誤導註解)。**注意**:`FailMode` import 仍被 `GuardConfig.fail_mode`(`config.py:30`)使用,勿刪 import。
6. `src/gateway.py::health`(`gateway.py:70-72`)— 回傳 `tripped_guards`(從 pipeline),讓降級可觀測、不再靜默。
7. docs 同步:`docs/OVERVIEW.md`(若述及 breaker 行為)、`docs/interview_prep_side_projects.md` 的 Q1(升級成 trade-off 論述)、`docs/changelog/CHANGELOG.md`。

## 5. Error handling / 邊界

- tripped guard 仍需計 `latency_ms`(直接算,不呼叫 check)。
- `fail_mode="open"` 的 guard trip 後回 PASS,行為與現況相同(不回歸)。
- `monitor` / `redact` gateway mode:tripped closed-guard 的 BLOCK 會照 `_apply_mode` 被降級(monitor→FLAG),符合既有語意,不特例。
- 確認 `consumption` guard(rate-limit)tripped 時的 BLOCK 不會與正常 429 語意衝突(它目前回 BLOCK→403,一致)。

## 6. 驗證

- **改測試**:`tests/unit/test_pipeline.py` 目前斷言「once tripped… pass」(編碼了舊 bug)。改為:
  - tripped `fail_mode="closed"` guard → 聚合結果仍 BLOCK。
  - tripped `fail_mode="open"` guard → PASS(回歸保護)。
  - 新增:所有 closed-guard tripped 時,gateway 不會回 PASS。
- **新增測試**:`/_guard/health` 回傳 tripped 清單(step 6)。
- 跑 `pytest tests/unit/test_pipeline.py -v` 全綠;再跑整包輕量 unit(不需 Docker/ML)。
- `bandit -r src/` 0 高危;版本/行為變更記入 `docs/changelog/CHANGELOG.md`。
- 依 `testing-and-reports` skill 產出對應 report。

## 7. 面試附帶收穫

修完後 Q1(fail-closed vs breaker)的答法從「這是已知 bug」升級為:「breaker 只停止呼叫故障 guard 以保護算力,但 fail_mode 語意在錯誤與 tripped 之間一致 —— 我把可用性與安全兩個關注點解耦了。」這正是面試想聽的 trade-off 論述。同步更新 `docs/interview_prep_side_projects.md` 的 Q1。
