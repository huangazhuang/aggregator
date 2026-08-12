# GMGN V2 影子验收与入口迁移实施计划

## 1. Gate 0：代码完成

1. 汇总 C1–C6 完成记录和 schema/policy/runtime、`identity_epoch`、`identity_key_version`。
2. 运行全套离线、组件、workflow contract 和 Linux Mihomo 门禁。
3. 保存 `clash-cn-output`、`clash-cn-gmgn-output`、`clash-cn-gmgn-v2-shadow` refs/hash。
4. 断言 V2 自动模式 off，旧推荐入口和 gstatic 自动任务未改变。

## 2. Gate 1：单次真实 shadow

1. 选择一个新鲜 candidate profile SHA，保存 candidate 三件套 hash。
2. 手动触发 V2 shadow，并等待 CNB 完成。
3. 运行 `validate_public_outputs run`，核对 20/4/900 秒、有效性、选择、十组、history、bundle 和 remote Mihomo。
4. 比较 before/after refs，确认只允许 V2 shadow 变化。
5. 运行一次受控失败注入，确认 last-good 不变。
6. 通过后以单独变更把自动模式设为 shadow。

## 3. Gate 2：连续三次 accepted shadow

1. 收集三个不同 source SHA 的 accepted evidence，相邻至少 21600 秒。
2. 每次分别检查 policy/schema/runtime、`identity_epoch`、`identity_key_version` 完全一致；任一变化即重置序列。
3. 运行 `validate_public_outputs series`。
4. 执行 deterministic history canary/replay，证明 bad1→bad2→bad3/remove→recover。
5. 生成迁移候选报告；停止，不执行正式迁移。

## 4. Gate 3：用户批准后的迁移

1. 等待用户在迁移报告之后明确批准。
2. 再次记录三个受保护分支 refs/hash。
3. 将最后 accepted V2 exact bundle 提升至 `clash-cn-gmgn-output`，不重新测速/选择/渲染。
4. 运行 `validate_public_outputs migration` 并执行固定 Mihomo。
5. 更新 `CNB_SETUP.md`、`CLASH_VERGE_AUTO.md` 推荐入口和三类订阅说明。
6. 保持 gstatic profile hash，发布 frozen/legacy metadata，停止自动 trigger/schedule，保留手动恢复。
7. 远端验证 GMGN 正式、gstatic frozen 和旧 URL；执行回滚演练。

## 5. 验证命令

证据根目录：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-v2-rollout'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:PYTHONPATH = (Get-Location).Path

python -m unittest discover -s tests -v
python -m unittest tests.test_publication_transaction -v
python -m unittest tests.test_validate_public_outputs -v
python -m unittest discover -s tests -p 'test_workflow_contracts.py' -v
git diff --check -- .github/workflows .cnb.yml scripts subscribe tests CNB_SETUP.md CLASH_VERGE_AUTO.md
```

保存 refs：

```powershell
$Evidence = Join-Path $TaskTemp 'live'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
git ls-remote https://cnb.cool/ASD12321_446/aggregator.git `
  refs/heads/clash-cn-output `
  refs/heads/clash-cn-gmgn-output `
  refs/heads/clash-cn-gmgn-v2-shadow |
  Tee-Object -FilePath (Join-Path $Evidence 'before-refs.txt')
```

单次影子（C5 实现接口后）：

```powershell
gh workflow run sync-cnb.yml --ref main `
  -f trigger_gmgn_v2_shadow=true `
  -f source_profile_sha='<FULL_PROFILE_SHA256>'

python -m scripts.validate_public_outputs run `
  --expected-source-sha '<FULL_PROFILE_SHA256>' `
  --expected-mode shadow `
  --minimum-observation-window-seconds 900 `
  --evidence-dir (Join-Path $Evidence '<RUN_ID>')
```

连续三次：

```powershell
python -m scripts.validate_public_outputs series `
  --evidence-root $Evidence `
  --required-valid-runs 3 `
  --require-distinct-source-sha `
  --min-spacing-seconds 21600 `
  --require-same-policy-version `
  --require-same-runtime `
  --require-history-canary
```

用户批准并迁移后：

```powershell
python -m scripts.validate_public_outputs migration `
  --gmgn-status 'https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/status.json' `
  --gmgn-profile 'https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/clash.yaml' `
  --legacy-status 'https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-output/status.json' `
  --expected-bundle-hash '<LAST_ACCEPTED_V2_BUNDLE_HASH>' `
  --expect-legacy-frozen `
  --evidence-dir (Join-Path $Evidence 'migration')
```

## 6. Review Gate

- [ ] 每道 gate 的 evidence、允许变化 refs 和禁止变化 refs 均明确。
- [ ] 单次通过前自动模式 off；三次通过前正式/文档/gstatic 不变。
- [ ] 三次序列使用 distinct SHA、21600 秒间隔、相同 policy/runtime；invalid/retry/rejected 不计数。
- [ ] 用户批准发生在迁移报告之后，并有明确记录。
- [ ] promotion 使用 exact accepted bundle，不重新测速或渲染。
- [ ] gstatic profile/URL 保留、状态 frozen、自动任务停止、手动恢复可执行。
- [ ] 所有临时/live 证据位于 `D:\xiangmu\linshi`，公开内容无敏感信息。

## 7. 回滚点

- Gate 0 失败：停留代码阶段，不运行 live。
- Gate 1 失败：自动模式保持 off，旧默认不变。
- Gate 2 失败或版本变化：重置三次计数，必要时模式切回 off，保留诊断。
- 用户不批准：保持 V2 shadow，不迁移、不冻结 gstatic。
- Gate 3 失败：使用记录的 refs/hash 以 lease 恢复正式 GMGN 和推荐文档；按需恢复 gstatic schedule，所有分支/URL保留。
