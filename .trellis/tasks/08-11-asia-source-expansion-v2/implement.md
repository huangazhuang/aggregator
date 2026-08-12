# 外部亚洲来源受控扩展实施计划

## 1. 实施顺序

1. **等待 C1/C3 接口冻结**
   - 确认 source registry、source-health、candidate metadata 和 identity API。
   - 不在本任务复制 fingerprint、地区识别或发布门禁。
2. **实现共享评估器**
   - 建议新增 `scripts/evaluate_asia_sources.py` 或等价模块。
   - 评估器与生产解析共用 allowlist、identity 和 endpoint 计算。
3. **评估优先来源**
   - 在 `D:\xiangmu\linshi\asia-source-expansion-v2` 生成 awesome-vpn 报告。
   - 若未满足门禁，生成 Mahdibland 限额亚洲子集报告。
4. **实现 registry、限额和 feature flag**
   - 修改 `scripts/build_crawler_config.py` 与 C1 的 source 配置/health 接口。
   - 应用 300/source、100/region、3/endpoint 和 `<5000` 容量保护。
5. **接入第一个合格来源**
   - 合并 provenance，不覆盖已有来源证据。
   - 通过 C1 snapshot/status/remote smoke 后才视为候选接入成功。
6. **失败、恢复和回滚测试**
   - 覆盖 429、timeout、空内容、格式漂移、骤增/骤减、地区归零、安全端点、flag off/on。

## 2. 文件所有权

- 本任务主要 owner：外部 source registry/config、`scripts/build_crawler_config.py` 的新增来源段、评估器和 source-expansion 测试。
- C1 owner 保持 candidate/source-health 核心模块与 `.github/workflows/clash-verge-auto.yml`；本任务通过冻结接口接入，不回退 C1 修改。
- C3 owner 保持 identity/HMAC 模块；本任务只调用。
- 不修改 `.cnb.yml`、GMGN probe/publisher、正式分组或 rollout 文档。

## 3. 验证命令

本机临时目录：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\asia-source-expansion-v2'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_asia_source_expansion -v
python -m unittest discover -s tests -p 'test_candidate_*.py' -v
python -m unittest tests.test_asia_retention -v
python -m unittest discover -s tests -p 'test_candidate_pipeline_component.py' -v
python -m unittest discover -s tests -v
git diff --check -- scripts subscribe tests
```

受控只读评估命令在实现后应支持：

```powershell
python -m scripts.evaluate_asia_sources `
  --source awesome-vpn `
  --current-status-url '<CANDIDATE_STATUS_URL>' `
  --current-profile-url '<CANDIDATE_PROFILE_URL>' `
  --current-metadata-url '<CANDIDATE_METADATA_URL>' `
  --output-dir (Join-Path $TaskTemp 'awesome-vpn')
```

若 awesome-vpn 未过门禁，再以 `--source mahdibland-asia-limited` 运行同一命令。真实下载和报告只写上述专用目录。

## 4. Review Gate

- [ ] 评估器与生产解析共用 C1/C3 owner，不存在第二套 fingerprint 或安全 allowlist。
- [ ] 报告同时给出 raw、exact、endpoint、overlap、五地区、新鲜度和透明度，不用原始行数冒充增益。
- [ ] 数值门禁、裁剪顺序和输入重排均有确定性测试。
- [ ] source failure/恢复经过 C1 last-good，不能用缩水 snapshot 覆盖上一版。
- [ ] candidate snapshot 仍只有 `clash.yaml + status.json + candidate-metadata.json` 三件套。
- [ ] 关闭单一 flag 可回滚，且不删除历史或影响其他来源。
- [ ] 测试/评估临时产物全部位于 `D:\xiangmu\linshi`。

## 5. 回滚点

- 评估未过门禁：保持来源 disabled，不改生产候选。
- 接入后发现格式/安全/容量问题：关闭该 source flag，C1 保留 last-good 并记录停用原因。
- C1/C3 schema 变化：暂停接入，升级 registry/fixture 后重新评估；禁止通过本地兼容猜测继续发布。
- 新来源导致真实 CNB 预算异常：在 C7 影子阶段关闭来源并回到接入前 candidate snapshot，不减少 GMGN 轮数或质量标准。
