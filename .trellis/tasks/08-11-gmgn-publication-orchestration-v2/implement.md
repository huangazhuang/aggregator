# GMGN 事务发布触发与远端校验实施计划

## 1. 实施顺序

1. **冻结 bundle 和 validator schema**
   - 与 C1–C4 fixture 对齐 run/source/main/policy/runtime、`identity_epoch` 与 `identity_key_version` 字段。
   - 定义非递归 bundle hash、逐文件 hash、branch-neutral status、last-5 index、public allowlist 和 previous-state validator。
2. **实现事务纯函数**
   - 建议新增 `scripts/publish_transaction.py`：previous load、bundle build、CAS plan、rollback plan。
   - 修改 `scripts/cnb_gmgn_publish.py` 只输出已验证 bundle 输入，不直接裸推分支。
3. **实现远端 validator**
   - 建议新增 `scripts/validate_public_outputs.py`，提供 `run/series/migration`。
   - 使用可 mock HTTP fetch、nonce/no-cache、exact commit/hash 和固定 Mihomo 校验。
4. **集成 staging/lease 发布**
   - 保存 observed tip，推 staging，remote smoke，再 lease 提升 shadow。
   - 实现 post-promotion smoke 和 previous commit lease rollback。
5. **实现 SHA 幂等触发**
   - GitHub candidate remote smoke 后发完整 SHA trigger。
   - CNB registry/lock 区分 queued/running/failed/accepted 和 retry_of。
   - 保持自动模式 off，仅允许手动 source SHA。
6. **工作流与安全集成**
   - `.cnb.yml` 由本任务唯一修改。
   - 在每个 probe 分片的 Mihomo 启动前配置并调用 C2 network guard；记录 backend/policy version，guard 缺失、规则未生效或 DNS 固定漂移时失败关闭。
   - C1 完成后接手 `.github/workflows/clash-verge-auto.yml` 触发尾段；修改 `sync-cnb.yml`/`tests.yml`。
   - 保持 token、private fragment、分支 allowlist 和 failStages 隔离。
7. **失败注入与组件测试**
   - previous 网络错误、坏 state、缺片、Mihomo invalid、staging/promotion push 失败、CAS 冲突、旧缓存、rollback 失败。

## 2. 文件所有权

- `.cnb.yml`：本任务最终唯一 owner；C2–C4 不得并行改。
- `.github/workflows/clash-verge-auto.yml`：仅在 C1 完成后修改 trigger 尾段，不回退 C1 的 candidate 发布改动。
- `.github/workflows/sync-cnb.yml`、`.github/workflows/tests.yml`：本任务 owner。
- `scripts/cnb_gmgn_publish.py`：消费 C3/C4 已冻结接口，冲突时协调 schema，不还原其他实现。
- 建议新增 `scripts/publish_transaction.py`、`scripts/validate_public_outputs.py` 及 publication/workflow tests。

## 3. 验证命令

所有本机证据和临时文件写入 `D:\xiangmu\linshi\gmgn-publication-orchestration-v2`：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-publication-orchestration-v2'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_publication_transaction -v
python -m unittest tests.test_validate_public_outputs -v
python -m unittest tests.test_cnb_gmgn_publish -v
python -m unittest tests.test_cnb_gmgn_shadow -v
python -m unittest discover -s tests -p 'test_workflow_contracts.py' -v
python -m unittest discover -s tests -p 'test_gmgn_component_pipeline.py' -v
python -m unittest discover -s tests -v
git diff --check -- .github/workflows .cnb.yml scripts tests
```

Linux/CNB 额外门禁：

```bash
sha256sum clash/clash-linux-amd
clash/clash-linux-amd -v
clash/clash-linux-amd -t -d "$RUNNER_TEMP/gmgn-v2-remote" -f "$RUNNER_TEMP/gmgn-v2-remote/clash.yaml"
```

离线 CLI fixture：

```powershell
python -m scripts.validate_public_outputs run --help
python -m scripts.validate_public_outputs series --help
python -m scripts.validate_public_outputs migration --help
```

## 4. Review Gate

- [ ] previous absent 与 previous unreadable 的测试走不同分支。
- [ ] staging、authoritative ref、失败诊断和旧输出分支有精确 allowlist。
- [ ] 所有 authoritative push 使用 observed tip lease；不存在裸 `git push --force` 到 V2 shadow。
- [ ] remote smoke 在 promotion 前后执行，下载使用 nonce/no-cache 并运行固定 Mihomo。
- [ ] bundle hash 按移除顶层 `bundle_hash` 的 canonical payload 重算，`bundle.json` 仅承载最终逐文件 hash；不存在自引用或未覆盖 payload。
- [ ] shadow→formal 所需 bundle 文件不含 branch/mode/绝对 URL/promotion time，能够保持字节级一致。
- [ ] accepted history 与 processed SHA 只在最终 smoke 成功后提交一次。
- [ ] validator 独立核对 `identity_epoch` 与 `identity_key_version`，任一缺失/未知都失败关闭。
- [ ] 代码门禁时自动触发仍为 off，旧 gstatic/正式 GMGN/文档未改变。
- [ ] 日志、公开 bundle 和异常消息通过凭据/私有路径扫描。
- [ ] workflow contract 和 Linux 组件测试覆盖 network guard 启动顺序、DNS rebinding、私网/metadata deny 与 guard-unavailable fail-closed。

## 5. 回滚点

- Python 事务/validator 测试不通过：不接 workflow，线上无变化。
- 手动 V2 staging 失败：保留 V2 shadow previous tip，修复后重试同 source SHA，不计 history。
- 自动 trigger 接入异常：关闭/回退 trigger 尾段，保留手动入口。
- lease 或 remote smoke 异常：按 previous commit 回滚 shadow；旧 gstatic/正式 GMGN 始终不动。
- 任何 schema 破坏性变化：提升版本并同步 C1–C4 producer/consumer/fixture，未知版本失败关闭。
