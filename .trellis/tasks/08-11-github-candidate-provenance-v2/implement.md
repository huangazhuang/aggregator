# GitHub 候选池与 provenance V2 实施计划

## 1. 执行顺序

1. **冻结 fixture 与身份边界**
   - 与 C3 对齐 canonical fingerprint/HMAC API、`candidate_id` 格式、identity key version 和 identity epoch；C1 不编辑 C3 identity owner 文件。
   - 接入 `tests/fixtures/gmgn_identity_v1.json` 非秘密固定向量，冻结 metadata `identity_preflight` 字段。
   - 为 status v2、metadata v2、previous snapshot 和 source-health reducer 建立完整 fixture 与严格字段常量。
2. **来源健康与探索配额**
   - 在 `subscribe/collect.py`、`subscribe/crawl.py` 和必要的共享脚本中实现固定/动态来源统一 health reducer。
   - 实现 48h last-good、3 次成功缺失、6h 间隔与恢复语义。
   - 将机场选择改为 60/20/20 配额并修复 `workflow.exists` 只检查第一项的问题。
3. **安全清洗、identity 接入和 provenance 合并**
   - 在现有 `subscribe/clash.py` 验证之后接入 C3 identity API。
   - 实现精确重复配置的 metadata 合并，确保输入重排、普通/亚洲源重复、同名冲突均确定性。
   - 拒绝不可接受协议/端点；域名解析全部 A/AAAA 并记录安全检查版本/时间，公开字段使用 allowlist。
4. **亚洲提示与检查语义**
   - 在 `subscribe/asia.py` 补安全机场代码和反误判测试。
   - 保持 `apply_tcp_probe.py`、`filter_reachability.py` 的亚洲 bypass，并输出 passed/failed/bypassed 状态。
5. **生成 V2 三件套**
   - 扩展/拆分 `scripts/prepare_github_publish.py`，由同一 staging model 生成 `clash.yaml`、metadata 和 status。
   - 实现 URL/SHA/schema/count/identity key version/identity epoch 和一对一 candidate 映射 validator。
6. **previous 与掉量门禁**
   - 明确区分 confirmed absent 与暂时不可读。
   - 实现总量/亚洲/五地区/来源 quorum 的整数边界与拒绝原因。
7. **工作流默认关闭集成**
   - C1 独占修改 `.github/workflows/clash-verge-auto.yml`，加入最小权限 staging/validate stage 和 V2 开关；默认值保持关闭。
   - 拆分 collection → controlled identity → publisher：collection 不持 HMAC key/发布 token，identity 不访问原始来源/不启动 Mihomo/不持发布 token，publisher 不持 HMAC key。
   - 不加入 CNB trigger，不修改其他输出分支。
8. **全量验证与交接**
   - 运行目标/完整测试、JSON/YAML 回读、敏感字段扫描和 `git diff --check`。
   - 向 C4/C5/C6 交付 schema fixture、policy version 和 producer/consumer 映射。

## 2. 文件范围与所有权

允许修改：

- `subscribe/asia.py`, `subscribe/collect.py`, `subscribe/crawl.py`, `subscribe/workflow.py`, `subscribe/clash.py`, `subscribe/process.py`
- `scripts/build_crawler_config.py`, `scripts/merge_clash_profiles.py`, `scripts/apply_tcp_probe.py`, `scripts/filter_reachability.py`, `scripts/prepare_github_publish.py`
- 可新增 candidate/source-health/provenance 的 `scripts/` 纯模块
- `.github/workflows/clash-verge-auto.yml`
- `tests/test_asia_retention.py` 与 `tests/test_candidate_*.py`、必要的 workflow contract 测试

禁止修改：

- C3 identity owner 文件；如 API 缺失，通过接口评审协调，不在 C1 复制实现。
- `.cnb.yml`、`scripts/cnb_gmgn_shadow.py`、`scripts/cnb_gmgn_publish.py`。
- `CNB_SETUP.md`、`CLASH_VERGE_AUTO.md` 的默认入口说明（由 C7 统一迁移）。

## 3. 最低测试矩阵

- source health：成功、429、Timeout、解析失败、48h 边界、3 次/6h/48h confirmed missing、恢复、多来源共享候选。
- publish guard：60%/59.x%、70%/69.x%、五地区 50%、非零归零、80% quorum、首发与 previous 暂时故障。
- identity/provenance：输入重排、普通+亚洲重复、同名不同配置、同配置多来源、metadata orphan/duplicate/hash mismatch。
- airport quota：known-good 过量、桶不足外溢、untried/due 不饥饿、任务与 proxy 双层去重。
- Asia：新增机场代码、短词/状态文本反误判、TCP/reachability 一次失败仍保留。
- security：loopback/private/link-local/metadata/非法端口拒绝；目标 DNS 二次观察、多 canary 2/3 健康、批量异常比例上限和 hostname 级缓存；公开 JSON、异常链与 CLI stderr 不含 hostname、解析 IP 或假 secret。
- workflow：V2 默认关闭、最小权限、现有并发组保留、不触发 CNB、不写其他分支。

## 4. 验证命令

所有临时产物写入专用目录：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\github-candidate-provenance-v2'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_asia_retention -v
python -m unittest discover -s tests -p 'test_candidate_*.py' -v
python -m unittest discover -s tests -p 'test_workflow_*.py' -v
python -m unittest discover -s tests -v
git diff --check -- subscribe scripts tests .github/workflows/clash-verge-auto.yml
```

生成 fixture/组件输出后还必须用 `json.loads`/`yaml.safe_load` 回读，并运行 candidate snapshot validator；测试代码自行使用 `$env:AGGREGATOR_TEST_TMPDIR`，不得在仓库产生临时 profile。

## 5. 完成门禁

- PRD 全部验收项有自动化证据；新 schema 的 producer、validator、CNB consumer fixture 字段一致。
- C3 identity API 已真实接入，不存在第二套 fingerprint/HMAC。
- V2 workflow 开关默认关闭，代码合入不会改变当前线上入口或触发 CNB。
- 完整测试与敏感字段扫描通过，未修改 C2–C7 所有权文件。

## 6. 回滚点

- **模块阶段**：新 reducer/schema 尚未接入 workflow，可仅回退 C1 模块和测试。
- **默认关闭集成阶段**：关闭 V2 开关即回到原生成路径；不删除 previous metadata/state。
- **未来 C5 接入后异常**：C5 必须保持 GitHub last-good tip；C1 只提供拒绝原因，不能强推缩水快照。
