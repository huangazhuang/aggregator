# GMGN 亚洲节点选拔 V2 实施计划

## 1. 执行模型

当前任务作为父任务，负责统一 PRD、schema/策略版本、子任务依赖、跨层集成和 rollout 门禁，不直接承载所有业务实现。实际工作拆为七个可独立验收的子任务。

| ID | 子任务 | 主要交付物 | 依赖 |
|---|---|---|---|
| C1 | GitHub 候选池与 provenance | 来源 last-good、地区/来源掉量保护、metadata、探索配额、安全清洗 | 根规范与设计冻结；最终 metadata 联调依赖 C3 identity API |
| C2 | GMGN 测量有效性 | 时间戳/观察窗、分片出口与 canary、错误分类、并发标定 | 根规范与设计冻结 |
| C3 | 稳定身份、历史与名称 | fingerprint、HMAC 诊断 ID、history 状态机、稳定 output name | 根规范与设计冻结 |
| C4 | 真实地区、选择与分组 | 出口/ASN cache、分层、多样性、九个手动分组 | C1、C2、C3 |
| C5 | 事务发布与触发 | bundle、CAS/lease、exactly-once SHA 触发、远端 smoke、工作流集成 | C1–C4 |
| C6 | 外部亚洲来源接入 | 来源边际增益、受控限额、可撤销开关 | C1；可与 C4 后半并行 |
| C7 | 影子验收与入口迁移 | 单次/三次证据、正式提升、gstatic 冻结与恢复说明 | C5、C6、全部代码门禁 |

根项目 Trellis package/spec 修正属于规划前置，已在父任务中完成。最终批准后，C1/C2/C3 可以并行启动：C1 先完成来源健康、门禁和 sidecar 生产边界，但不另写 fingerprint/HMAC；其最终 metadata 联调等待 C3 冻结 identity API。父任务本身不执行 `task.py start`，应启动拥有下一交付物的子任务。

## 2. 跨任务冻结契约

开始 C1–C3 前先冻结并以 fixture 表达：

- GitHub candidate status/metadata schema；
- GMGN manifest、private fragment、redacted fragment schema；
- `valid_run` 与 `bad_run_countable` 条件；
- `history.json`、selection policy、publish bundle 版本；
- fingerprint、公开 HMAC diagnostic ID 与 output-name 规则；
- public/private 字段 allowlist；
- 状态迁移：core、flexible、manual-candidate、history-protected、removed、unknown-region、source-missing、invalid-config、rejected-run。

任何破坏性 schema 调整都必须提升版本，并同步 producer、consumer、validator、回放器、文档和测试。未知版本 fail-closed。

## 3. C1：GitHub 候选池与 provenance

### 文件范围

- `subscribe/asia.py`, `subscribe/collect.py`, `subscribe/crawl.py`, `subscribe/workflow.py`, `subscribe/clash.py`, `subscribe/process.py`
- `scripts/build_crawler_config.py`, `scripts/merge_clash_profiles.py`, `scripts/apply_tcp_probe.py`, `scripts/filter_reachability.py`, `scripts/prepare_github_publish.py`
- `.github/workflows/clash-verge-auto.yml`
- 相关/新增 candidate 与 source-health 测试

### 顺序

1. 完成 provenance 合并和精确去重调用边界，修复任务去重只比较首项的问题；canonical fingerprint/HMAC identity 实现由 C3 独占，C1 只消费冻结 API/fixture。
2. 为固定与动态来源增加稳定 source ID、last-success、观察状态、confirmed tombstone 和 TTL。
3. 精确重复配置合并来源/地区/测试证据，而不是按名称丢弃元数据。
4. 补齐安全地区别名，减少短词误判；亚洲继续绕过 GitHub 单轮网络淘汰。
5. 生成 `candidate-metadata.json` 与版本化 `status.json`。
6. 增加总量、亚洲、五地区、来源 quorum 和上一版比例发布门禁。
7. 将 known-good/untried/due-retry 改为配额轮转。
8. 分离不可信解析/测速与发布凭据，拒绝私网/loopback/link-local/metadata 端点。
9. 推送后防缓存回读 GitHub profile/status/metadata。

### 完成门禁

- 单来源失败、某地区归零、previous 暂时不可读、来源 quorum 不足均不覆盖 last-good。
- temporary failure 与 confirmed missing 可测试地区分；后者才允许节点消失。
- metadata 不泄露私有订阅 URL/token，CNB 能按 HMAC `candidate_id` 读取来源和地区证据。
- 新来源不会被 192 个 known-good 永久饿死。

## 4. C2：GMGN 测量有效性与并发标定

### 文件范围

- `scripts/cnb_gmgn_shadow.py`
- `scripts/cnb_mihomo_filter.py` 中复用的 runner/controller 观测
- `tests/test_cnb_gmgn_shadow.py` 及 fake-clock/组件/benchmark 测试

### 顺序

1. manifest 加入 runtime hash、观察窗、canary、分片出口和策略版本。
2. 每轮记录开始/结束时间，每候选保留完整 20 条结果；初始最短观察窗使用版本化的 900 秒。
3. 增加 DNS/TLS/connect/auth/403/429/target/controller 等规范化错误分类。
4. 每片独立记录真实出口，执行直接目标检查和共享 canary/锚点。
5. publisher 输入携带全局 round trends、error counts、control/canary 结果。
6. 建立 `valid_run` 纯校验：缺片、轮数、观察窗、controller、目标事故、跨片不可比均拒绝。
7. 用受控候选比较 8/16/24/32 workers；默认保持 16，只有吞吐改善且假 Timeout/5xx/canary 不恶化才修改。
8. 实现版本化 network-guard launcher/self-test：固定已验证公网解析，隔离 Mihomo/探测器并阻断私网、link-local、CGNAT、Runner/CI 内网和云元数据；向 C5 交付工作流接入契约。隔离不可用时必须在 Mihomo 启动前失败关闭。

### 完成门禁

- N=4、5、2260、5000 与输入重排均证明分片稳定、完整、平衡。
- fake clock 证明同节点顺序与至少 900 秒观察窗。
- 系统事故产生 `valid_run=false` 且不生成可发布 selection 输入。
- 所有候选仍恰好 20 轮，不提前淘汰。
- DNS rebinding、私网/元数据恶意端点和 guard 不可用均有 Linux 组件/工作流契约测试；probe job 不持有发布凭据。

## 5. C3：稳定身份、历史与名称

### 文件范围

- 建议新增 `scripts/gmgn_identity.py`, `scripts/gmgn_history.py`
- `scripts/cnb_gmgn_publish.py` 的 history 接口接入
- `tests/test_cnb_gmgn_publish.py`
- 新增 history/stable-name 测试

### 顺序

1. 作为唯一 owner 实现统一内部 fingerprint 与 HMAC identity API；公开 candidate/endpoint/server/exit ID 使用带 `identity_key_version`、域前缀和 `identity_epoch` 的 HMAC。
2. 定义 `history.json` schema 和原子读写。
3. 持久化 output name、tier、迁移原因、bad streak、last seen、最近有效运行和出口 cache。
4. 有效不同 SHA 且满足最短间隔的零响应运行才增加亚洲候补 bad streak。
5. 新 SHA accepted 但间隔不足时仍推进 history 顶层 run/source，只标记 `counted_bad=false`；重复 SHA、基础设施 retry、无效/拒绝运行和暂时 source failure 不产生第二次 transition。
6. 三次可计数零响应后移除；任一新 accepted valid run 重新至少一次响应即立即清零，达到阈值立即晋级。
7. 输入重排、源改名、排名/层级变化和同名冲突不改变已有输出名。
8. key/epoch 轮换保留快照外 legacy tombstone 与名称占用；旧 key 仅在 legacy 清零或 90 天可审计 GC 后退役。

### 完成门禁

至少五次合成运行覆盖：core → bad1 → bad2 → bad3/remove → recovered，并插入无效运行、重复 SHA、间隔不足、source missing、invalid config 和 key/schema 迁移失败场景。

## 6. C4：真实地区、选择、多样性和分组

### 文件范围

- `scripts/cnb_gmgn_publish.py`
- 建议新增 `scripts/gmgn_region.py`, `scripts/gmgn_selection.py`
- `subscribe/location.py`
- 地区/多样性/分组/诊断测试

### 顺序

1. 对 responders、严格入选和历史候补做 per-proxy 出口国家/IP/ASN 查询并缓存 TTL。
2. 名称只作提示；unknown 不得获得亚洲主力宽松阈值。
3. 实现核心、弹性、手动候补、历史保护和非亚洲严格层。
4. 主力/自动组执行故障域硬上限；亚洲候补在总量未满 150 时只降权。
5. 实现总量 150、非亚洲 20 和不为80降标。
6. 生成稳定名称与目标分组，自动组只含亚洲核心和非亚洲严格层。
7. 发布 node-status 能解释入选、降级、历史保护和淘汰原因，保持脱敏。

### 完成门禁

- 新亚洲 `response_count >=1` 可进入仅手动候补；20轮零响应新节点不进入正式订阅。
- 实际出口分组正确，查询失败明确降级。
- 精确包含手动优先、五地区、亚洲候补、非亚洲稳定、全部入选及辅助自动组，所有引用有效。

## 7. C5：事务发布、自动触发与远端 smoke

### 文件范围

- `.cnb.yml`（最终唯一 owner）
- `.github/workflows/sync-cnb.yml`
- C1 完成后的 `.github/workflows/clash-verge-auto.yml` 触发尾段
- `.github/workflows/tests.yml`
- `scripts/cnb_gmgn_publish.py` 的 bundle 接口
- 建议新增 `scripts/publish_transaction.py`, `scripts/validate_public_outputs.py`
- publication/workflow/remote-validator 测试

### 顺序

1. 新增独立 `clash-cn-gmgn-v2-shadow`，代码门禁阶段只允许手动触发。
2. 一次性构建/验证 `clash.yaml + status + history + node-status + last-N runs` bundle。
3. previous branch/`history.json` 读取 fail-closed，区分明确首发与暂时网络错误。
4. 保存 observed tip 并用 force-with-lease/CAS；旧 run 不得覆盖新 tip。
5. 以完整 source profile SHA 作为幂等 trigger/lock key；同 SHA 正常只发布一次。
6. 完整 bundle 先推 staging ref 并防缓存回读，通过后才以 CAS 提升 V2 shadow current；提升后再次验证 schema/hash/count/groups/20轮/四片/run 关联和固定 Mihomo。
7. 单次影子通过后，才单独启用“新 SHA → V2 shadow”自动触发。
8. 在 `.cnb.yml` 中作为唯一 owner 配置 C2 network guard，并在每片启动前执行 fail-closed self-test；工作流不得在 guard 缺失时退化为无隔离探测。

### 完成门禁

并发旧 run、外部 tip 变化、push 失败、远端旧缓存、坏 previous `history.json`、缺片和 Mihomo invalid 都证明 last-good 分支不变；现有 gstatic 和正式 GMGN 分支在影子阶段不受影响。

## 8. C6：外部亚洲源受控接入

1. 先评估并通过开关接入 `awesome-vpn/awesome-vpn`。
2. 记录 raw、精确唯一、唯一端点、与现池重叠、五地区、更新时间和验证透明度。
3. 若边际增益不足，再评估 Mahdibland 限额亚洲子集。
4. V2Hive 只能作为带每源/每地区/每入口上限的 discovery reservoir。
5. 接入后重新计算 CNB 最坏耗时；接近约5000先扩容评估。

完成门禁：撤销单一 source 开关即可回滚，来源失败不会拖垮其他来源或覆盖 last-good。

## 9. C7：真实影子、迁移与 gstatic 冻结

### 门禁一：代码完成

- C1–C6 离线/组件/工作流测试与 Linux Mihomo 校验通过。
- V2 自动触发关闭，只能手动写 V2 shadow。
- 旧 gstatic、当前正式 GMGN 和推荐文档未改变。

### 门禁二：单次有效影子

- 明确 source SHA，四片、20轮、观察窗、出口/canary、history bootstrap、地区/分组、远端 smoke 全部通过。
- 失败注入证明拒绝发布时 V2 last-good 不变。
- 只有该门禁通过后才启用新 SHA 自动写 V2 shadow。

### 门禁三：连续三次有效影子

- 三个不同 source SHA，policy/schema/runtime 一致，满足最短计数间隔。
- 重复/重试/无效/拒绝运行不计数。
- 名称、历史、地区 cache、恢复晋级和 bundle 关联跨运行稳定。
- 使用不进入用户订阅的确定性 canary/replay 证明 bad1→bad2→bad3/remove→recover。

### 门禁四：用户确认后的迁移

1. 记录旧 gstatic、正式 GMGN 和 V2 shadow tip/bundle hash。
2. 将已验收的同一 V2 bundle 提升至正式 GMGN，不重新测速。
3. 远端回读证明正式 hash/run_id 与验收 bundle 一致。
4. 更新文档和推荐入口。
5. 停止 gstatic 自动触发，保留 `clash-cn-output`，标记 frozen/legacy、冻结时间、最后 hash 和受控恢复方法。

## 10. 验证命令

所有本机测试/证据使用 `D:\xiangmu\linshi\gmgn-asia-selection-v2`：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-asia-selection-v2'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:PYTHONPATH = (Get-Location).Path
python -m unittest discover -s tests -v
git diff --check -- .trellis/spec .github/workflows .cnb.yml scripts subscribe tests CNB_SETUP.md CLASH_VERGE_AUTO.md
```

目标模块/组件门禁：

```powershell
python -m unittest tests.test_asia_retention -v
python -m unittest tests.test_cnb_gmgn_shadow -v
python -m unittest tests.test_cnb_gmgn_publish -v
python -m unittest tests.test_cnb_policy_replay -v
python -m unittest tests.test_pipeline_utils -v
python -m unittest discover -s tests -p 'test_candidate_*.py' -v
python -m unittest discover -s tests -p 'test_gmgn_*.py' -v
python -m unittest discover -s tests -p 'test_workflow_*.py' -v
```

Linux/CNB 额外执行固定 Mihomo：

```bash
sha256sum clash/clash-linux-amd
clash/clash-linux-amd -v
clash/clash-linux-amd -t -d "$RUNNER_TEMP/gmgn-v2-mihomo" -f "$RUNNER_TEMP/gmgn-v2-build/clash.yaml"
```

live 阶段必须保存受保护分支 before/after refs、source SHA、bundle hash、状态/配置防缓存副本和 validator 输出到专用证据目录；验证器应提供单次、连续序列和迁移三种模式。

## 11. 高风险文件与所有权

- `.cnb.yml`：只由 C5 最终集成，C2–C4 不并行编辑。
- `.github/workflows/clash-verge-auto.yml`：C1 先负责候选发布，C5 后接手触发尾段。
- `scripts/cnb_gmgn_publish.py`：C3 先冻结 history API，C4 再改选择，C5 最后接 bundle。
- `subscribe/asia.py`：C1 是唯一地区标签 owner，C4 只消费其证据。
- canonical fingerprint/HMAC identity 模块：C3 是唯一实现 owner；C1/C4/C5 只消费其版本化 API 和 fixture。
- `CNB_SETUP.md`, `CLASH_VERGE_AUTO.md`：C7 在 rollout 时统一更新，避免实现中多次漂移。

实现代理必须知道存在并行工作，不得还原其他子任务修改；发现接口变化时以冻结 schema 和父任务设计为准。

## 12. 回滚点

- **代码阶段**：不改变线上触发/分支；失败只回滚当前子任务代码。
- **单次影子失败**：关闭 V2 自动触发，保留旧正式分支和 V2 last-good。
- **三次验收中断**：policy/schema/runtime 变化则重置连续计数，但保留诊断。
- **迁移后回滚**：恢复迁移前记录的推荐入口与 gstatic 手动/定时触发；所有旧分支和 URL 保留，不删除历史产物。

## 13. `task.py start` 前检查

- [ ] PRD 无开放决策并完成收敛 pass。
- [ ] `design.md`、`implement.md` 已审阅。
- [ ] aggregator 根 specs 无占位，Trellis package 映射正确。
- [ ] 父任务已建立子任务和依赖说明。
- [ ] 每个准备启动的子任务有自己的 PRD/计划及真实 implement/check context。
- [ ] 已向用户展示最终规划摘要。
- [ ] 用户在摘要之后另行明确批准开始实现。
