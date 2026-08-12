# GMGN 亚洲节点选拔 v2 技术设计提案

> 本文是研究提案，不是最终契约。与父/子任务正式 `prd.md`、`design.md`、`implement.md` 或 [planning-resolution.md](./planning-resolution.md) 冲突时，以后者为准；已收敛差异包括 `candidate-metadata.json`、900 秒、独立 V2 shadow、`history.json` 和 identity 字段命名。

> 历史研究快照：本文件用于记录设计推导。正式实现以父/子任务文档、`planning-resolution.md` 和 `.trellis/spec/aggregator/gmgn-v2-contract.md` 的已收敛契约为准。

## 1. 设计结论

采用单仓库、两段式供应链，不拆 Worker 仓库：

1. GitHub 只负责生成“可追溯的宽候选快照”，保留来源、稳定身份和来源健康；亚洲候选不做单轮 GMGN 淘汰。
2. CNB 只消费一个固定快照，四个独立 Mihomo 分片对每个候选执行恰好 20 轮；测量、有效运行判定、出口验证、历史状态和选择发布分层处理。
3. `clash-cn-gmgn-output` 成为正式 GMGN 的原子发布单元：当前 profile、状态、历史、名称映射和对应诊断必须来自同一个 `run_id`、同一个提交。被拒绝的运行只能写独立失败诊断，不能推进历史或覆盖 current。
4. 亚洲核心/弹性是主力，亚洲手动候补是独立层；候补只要本轮至少一次响应，或仍在三次有效坏运行保护期内即可保留。候补不进入自动组、不计入稳定容量。
5. 当前 4×16 workers、约 2260 候选、约 24 分钟作为 v1 生产基线；先增加时间窗和有效运行控制，不直接提高到 32–48 workers。

## 2. 架构边界与数据流

```text
公共/显式允许发布的来源
  -> GitHub 收集与逐源 last-success
  -> 配置安全校验、精确去重并合并 provenance
  -> candidate snapshot v2
       status.json
       clash.yaml                 # 给用户看的宽候选订阅
       candidates.jsonl           # CNB 唯一机器输入，含 proxy + candidate_id + provenance
       source-health.json
  -> 远端 smoke + CAS 发布
  -> 按新的 profile_sha256 幂等触发 CNB

CNB coordinator
  -> 固定 status/candidates pair，校验 SHA、freshness、schema、容量预算
  -> 确定性四分片 manifest v3
  -> shard-0..3：独立 Mihomo、20 轮、时间戳、直连控制、canary、分片出口
  -> merge：完整性校验 + valid-run gate
  -> 仅对响应节点/历史保护节点做真实出口查询与缓存
  -> history reducer -> tier selection -> diversity -> stable names/groups
  -> staging remote smoke -> CAS promotion
  -> current profile/status/state/diagnostics 同 run_id 原子关联
```

信任边界必须分离：收集/解析/探测 job 不持有正式分支写凭据；最终 publisher 不重新访问不可信订阅，只读取已校验的固定快照、分片结果和上一版状态。代理服务器为域名时，探测前解析并拒绝 loopback、link-local、私网、组播和云元数据地址；运行网络还应阻断到 CI 内网/元数据地址，避免仅依赖字符串校验。

## 3. GitHub 候选快照与 provenance

### 3.1 稳定身份

新增一个共享 owner（建议 `scripts/proxy_identity.py`），GitHub 与 CNB 不再各写一套 fingerprint：

- `config_fingerprint_v1`：复制代理配置，移除 `name`、测速值、来源临时字段和运行时字段，对所有协议有效字段递归排序并用紧凑 JSON 编码，计算 SHA-256。配置/凭据变化视为新节点；单纯改名不变。
- `candidate_id`：`c1_` + `HMAC-SHA256(CANDIDATE_ID_KEY, fingerprint)[:24]`。公开文件只出现 opaque ID，不公开可枚举的原始 fingerprint。密钥或 identity epoch 改变必须走显式迁移，不能静默清空历史。
- `endpoint_id`、`server_id`、`exit_id` 同样使用带域前缀的 HMAC，供去重和多样性比较，不公开原始出口 IP。

精确重复配置合并为一个 candidate，合并所有 provenance、亚洲证据和检查结果；显示名称只作为候选别名，不能决定身份或覆盖证据。

### 3.2 `candidate-snapshot` v2 契约

`status.json` 至少包含：

```json
{
  "kind": "github-candidate-status",
  "schema_version": 2,
  "snapshot_id": "cand_<opaque>",
  "run_at": "...Z",
  "main_sha": "<40hex>",
  "profile_sha256": "<64hex>",
  "candidates_sha256": "<64hex>",
  "provenance_schema": 1,
  "candidate_count": 2260,
  "protected_asia_count": 1163,
  "region_hint_counts": {"HK": 0, "JP": 0, "KR": 0, "SG": 0, "TW": 0},
  "source_counts": {"configured": 0, "successful": 0, "cached": 0, "failed": 0},
  "dedupe": {"raw": 0, "exact_unique": 0, "endpoint_unique": 0},
  "publish_gate": {"passed": true, "policy_version": "candidate-v1"}
}
```

`candidates.jsonl` 每行是完整机器记录：`candidate_id`、`proxy`、`aliases`、`protocol`、`server_id`、`endpoint_id`、`first_seen_at`、`last_seen_at`、`region_evidence[]`、`github_checks`、`provenance[]`。公共来源可记录仓库和文件；私有来源只能记录不可逆 `source_id`，不得写 URL/token。私有订阅派生配置只有 `publish_derivatives=true` 时才允许进入公开快照。

每个固定 raw 源保存 `last_success_at`、内容 hash、raw/unique/region counts、连续失败与恢复状态。网络失败/429/解析失败只使用不超过 48 小时的 last-success，不等于“来源消失”；节点只有在至少 3 次彼此间隔达到 6 小时的成功采集中都确认缺失，才标记 `source_disappeared`。缓存过期且来源仍失败时，整次候选发布失败关闭，不用缩水结果替换 last-good。

机场 192 配额按 60% known-good、20% untried、20% due-retry 分配，某一桶未用完才可外溢。超大外部源必须先输出边际增益报告，并受每源/每地区/唯一入口预算约束；不把数千条高度重复记录直接送入 CNB。

### 3.3 GitHub 发布门禁

门槛放入版本化 policy，不散落在 workflow：默认总候选保留率 60%、亚洲总量 70%、HK/JP/KR/SG/TW 各 50%，上一版非零地区不得本轮归零；固定来源成功 quorum 80%。previous branch/status 暂时读取失败、schema/hash 不匹配均失败关闭，只有 `ls-remote` 明确确认分支从未存在才允许首发。

## 4. CNB 四分片、20 轮与有效运行

### 4.1 manifest/fragment v3

coordinator 固定 `status.json + candidates.jsonl`，而不是重新从 `clash.yaml` 猜元数据。manifest 增加：`snapshot_id`、`candidates_sha256`、`policy_version`、`identity_epoch`、`minimum_observation_window_seconds=900`、Python/PyYAML/Mihomo 版本与二进制 hash、canary-set hash、预期 Runner 国家、四片错峰参数。

候选按 `candidate_id` 排序后 round-robin 到 4 片，保证输入重排不改变分片且片差不超过 1。每片使用独立工作目录、Mihomo 进程、controller/mixed port 和私有日志。分片启动错开 0/15/30/45 秒，默认每片 16 workers。

每个节点每轮只能有一个请求；第 N+1 轮必须等待该片第 N 轮全部完成，因此同节点绝不并发。每个样本私有记录 `round`、`started_at`、`finished_at`、delay/error category；第一轮最后一个样本开始后，以 900 秒/19 的节拍约束后续轮次，最终逐节点验证首末采样开始时间跨度至少 900 秒。自然运行超过该窗口时不额外等待。

### 4.2 控制与错误分类

每片独立记录探测前/后的 Runner 出口；默认要求 country code 为 `CN`，四片 country/region 一致，具体省份只作为可配置 allowlist，不硬编码广东。原始 Runner IP 只留私有运行目录，公开状态只写 country/region/org 和 opaque egress ID。

每轮同时执行：

- 不经过候选代理的 GMGN 直连控制；
- 同一组版本化私有 canary；
- Mihomo `/version` 健康检查。

错误统一为 `target_403`、`target_429`、`target_5xx`、`dns`、`tls`、`connect`、`proxy_auth`、`client_timeout`、`controller_request`、`controller_unhealthy`、`other`。原始错误仅在私有 fragment，公开文件只保留计数。

### 4.3 `valid-run` gate v1

“完成运行”不等于“有效运行”。以下全部满足才可进入历史 reducer：

1. source/status/provenance hash、新鲜度、main SHA、policy/schema 一致；4 片无缺失、重复或额外候选。
2. 每候选恰好 20 次、逐节点观察跨度至少 900 秒，所有计数和 round trends 可回算。
3. 每片 Mihomo 健康失败为 0；Runner 出口为 CN 且四片 region 一致。
4. 每片直连控制至少 18/20 成功且不得连续失败 3 轮。
5. 每个 canary 每片至少 16/20 响应；四片成功次数差不超过 4，median 差不超过 `max(300ms, 50%)`。
6. 全局 403+429 不超过全部尝试的 2%；任一轮达到 10% 时直接判系统性异常。

免费代理本身可有很高 no-result，因此“全局 timeout 比例高”不单独拒绝；只有与 control/canary 退化或单片显著偏离同时出现才拒绝，避免把候选质量差误判为基础设施事故。所有门槛均记录 policy version，并先在影子阶段校准。

## 5. 历史状态、真实出口与选择

### 5.1 durable state v1

新增独立 reducer（建议 `scripts/cnb_gmgn_state.py`），输入只能是上一版校验通过的 `state.json` 和本次 valid run，输出新状态；publisher 不再从上一版组名反推历史。

每节点保存：`candidate_id`、`output_name`、`current_tier`、`bad_run_streak`、`last_counted_source_sha`、`last_counted_at`、最近 3 次有效观察、迁移原因、首次/最后见到时间、出口缓存和来源状态。只有不同 source SHA 且与上次计数间隔至少 6 小时的有效运行才改变 streak；同 SHA 基础设施重试、无效运行、拒绝发布均不计数。

亚洲历史的“保留标准”定义为 `response_count >= 1`：

- 达到亚洲核心/弹性：晋级并把 bad streak 清零。
- 本轮至少一次响应但低于 10/20：进入/保持 `asia_manual_candidate`，bad streak 清零。
- 本轮 0 响应且此前是亚洲入选/候补：降为 `history_protected`，bad streak +1；第 1、2 次仍保留，第 3 次移除。
- 重新有响应自动恢复；配置无法被 Mihomo 加载或来源已按 GitHub 契约确认消失可立即移除。

状态 schema 不支持时失败关闭；迁移必须显式提供 `from_version -> to_version`，禁止把未知状态当首发。

### 5.2 出口验证与地区证据

查询范围仅为本轮 `response_count >= 1` 的节点和历史保护节点。通过相应代理访问固定、版本化的出口元数据接口，校验公共 IP、country code、region、ASN；provider URL/响应 schema 作为配置契约，测试使用 mock。缓存 TTL 7 天；历史节点查询失败时可在 30 天 grace 内使用带 `stale=true` 的旧结果，查询失败不使整次发布失败。

政策分类：真实出口为 HK/JP/KR/SG/TW 才能获得亚洲核心/弹性阈值；可靠的国家专用来源证据但查询失败只能进入“临时亚洲候补”；单纯模糊名称命中不能获得宽松主力阈值。未知地区节点若达到非亚洲严格线可进入非亚洲稳定，否则只留 GitHub 候选池。

### 5.3 层级、容量与多样性

- 亚洲核心：`>=14/20` 且前后十轮各 `>=5`。
- 亚洲弹性：`10–13/20`。
- 亚洲候补：本轮至少一次响应但低于 10/20，或 bad streak 为 1–2 的历史保护节点。
- 非亚洲稳定：前 10 个可用 `>=16/20`；第 11–20 个必须 `>=18/20`。
- 总数最多 150，非亚洲最多 20；80 仅作期望值，任何情况下不自动降阈值。

严格主力采用 greedy diversity：同 exit ID 最多 3、同 server 最多 3；ASN 上限为 `max(3, ceil(target_strict*0.30))`，来源上限为 `max(2, ceil(target_strict*0.25))`。先满足五地区覆盖，再按达标次数、响应次数、P90、median、jitter 排序。多样性不能把不达标节点补进主力。

亚洲候补在总数不超过 150 时不执行 IP/ASN/source 硬删除，只降权并标记集中度；超过 150 时先保留核心、弹性和历史保护，再按响应质量、地区缺口、来源/出口集中度裁剪普通候补。

## 6. 分组、稳定名称与公开诊断

输出组固定为：

1. `👆手动优先测速`：亚洲核心、亚洲弹性、非亚洲稳定，已应用主力多样性限制。
2. `🇭🇰香港`、`🇯🇵日本`、`🇰🇷韩国`、`🇸🇬新加坡`、`🇹🇼台湾`：按真实出口分组，可同时包含该区主力和候补。
3. `🌏亚洲候补`：普通候补和历史保护，仅手动使用。
4. `🌍非亚洲稳定`。
5. `📦全部入选`：全部发布节点。
6. `GMGN自动`：仅亚洲核心和非亚洲稳定，不含弹性、候补和观察节点。

名称映射 `candidate_id -> output_name` 持久化。首次命名采用清洗后的来源名；冲突后缀由 candidate ID 确定，不依赖输入顺序。后续源改名、排名或层级变化不改公开名；名称不附加延迟、成功率或名次。

公开 diagnostics 使用 stable opaque `candidate_id`，并为当前 profile 输出 `output_name -> candidate_id` 映射，可查看 tier、reason、20 轮汇总、history transition、地区置信度和集中度标记；不写 server、port、凭据、原始错误或私有来源 URL。淘汰节点可按 candidate ID 查询原因。

## 7. 触发、原子发布与回滚

GitHub 候选发布完成远端 smoke 后，用 profile SHA 生成幂等 CNB tag（例如 `cnb-gmgn-source-<sha256>`）。同 SHA tag 已存在即 no-op；CNB 的 processed-source registry 再做一次去重。手动触发可重试基础设施失败，但不得把同 SHA 重复计入 bad streak。

CNB 发布顺序必须改为：加载并校验 previous tip/state -> build 全部新产物 -> Mihomo `-t` -> 推送 staging ref -> 防缓存远端 smoke -> 以 `--force-with-lease=<previous_tip>` 提升正式 ref。正式提交同时包含根目录 current 文件、`state.json`、`runs/<run_id>/diagnostics.json` 和最近至少 5 个可回滚 bundle。shadow 分支只是镜像，不再先于 profile 覆盖权威诊断；镜像失败不能破坏已验证的正式 bundle。

远端 smoke 校验 schema、hash、数量、精确组名、引用、run_id、20/4、Mihomo 可加载性和正式 ref tip。CAS 失败说明有更新版本，旧运行必须退出，不得重试 force 覆盖。发布后 smoke 失败时，以当前 tip 为 lease 把根 current 恢复到内置 previous bundle，并保留失败诊断。

## 8. gstatic 冻结、rollout 与 rollback

rollout 分四道人工可见门禁：

1. 离线单元/组件/workflow 契约和固定 Mihomo 集成测试全部通过。
2. 独立 GMGN 分支完成一次真实 valid shadow，核对出口、canary、错误率和容量。
3. 至少 3 次不同 source SHA、间隔满足历史计数要求的 valid+accepted 运行通过，验证降级、两次保护、第三次移除、恢复和名称稳定。
4. 用户确认推荐入口切到 GMGN；此前不修改旧入口。

第 4 步后才冻结 gstatic：停止其 cron/tag 自动触发，但保留手动入口；`clash-cn-output` 的 `clash.yaml` 不删除、不改 URL，README/status 增加 `lifecycle=frozen`、`frozen_at`、最后 profile hash、GMGN replacement URL 和手动恢复说明。未来只有 GMGN 长期不可用时由人工恢复 gstatic，不做自动双向切换。

任一 rollout 阶段失败：关闭新 SHA 自动触发，正式 GMGN 保持 last-good，推荐文档仍指向原入口；若已经切换，则从保留 bundle 以 lease 回滚 GMGN current，必要时人工恢复 gstatic 自动任务。不得删除任一旧分支。

## 9. 受影响文件

建议新增：

- `scripts/proxy_identity.py`：唯一 canonical fingerprint/HMAC ID owner。
- `scripts/candidate_state.py`：来源 last-success、provenance 合并、候选发布门禁。
- `scripts/cnb_gmgn_state.py`：valid-run gate、历史 reducer、出口缓存、层级/多样性/稳定名称。
- `tests/test_candidate_snapshot.py`、`tests/test_cnb_gmgn_state.py`：schema、历史、多样性和命名组件测试。

主要修改：

- GitHub：`.github/workflows/clash-verge-auto.yml`、`.github/workflows/sync-cnb.yml`、`scripts/build_crawler_config.py`、`subscribe/collect.py`、`subscribe/process.py`、`subscribe/clash.py`、`subscribe/asia.py`、`scripts/merge_clash_profiles.py`、`scripts/filter_reachability.py`、`scripts/prepare_github_publish.py`。
- CNB：`.cnb.yml`、`scripts/cnb_gmgn_shadow.py`、`scripts/cnb_gmgn_publish.py`、`scripts/pipeline_utils.py`、必要时 `scripts/cnb_diagnostics.py`。
- 文档/测试：`CLASH_VERGE_AUTO.md`、`CNB_SETUP.md`、现有 `test_asia_retention.py`、`test_cnb_gmgn_shadow.py`、`test_cnb_gmgn_publish.py`、`test_pipeline_utils.py` 和 workflow contract/live-smoke 测试。

## 10. 明确拒绝的方案

- 不降低 14/10/16/18 主力阈值来凑 80；用独立亚洲候补解决本地差异。
- 不对正式运行做“数学上不可能达标即早退”，每候选必须留下 20 次观测。
- 不把 raw 爬取全集直接无界送入 CNB；GMGN 的“全部候选”指已通过配置安全校验、精确去重、来源保护后的固定 candidate snapshot。
- 不继续从名称、上一版组名或随机 shadow ID 推断地区和历史。
- 不把亚洲候补放进 `GMGN自动`，也不让多样性规则在 150 以下硬删候补变体。
- 不先推 shadow 再尝试 profile；不再使用无 lease 的裸 `git push --force`。
- 当前规模不拆仓库；只有持续约 8000 候选、稳定运行超过 60 分钟或证实 CNB 单仓库硬限制后再评估。

## 11. 主要风险与缓解

- 出口元数据 provider 限流/漂移：接口适配器、schema pin、7 天缓存、30 天历史 grace；失败只降级地区证据，不破坏整次运行。
- canary 本身失效：使用 2–3 个不同故障域 canary，按集合判断并版本化 hash；更新 canary 不能与策略变更混在同一无说明运行。
- HMAC 密钥丢失/轮换导致身份重置：identity epoch 写入所有 schema，密钥变更必须迁移或停止发布。
- 多样性上限在候选少时压低数量：允许少于目标，不放宽质量；诊断公开被 cap 的数量，后续基于数据调参。
- 高频新 SHA 消耗历史：distinct SHA + 6 小时间隔双门槛，失败/拒绝/重试不计数。
- 两阶段远端发布仍遇到 CDN 延迟：staging ref 防缓存 smoke、正式 ref 再 smoke、previous bundle + lease 回滚。
- 新 schema 一次改动面较大：先同时产出旧/新诊断进行 shadow 对照，消费者切到 v2 后再删除旧字段；未知 schema 一律失败关闭。
