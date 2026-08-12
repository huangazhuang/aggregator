# 外部亚洲来源受控扩展

## Goal

在不把高度重复、不可审计或会让 CNB 超出预算的节点池无界加入生产的前提下，完成至少一个外部 HK/JP/KR/SG/TW 来源的边际增益评估与可撤销接入。GitHub 仍负责扩大“安全、最新、独立”的宽候选池；新增来源只进入 C1 冻结的 `clash.yaml + status.json + candidate-metadata.json` 契约，由 CNB 后续完整执行 GMGN 20 轮。

优先顺序冻结为：先评估 `awesome-vpn/awesome-vpn`；若其未通过增益/安全/新鲜度门禁，则评估并限额接入 Mahdibland 亚洲子集。V2Hive 本任务只允许作为带严格限额的 discovery reservoir，不允许全量直灌 CNB。

## Dependencies

- 必须等待 `08-11-github-candidate-provenance-v2` 冻结 source registry、source-health、last-good、metadata、C3 identity API 接口和候选发布门禁。
- 复用 C3 作为唯一 fingerprint/HMAC identity owner；本任务不得自行定义第二套精确去重或公开 ID。
- 接入后的候选 snapshot 由 C5/C7 测速与发布，本任务不修改 CNB 测量或选择策略。
- C7 的真实影子验收必须包含已接入来源后的容量、地区增益和失败隔离证据。

## In Scope

- 实现可重复的外部来源审计，输出 raw、配置有效、精确唯一、唯一入口、与现池重叠、五地区、新鲜度和生成/验证透明度。
- 通过 source registry/feature flag 受控接入第一个通过门禁的来源。
- 对每源、每地区和每入口设置固定预算，避免一个聚合源占满候选或 CNB 时间预算。
- 将新来源 provenance、last-success、失败/恢复状态和地区证据写入 C1 契约。
- 为来源失败、内容暴增、内容缩水、格式变化、私网/元数据端点和回滚提供测试。

## Out of Scope

- 全量接入 V2Hive、Mahdibland 5k+ 宽池或任何未经限额的大型 reservoir。
- 以原始 YAML/URI 行数代替稳定 identity、唯一入口或边际增益。
- 修改 GMGN 20 轮、1000 ms、900 秒观察窗口、亚洲/非亚洲阈值、历史或最终分组。
- 拆分仓库、创建 worker 仓库或把多个外部源同时无门禁上线。
- 将私有订阅 URL/token、可逆来源标识或未经显式许可的私有派生代理公开。

## Requirements

### R1. 统一评估报告

- 每个待评估来源必须通过同一评估器，记录：`raw_count`、`valid_count`、`exact_unique_count`、`unique_endpoint_count`、`overlap_fingerprint_count`、`overlap_endpoint_count`、HK/JP/KR/SG/TW 数量、协议分布、最新提交/产物时间、生成与验证透明度、解析/安全错误分布。
- 精确 identity、endpoint/server ID 必须调用 C3 冻结 API；来源 metadata 使用 C1 的稳定 source ID 和 provenance schema，并分别记录 `identity_epoch` 与 `identity_key_version`，不得用 ID 前缀替代任一版本字段。
- 评估结果必须区分“来源自身重复”和“与现有 candidate snapshot 重叠”；不得只报告总行数。
- 真实网络审计证据和下载内容写入 `D:\xiangmu\linshi\asia-source-expansion-v2`，不把临时上游快照提交到仓库。

### R2. 接入门禁

- 来源产物或仓库最后有效更新时间不得早于评估时 72 小时；暂时网络失败不得被误判为内容为空。
- 经过 allowlist、私网/loopback/link-local/云元数据拒绝和精确去重后，必须至少贡献 5 个现池中不存在的目标亚洲唯一 endpoint，且覆盖至少 2 个 HK/JP/KR/SG/TW 地区，才能作为本任务的生产接入来源。
- 来源中可解析的目标亚洲记录与现池 endpoint 重叠率不得高于 80%；超过时可继续作为研究 reservoir，但不作为本任务的生产贡献。
- 必须能说明其产物生成/地区标注/验证的最低透明度；无法审计生成方式的来源只能作为 discovery reservoir，不能直接获得 unlimited trusted source 地位。
- 第一个满足上述全部门禁的来源必须通过独立 feature flag 接入；如果 `awesome-vpn` 不满足，则继续评估 Mahdibland 的限额亚洲子集，直到一个来源满足。若候选均不满足，任务不得伪造接入完成，应保持现池并报告门禁证据。

### R3. 固定限额与容量预算

- 单一新增来源每次最多贡献 300 个精确唯一候选；单个目标地区最多 100 个；同一 `server:port` 最多保留 3 个协议/凭据变体。超出时按新鲜度、来源内唯一性、地区缺口和稳定 identity 确定性裁剪。
- V2Hive 若作为 reservoir，抓取/解析阶段也必须使用上述限额，且不得把五地区 4578 条全量直接写入 candidate snapshot。
- 接入前后必须估算 `4 shards × 20 rounds × request timeout/workers` 的最坏耗时；最终 candidate 总量必须低于 5000，且估算值必须低于 C2/CNB 版本化运行预算。
- 若加入来源会触发候选总量或运行预算上限，本轮 source integration 必须 fail-closed，不得通过降低 GMGN 轮数、缩短 900 秒观察窗或预先删除亚洲候补来腾出容量。

### R4. 来源健康、last-good 与发布保护

- 新来源必须拥有稳定 source ID、last-success 内容 hash、成功时间、raw/unique/region 计数、连续失败、恢复和 confirmed missing 状态。
- HTTP/429/解析失败或暂时空响应进入观察并使用仍在 C1 TTL 内的 last-good；不得发布“新增来源瞬时消失导致亚洲大幅掉量”的缩水 snapshot。
- 来源恢复后自动重新纳入；格式不支持、内容安全失败或缓存过期时，候选发布门禁必须保留上一版而不是继续使用不可信输入。
- 精确重复配置必须合并全部 provenance 和地区证据；不得因展示名称排序丢失新增来源贡献或亚洲保护证据。

### R5. 不可信输入和公开边界

- 只接受项目明确支持的协议/字段；域名解析后仍需拒绝 loopback、link-local、私网、组播和云元数据地址。
- 采集、解析和评估阶段不持有正式分支写 token 或私有订阅 secrets；publisher 只消费经过验证的固定 snapshot。
- 公共 `candidate-metadata.json` 只能记录安全 source ID、时间、地区证据和非敏感聚合字段，不得包含私有 URL/token、原始上游凭据或可逆私有来源标识。
- 私有来源派生代理是否公开必须有显式 `publish_derivatives=true`；本任务不隐式改变既有私有源发布行为。

### R6. 可撤销接入

- 每个新来源由一个独立、默认可关闭的 registry/feature flag 控制；关闭单一 flag 即可停止后续采集，不影响其他来源。
- 关闭来源后仍由 C1 的 confirmed-missing/last-good 规则决定已有 candidate 的自然退出，禁止把暂时关闭当成一次 GMGN bad run。
- 回滚不得删除历史 source-health 或 provenance 记录；需要保留最近一次成功与停用原因，便于恢复。

## Acceptance Criteria

- [ ] `awesome-vpn` 生成完整、可重复的边际增益报告；如果未过门禁，Mahdibland 限额亚洲子集生成同格式报告。
- [ ] 至少一个来源通过新鲜度、安全、净新增 endpoint、地区覆盖、重叠和容量门禁后由独立 flag 接入；若没有来源通过，任务保持 fail-closed 并明确不能宣告完成。
- [ ] 接入来源最多贡献 300、单地区最多 100、同入口最多 3 个变体；输入重排不改变裁剪结果。
- [ ] 新 candidate snapshot 仍使用 `clash.yaml + status.json + candidate-metadata.json`，profile hash 与 metadata 绑定，不新增重复代理载荷的 `candidates.jsonl`。
- [ ] status/metadata 独立包含并校验 `identity_epoch` 与 `identity_key_version`；缺失或未知迁移时拒绝候选发布。
- [ ] 新来源的 source ID、last-success、地区/唯一性计数和 provenance 能由 C1 status/metadata 查询，公开文件无 URL/token/凭据泄漏。
- [ ] 来源 429、超时、空响应、格式变化、内容突然减少或某地区归零时保留 last-good，不能覆盖异常缩水候选池；恢复后自动重新纳入。
- [ ] 私网、loopback、link-local、云元数据和不支持协议/字段被拒绝，且采集阶段没有发布凭据。
- [ ] 接入后 candidate 总数小于 5000、CNB 最坏耗时低于版本化预算；不得通过减少 20 轮或 900 秒观察窗通过预算。
- [ ] 关闭该来源的单一 flag 可回滚后续采集，其他来源和现有 last-good 不受影响。
