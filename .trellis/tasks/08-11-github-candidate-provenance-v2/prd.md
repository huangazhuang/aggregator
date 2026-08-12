# GitHub 候选池与 provenance V2

## Goal

把 GitHub `clash-verge-output` 从“只有代理列表和总数”的产物升级为可追溯、可失败关闭的宽候选快照：尽可能保留新鲜、配置有效的香港、日本、韩国、新加坡、台湾候选，精确重复配置只保留一份但合并全部来源与亚洲证据，并向 CNB 提供与 `clash.yaml` 同一快照的 `status.json` 和 `candidate-metadata.json`。

本任务不负责判断节点是否适合进入最终 GMGN 主力；它负责保证 CNB 收到的是宽、稳定、可解释且没有异常缩水的候选输入。

## Dependencies and Ownership

- 前置契约：父任务 `08-11-gmgn-asia-selection-v2` 的 PRD、设计、实施计划和 `aggregator` 根规范已经冻结。
- C3 `08-11-gmgn-history-identity` 独占 canonical proxy fingerprint、HMAC `candidate_id`、`server_id`、`endpoint_id` 与 identity key version/epoch 的实现。本任务可以并行完成来源健康、provenance、发布门禁和测试，但不得另写第二套指纹/HMAC；最终验收必须接入 C3 的共享 API。
- 本任务是 C4 真实地区/选择、C5 事务发布/触发和 C6 外部来源接入的前置。C6 才负责加入新的外部亚洲源，本任务只提供安全接入和边际增益所需的契约。
- DNS/私网防护分层所有权固定：C1 负责候选生成时的 endpoint 字符串/IP/域名解析校验；C2 在每次 probe 启动前再次解析并拒绝安全状态漂移；C5 负责 GitHub/CNB job 的网络层 deny（私网、metadata、link-local）和探测 job 不持有发布凭据。C1 的解析检查不能替代 C5 的网络隔离。
- `.github/workflows/clash-verge-auto.yml` 在本任务阶段由 C1 独占；C5 只能在 C1 完成后接手“新 SHA 触发 CNB”的尾段。
- GitHub identity producer 与 CNB identity validator 必须配置完全相同的 `GMGN_IDENTITY_HMAC_KEY` 字节、`identity_key_version` 和 `identity_epoch`。C3 提供不含真实凭据的固定 fixture；C1 把该 fixture 的 candidate/server/endpoint/exit public IDs 写入 metadata preflight，C2/CNB 在任何 Mihomo 启动前重算并逐项比较，不一致即失败关闭。

## Requirements

### R1. 固定的候选快照三件套

一次被接受的 GitHub 发布必须在同一提交中生成：

- `clash.yaml`：给用户和 CNB 使用的宽候选代理配置，不附加 provenance 私有字段；
- `status.json`：`kind=github-candidate-status`、`schema_version=2`；
- `candidate-metadata.json`：`kind=github-candidate-metadata`、`schema_version=2`，只保存元数据，不复制完整 proxy 配置。

`status.json` 必须记录 `snapshot_id`、`run_at`、`main_sha`、`profile_sha256`、`candidate_metadata_url`、`candidate_metadata_sha256`、`candidate_metadata_schema_version`、`candidate_metadata_count`、`identity_key_version`、`identity_epoch`、原始/配置有效/精确唯一/唯一入口/最终候选数量、HK/JP/KR/SG/TW 与未知数量、来源健康计数、GitHub 已测/亚洲绕过计数、策略版本及与上一版的变化。

CNB 或本地 validator 必须能使用 C3 的 identity API，为 `clash.yaml` 的每个 proxy 重算 `candidate_id`，并与 metadata 建立一对一关系；metadata 顶层还必须包含版本化 `identity_preflight` 固定 fixture 的四类 public IDs。缺项、重复项、孤儿 metadata、preflight 不一致，以及 URL/SHA/schema/count/identity key version/identity epoch 任一不一致均拒绝快照。

### R2. provenance 合并而不是重复项覆盖

- 精确重复配置按 C3 canonical fingerprint 合并，不能按名称或输入顺序决定保留哪一份证据。
- 合并后必须保留全部安全 `source_ids`、别名、首次/最后见到时间、来源最近成功时间、地区提示和证据、GitHub 检查状态、协议及 HMAC 化的 server/endpoint 标识。
- 任一来源提供可靠 HK/JP/KR/SG/TW 证据时，合并记录保留该证据；普通别名不能覆盖 `ASIA-KEEP` 或国家专用来源证据。
- 公开来源使用稳定、可审计的别名；私有/动态来源只使用持久化不透明 ID。不得公开私有订阅 URL、token、账号、可逆来源标识或原始抓取错误。
- 私有订阅派生代理只有显式 `publish_derivatives=true` 时才允许进入公开候选快照。

### R3. 亚洲宽池语义

- 名称或可靠来源证据识别为 HK/JP/KR/SG/TW 的配置有效候选继续绕过 GitHub 单轮 liveness、可选中国 TCP 探针和 GMGN/Google/YouTube 严格淘汰。
- 单轮 Timeout、一次抓取抖动或 GitHub Runner 的网络差异不得删除亚洲候选。
- 补齐 `TPE`、`KHH`、`NRT`、`KIX`、`ICN`、`SIN` 等安全机场代码；单字、状态文本和普通词不得误判为亚洲。
- `candidate-metadata.json` 必须明确记录 `github_check_state` 为 `passed`、`failed` 或 `bypassed_asia`，不能用一个含糊的 `alive_check=true` 宣称所有候选都已测活。
- 名称/来源只产生地区提示，不能在本任务中冒充真实出口验证；真实出口由 C4 处理。

### R4. 来源 last-good、观察与确认消失

- 固定 raw 源和动态来源使用同一来源健康模型：`healthy`、`using_last_good`、`observing_failure`、`confirmed_missing`、`recovered`。
- HTTP/429/限流/超时/解析失败只进入观察状态；使用上一版快照中不超过 48 小时的 last-good 候选，不把本轮失败解释为来源消失。
- 只有至少 3 次成功采集都确认某候选缺失、相邻确认至少间隔 6 小时，并且距该候选最后一次成功见到已满 48 小时，才可标记 `confirmed_missing`。
- 来源恢复后自动恢复为 `healthy`，其候选重新参与合并；不得要求人工删除 tombstone。
- previous profile/status/metadata 暂时不可读、坏 JSON/YAML 或 hash/schema 不一致时失败关闭；只有远端 ref 查询明确证明分支从未存在时允许首发。

### R5. 来源探索配额

- 机场运行上限 192 时，初始配额固定为 60% known-good、20% untried、20% due-retry；某桶未用完才允许其他桶占用。
- 输入顺序不得让 known-good 永久挤占 untried/due-retry。
- 选择结果和未使用配额必须进入安全状态统计，以便证明新来源持续获得探索机会。
- 修复任务去重只比较第一项的问题，重复订阅任务不得重复消耗下载、解析和测速预算。

### R6. GitHub 发布掉量保护

候选发布 policy v1 固定以下初始门槛，修改时必须提升 policy version 并更新测试：

- 总候选数至少保留上一版的 60%；
- 受保护亚洲总量至少保留 70%；
- HK/JP/KR/SG/TW 各至少保留上一版的 50%；
- 上一版非零的目标地区本轮不得归零；
- 固定来源成功或安全使用未过期 last-good 的 quorum 至少为 80%。

任何门槛失败都不得覆盖 last-good；80 个最终 GMGN 节点与本任务无关，不能用于放宽 GitHub 候选发布门槛。

### R7. 不可信输入安全

- 外部代理配置只允许项目明确支持的协议和字段，且必须通过现有 Mihomo 配置验证语义。
- 代理 server 为 IP 或解析后的地址时，拒绝 loopback、link-local、私网、组播、保留地址和云元数据地址；非法端口和不可接受协议直接标记 invalid，不进入候选快照。
- 域名在候选生成时解析全部 A/AAAA 并要求每个结果可接受；metadata 记录安全检查版本/时间，不保存原始解析 IP。单 hostname 的 `EAI_AGAIN/EAI_FAIL` 不得直接代表整个 Runner DNS 故障：目标有界重试耗尽后必须在同一 resolver 上执行多 canary 健康检查并再观察目标；canary 健康且本轮异常 hostname 未超过版本化比例上限时，只隔离该 hostname，绝不把未解析节点判为安全。canary 异常、普通 resolver 异常或批量异常超限仍整轮失败关闭。DNS rebinding 的最终 TOCTOU 防护由 C2 启动前重查和 C5 网络层 deny 共同承担。
- 收集/解析/网络探测阶段不得持有正式输出分支写凭据；发布阶段只消费已经校验的 staging 快照。
- HMAC key 只注入独立受控 identity producer/validator stage。该 stage 只消费配置安全校验后的固定 staging snapshot/fixture，不执行订阅脚本、不访问原始来源、不启动 Mihomo、也不持有发布 token；collection/probe/publisher job 均不得同时持有 HMAC key 与不可信输入处理能力。
- 日志、状态和 metadata 不得包含订阅 secret、代理凭据、原始错误或 Runner 私网地址。

### R8. 兼容与上线边界

- 本任务完成时只交付 V2 生成、校验和默认关闭的集成能力，不启用新 SHA 自动触发，不切换用户推荐入口，不修改 CNB 正式/gstatic 分支。
- C5 接管事务发布前，现有 GitHub 生产路径必须可通过单一开关保持原行为；V2 失败不得破坏当前 `clash-verge-output` last-good。
- 文档迁移和新外部源接入分别属于 C7 和 C6。

## In Scope

- 候选来源健康、last-good、探索配额、任务去重和安全清洗。
- 精确配置去重时的 provenance/亚洲证据合并。
- `clash.yaml`、`status.json` v2、`candidate-metadata.json` v2 的生成、验证与本地/远端 smoke 支持。
- GitHub 候选发布的总量、地区、来源 quorum 与 previous fail-closed 保护。
- 对现有亚洲识别和 GitHub 检查绕过语义的测试强化。

## Out of Scope

- 新增或评估具体外部亚洲仓库（C6）。
- CNB 20 轮测速、有效运行门禁和并发标定（C2）。
- fingerprint/HMAC 算法和跨运行名称/历史实现（C3）；本任务只消费其 API。
- 真实出口/ASN 查询、最终质量阈值、多样性、Clash 目标分组（C4）。
- CNB trigger、CAS/lease、正式 bundle 和默认入口迁移（C5/C7）。

## Acceptance Criteria

- [ ] 同一配置来自普通源和亚洲专用源时，最终只有一个 proxy，metadata 保留全部来源、别名和亚洲证据；输入重排结果不变。
- [ ] `clash.yaml` 中每个 proxy 恰好对应一个 HMAC `candidate_id`，metadata 无孤儿、无重复、无裸 fingerprint；metadata URL/SHA/schema/count、`identity_key_version`、`identity_epoch` 均被 `status.json` 正确绑定。
- [ ] `status.json` 可观察到原始/有效/去重/入口/最终数量、五地区、来源状态、GitHub 已测与亚洲绕过数量，且 schema/kind/policy version 固定。
- [ ] 单个来源网络失败、429、解析失败或某目标地区异常归零时，未过期 last-good 被保留或整次发布失败关闭；last-good 分支内容不变。
- [ ] 只有 3 次成功确认、每次至少间隔 6 小时且最后见到超过 48 小时后，候选才成为 `confirmed_missing`；暂时失败不推进该计数，恢复后状态自动清零。
- [ ] previous 分支不存在与暂时不可读被明确区分；坏 previous JSON/YAML、hash、schema 或单边缺失均拒绝发布。
- [ ] 总量 60%、亚洲 70%、五地区 50%/不得归零、来源 quorum 80% 的精确边界均有通过和失败测试。
- [ ] known-good 超过 192 时，untried 与 due-retry 仍各得到固定配额；配额外溢和任务全量去重有确定性测试。
- [ ] `TPE/KHH/NRT/KIX/ICN/SIN` 被安全识别，短词/状态文本不误判；亚洲候选一次 Timeout 不会被 GitHub 网络步骤删除。
- [ ] 私网、loopback、link-local、云元数据等不可信 server 被拒绝；孤立的持续 DNS 临时失败在多 canary 健康和批量比例门禁下只隔离对应 hostname，canary/比例异常仍整轮失败；公开 JSON、日志与异常文本的凭据扫描通过。
- [ ] workflow/组件测试证明 collection job 无 HMAC key/发布 token，identity stage 无原始来源/Mihomo/发布 token，publisher 无 HMAC key；GitHub/CNB 对固定非秘密 fixture 产生完全相同的四类 public IDs，key bytes/version/epoch 任一不同都在测速前失败。
- [ ] V2 开关默认关闭，C1 完成后不会自动触发 CNB、不会切换用户入口、不会写入 gstatic 或当前 GMGN 正式分支。
- [ ] 目标测试、完整 `unittest`、JSON/YAML 回读和 `git diff --check` 全部通过。

## Rollback Point

在 C5 正式接入前，回滚只需关闭候选 V2 开关并恢复原 GitHub 生成路径；不删除任何远端分支或缓存。若 V2 staging 或 smoke 失败，当前 `clash-verge-output` tip 必须保持不变，失败证据只写入 `D:\xiangmu\linshi\github-candidate-provenance-v2`。
