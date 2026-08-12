# GMGN 稳定身份、历史与名称

## Goal

为 GitHub 候选和 CNB GMGN 选拔建立唯一、跨运行稳定且可安全公开关联的身份与历史层：内部 canonical fingerprint 不受源名称和输入顺序影响；公开只使用带版本密钥的 HMAC `candidate_id`；`history.json` 只在有效且被接受的发布中原子推进；亚洲节点连续 3 次可计数的零响应运行才从候补移除，恢复后自动回归；输出名称在源改名、排名、层级变化、移除和恢复之间保持稳定。

## Dependencies and Ownership

- 前置契约：父任务设计、`aggregator` specs 与 V2 状态枚举已经冻结。
- 本任务独占 canonical fingerprint、HMAC candidate/server/endpoint/exit ID、identity key/epoch migration、history reducer 和 stable output-name allocator。C1/C2/C4 必须消费这些 API，不得实现本地变体。
- C1 可以并行实现来源健康和 metadata，但最终 `candidate-metadata.json` 联调依赖本任务的 `candidate_id`；C2 的分片也使用同一 ID。
- C2 提供 `valid_run` 测量和每 candidate 20 轮汇总；C1 提供 source health/confirmed missing；C4 提供本轮拟议 tier/地区/多样性决定；本任务只归约身份和历史，不重复这些策略。
- C5 负责把 staged history 与 profile/status/diagnostics 原子发布。C3 可以生成下一版 history，但不能单独推进远端权威状态或修改 `.cnb.yml`。
- C3 不执行 DNS、HTTP、出口查询或 Mihomo 网络 I/O；只对 C1/C2/C4 已验证的 proxy/public IP 做 deterministic identity。候选解析安全由 C1/C2 承担，网络层私网/metadata deny 与 Secret 隔离由 C5 承担。

## Requirements

### R1. 唯一 canonical fingerprint owner

- 对已经通过配置验证的 proxy 生成 canonical JSON：递归排序 mapping key，保持 list 顺序和标量类型，使用 UTF-8 紧凑编码。
- `name`、provenance、GitHub/CNB 测量、output name、candidate/server/endpoint/exit ID 等非连接字段不参与 fingerprint；协议、server、port、凭据、transport、TLS/REALITY 和所有允许的连接字段必须参与。
- 未知/未允许字段在 identity 前由配置 validator 拒绝，不能通过随意忽略未知字段制造身份碰撞。
- 内部 fingerprint 使用完整 SHA-256，只能存在于私密内存/状态迁移工具；不得写入任何公开 status、metadata、diagnostics、README 或异常。
- 同一配置仅改名、provenance 或输入 key 顺序时 fingerprint 不变；任一连接相关值/类型变化时 fingerprint 必须变化。

### R2. 版本化 HMAC 公共身份

- `candidate_id` 格式固定为 `c1_<24 lowercase hex>`，内容是把 `identity_key_version`、`identity_epoch` 与域分隔纳入消息的 `HMAC-SHA256(identity_key, canonical_fingerprint)` 截断；server、endpoint、exit 分别固定为 `srv1_<24hex>`、`ep1_<24hex>`、`exit1_<24hex>`，使用不同 domain，禁止跨类型碰撞。
- `exit_id(public_ip)` 必须先用标准 IP parser 规范化：IPv4 使用 canonical dotted decimal，IPv6 使用 RFC 5952 compressed lowercase；拒绝无效、非 global、loopback、link-local、private、multicast、reserved 和 unspecified 地址。规范化后的 ASCII bytes 才进入 `exit` domain HMAC，原始出口 IP 不进入公开 history/diagnostics。
- 所有公开身份产物同时记录 `identity_key_version` 和 `identity_epoch`；密钥只从 `GMGN_IDENTITY_HMAC_KEY` Secret 注入，版本/epoch 由 `GMGN_IDENTITY_KEY_VERSION`、`GMGN_IDENTITY_EPOCH` 提供，均不得进入日志异常中的 secret 内容。
- 缺少密钥、未知 identity key version/identity epoch、ID 格式错误或同一快照出现 HMAC 冲突时失败关闭。
- C3 固定 `tests/fixtures/gmgn_identity_v1.json` 非秘密 test vector（假 proxy/server/endpoint/global IPv4/IPv6）；GitHub producer 与 CNB validator 用各自配置的生产 key 计算四类 public IDs 并比较。HMAC key 只进入独立受控 identity stage，该 stage 不执行订阅脚本、不访问原始来源、不启动 Mihomo、不持发布 token。
- key/epoch rotation 对当前 profile/metadata 中可重算的节点执行 old-ID → new-ID 一对一迁移并记录事件。已经移出当前快照、无法安全重算的 removed tombstone 保留旧 `candidate_id`、旧 identity key version/epoch 和名称占用，标记 `legacy_identity=true`，不得伪造新 ID。
- 只要仍有 legacy tombstone，旧 key 就必须留在受控 key registry。节点重现时先计算 active ID，再用仍受支持的 legacy key/epoch 计算旧 ID；匹配 tombstone 后迁移到 active ID 并保留 output name/history。缺旧 key、映射冲突或 legacy 节点无法审计时保留 last-good。
- removed tombstone 初始保留期为 90 天；不允许静默自动 GC。超过保留期后只能通过显式、可审计的 GC 事件移除，证据至少包含 candidate ID、output name、removed reason、last seen 和 age。只有 legacy 数量为 0，或所有剩余 legacy 已完成审计 GC 后，旧 key 才可退役。

### R3. `history.json` v1

权威历史固定为 `kind=cnb-gmgn-history`、`schema_version=1`，至少包含：

- `identity_key_version`、`identity_epoch`、history/selection policy version；
- `last_accepted_run_id`、source profile SHA、accepted_at；
- 以 `candidate_id` 为 key 的 nodes；
- 每节点稳定 `output_name`、节点自身 ID identity key version/identity epoch、legacy/tombstone retention 字段、当前/上一 state、最后迁移 reason、`bad_run_streak`、last counted-bad source SHA/time、最近至少 3 个 accepted valid observations（含 `counted_bad`）、first/last seen/selected、source status、最后测量摘要及 C4 出口 cache 的版本化安全容器。

公开 history 只以 HMAC `candidate_id`/`exit_id` 关联节点与出口，不包含完整 proxy、server/port、凭据、裸 fingerprint、原始出口 IP、私有 URL、原始错误或 Runner IP。Schema 使用严格字段集合；未知版本/字段和坏状态失败关闭，不将解析失败视为首发。

V1 不静默自动垃圾回收 removed tombstone/name mapping。90 天后只允许显式 audited GC；未 GC 的 tombstone 在节点恢复时继续提供旧 ID 匹配和稳定名称。

### R4. 可计数运行与原子提交

- history reducer 是纯函数：读取上一版已验证 history、本轮 C2 valid measurement、C1 source state 和 C4 staged decision，生成 staged next history；不就地修改 previous。
- 每个 `valid_run=true` 且最终 accepted 的新 run 都必须推进顶层 `last_accepted_run_id/source_sha/accepted_at` 并记录 observation。只有零响应 bad streak 增量额外要求 source/profile SHA 与上次 counted-bad SHA 不同、距上次 counted-bad 至少 21600 秒、不是重复 accepted run、来源仍存在且配置有效。
- 新 SHA 的 accepted zero-response run 若距上次 counted-bad 不足 21600 秒，仍随 current bundle 写入 history，observation 标记 `counted_bad=false`，但 streak 不增加。accepted responsive run 不受 21600 秒限制，应立即清零 streak并恢复/晋级。
- 已经 accepted 的同 source SHA/run ID、同 SHA 的第二次结果或基础设施 retry 不得产生第二次 transition；只有此前未 accepted 的基础设施失败 retry 才可成为该 SHA 的首次 accepted run。
- `valid_run=false`、C4/C5 rejected、previous/bundle/Mihomo/远端 smoke 失败才保持权威 history 序列化字节和 last accepted run 完全不变。
- staged history 只有与同一 run 的 profile/status/diagnostics 一起被 C5 接受并原子发布后才成为权威；失败运行只保留脱敏/私密证据。

### R5. 亚洲三次保护状态机

本任务使用以下稳定 state 标识：`asia_core`、`asia_flexible`、`asia_manual_candidate`、`history_protected`、`non_asia_stable`、`unknown_region`、`removed_bad_streak`、`removed_source_missing`、`removed_invalid_config`。

- 新亚洲候选本轮 `response_count >= 1`：bad streak=0；按 C4 staged decision 进入 core/flexible/manual candidate。
- 新候选 20 轮零响应：不进入 CNB 正式输出，也不新建需要公开的 history 节点，只保留在 C1 GitHub 候选池。
- 之前已是亚洲 core/flexible/manual/history-protected 的节点，本轮 accepted 且零响应：进入/保持 `history_protected`；只有 `counted_bad=true` 才 streak +1，第 1、2 次计数仍保留，第 3 次进入 `removed_bad_streak`。
- 任一新的 accepted valid run 重新 `response_count >=1`：不受 21600 秒限制，bad streak 立即清零；按 C4 staged decision 自动进入 manual/core/flexible，并记录 `recovered_response` 或 `recovered_quality`。
- C1 `confirmed_missing` 或配置无法被 Mihomo 加载时可立即进入对应 removed state；暂时来源抓取失败/使用 last-good 不增加 streak、不直接移除。
- 非亚洲不享受三次零响应候补保护；其是否进入 history 由 C4 的严格选择结果决定。

### R6. 稳定 output name

- 首次进入任一可发布 state 时分配并持久化 `output_name`；优先使用清洗后的安全 source alias，不附加延迟、成功率、排名、tier 或运行时间。
- 已有 mapping 在源名称变化、输入重排、排名/层级变化、候补降级、移除和恢复时保持不变。
- 同名冲突使用 candidate ID 的稳定后 6 位作为后缀，格式固定为 `<base> [<id6>]`；不依赖遍历顺序或当轮排名。
- 名称不得与 Clash 内建目标或固定组名冲突；清洗后为空、超限或冲突时使用版本化稳定 fallback。
- bootstrap 现有合法 GMGN profile 时尽量保留其现有唯一名称，并记录 `bootstrap_legacy_profile`；不能从上一版组名反推出 3 次 streak。

### R7. 可解释迁移与恢复

- 每次状态变化记录固定 reason enum、from/to state、run ID、source SHA 和时间；不记录原始错误。
- 最近观察至少能重建 `core → bad1 → bad2 → bad3/remove → recovered`，并区分 invalid/retry/spacing/source missing。
- C4/C5 的公开 node status 可以用 `candidate_id` 定位 output name、tier、20 轮汇总和迁移 reason；不得公开 fingerprint 或密钥。

### R8. 兼容和上线边界

- 新 identity/history API 先以默认关闭的 adapter 接入 `scripts/cnb_gmgn_publish.py`，不改变当前正式选择、组名或远端分支。
- `.cnb.yml`、bundle/CAS、真实地区/分组和默认入口分别由 C5/C4/C7 负责。
- 首次 V2 shadow 必须显式从 current profile/status bootstrap；previous 读取失败时不允许空 history 首发覆盖现有正式输出。

## In Scope

- canonical fingerprint 与 HMAC candidate/server/endpoint/exit ID 单一实现和测试向量。
- identity key version、显式 rotation/migration 和失败关闭。
- `history.json` v1 schema、严格 loader/validator、纯 reducer、staged writer。
- 亚洲 3 次 bad-run、恢复、source missing/invalid 立即移除和运行计数门槛。
- stable output name、legacy bootstrap 和公开 candidate ID 映射接口。

## Out of Scope

- 来源抓取、last-good 和 confirmed-missing 的判定实现（C1；C3 只消费状态）。
- GMGN 20 轮、valid-run、control/canary（C2）。
- 真实地区、质量阈值、多样性、最终 tier 与 Clash 分组（C4；C3 只持久化 staged decision）。
- 原子 bundle、CAS/lease、trigger、远端 smoke（C5）。
- 外部来源和入口迁移/gstatic 冻结（C6/C7）。

## Acceptance Criteria

- [ ] canonical test vectors 证明改名/provenance/key 顺序不改 fingerprint，protocol/server/port/credential/transport/TLS/REALITY 任一连接字段变化都会改 fingerprint。
- [ ] candidate/server/endpoint/exit HMAC 使用域分隔且 ID 格式、截断、identity key version、identity epoch 有固定测试向量；IPv4/IPv6 canonicalization、非公网拒绝和跨 domain 不碰撞均被测试，公开 fixture 不含裸 fingerprint、原始出口 IP 或 secret。
- [ ] GitHub/CNB 对同一非秘密 fixture 的四类 public IDs 完全一致；key bytes/version/epoch 任一不一致都在抓取后的受控 identity preflight、测速前失败，collection/probe/publisher 不持 HMAC key。
- [ ] 缺 key、未知版本、HMAC 冲突或可重算节点迁移不全均失败关闭；快照外 tombstone 在轮换时保留 legacy ID/name，重现后可借旧 key迁移，90 天 audited GC 后旧 key 才可安全退役。
- [ ] `history.json` 严格 schema/字段/时间/计数验证通过；坏 JSON、未知 schema、重复/无效 ID、last accepted 关联不一致均拒绝。
- [ ] 合成序列覆盖 `core → bad1/protected → bad2/protected → bad3/removed → recovered`，每一步 state、streak、reason 和 recent observations 正确。
- [ ] invalid/rejected/publish-failed run 保持 history 字节不变；duplicate accepted SHA/retry 不产生第二次 transition；新 SHA `<21600s` 的 accepted zero-response run 推进 last accepted/observation 但 `counted_bad=false` 且 streak 不增。
- [ ] 在 bad1 后不足 21600 秒出现 accepted responsive run 时，streak 立即清零并恢复/晋级；该快速恢复不被 spacing gate 阻止。
- [ ] 暂时 source failure/last-good 不计数；`confirmed_missing` 和 invalid config 可立即移除且 reason 不混淆。
- [ ] 新亚洲零响应节点不进入正式/history 输出；新亚洲至少一次响应进入 manual 或 C4 拟议主力并清零 streak。
- [ ] source rename、输入重排、排名/tier 变化、同名冲突、removed 后 recovery 均保持既有 output name；名称不含动态测速字段。
- [ ] legacy bootstrap 保留可验证唯一名称；未知旧 schema/profile/status/hash 失败关闭，不从组名虚构历史。
- [ ] reducer 不就地修改 previous；每个新 accepted valid run 推进 `last_accepted_run_id`，只有 invalid/rejected/publish failure 路径断言 previous 序列化字节不变。
- [ ] 目标测试、完整 `unittest`、JSON 回读、敏感字段扫描和 `git diff --check` 通过。

## Rollback Point

本任务完成时 identity/history adapter 默认关闭，当前 GMGN publisher 和远端分支不变。回滚只需停止使用新 adapter 并继续当前无 durable history 的路径；不得删除已生成的 migration evidence。所有本机历史 fixture 写入 `D:\xiangmu\linshi\gmgn-history-identity`。
