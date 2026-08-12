# GMGN V2 跨层契约

本规范适用于 `.trellis/tasks/08-11-gmgn-asia-selection-v2` 及其子任务实现的 V2 路径。现有 V1 gstatic/GMGN 行为在迁移前继续保留；当本页与描述 V1 现状的其他规范发生冲突时，V2 代码以本页和已批准任务设计为准。

## 1. Scope / Trigger

以下任一改动必须使用本契约并同步 producer、consumer、validator、回放器、工作流和测试：

- GitHub candidate snapshot v2：`clash.yaml`、`status.json`、`candidate-metadata.json`；
- GMGN manifest/fragment v3、四分片 20 轮和 `valid_run`；
- canonical fingerprint、HMAC public identity、`history.json` v1；
- `clash-cn-gmgn-v2-shadow` 的原子 bundle、staging smoke、CAS/lease；
- 连续三次影子验收、正式 bundle 提升和 gstatic 冻结。

V2 影子阶段不得改写 `clash-cn-output` 或现有 `clash-cn-gmgn-output`。

## 2. Signatures

共享实现必须只有一个 owner，并提供等价于以下接口的可测试纯函数边界：

```python
def canonical_fingerprint(proxy: Mapping[str, Any]) -> str: ...

def legacy_v1_proxy_fingerprint(proxy: Mapping[str, Any]) -> str: ...

def public_identity(
    kind: Literal["candidate", "endpoint", "server", "exit"],
    value: str | bytes,
    *,
    key: bytes,
    identity_key_version: str,
    identity_epoch: str,
) -> str: ...

def validate_candidate_snapshot(
    profile_bytes: bytes,
    status: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> CandidateSnapshot: ...

def validate_gmgn_run(
    manifest: Mapping[str, Any],
    fragments: Sequence[Mapping[str, Any]],
) -> ValidRun: ...

def reduce_history(
    previous: Mapping[str, Any],
    *,
    run: ValidRun,
    snapshot: CandidateSnapshot,
    source_events: Sequence[SourceEvent],
    selection_decisions: Mapping[str, StagedSelectionDecision],
    region_decisions: Mapping[str, StagedRegionDecision],
) -> Mapping[str, Any]: ...

def build_publish_bundle(...) -> PublishBundle: ...

def minimal_mihomo_env(work_dir: Path) -> dict[str, str]: ...
```

C3 是 fingerprint/HMAC identity 唯一实现 owner；C1/C4/C5 只消费该 API 和版本化 fixture，不能自行重写 fingerprint。

`canonical_fingerprint()` 是 Candidate/GMGN V2 的严格连接 schema 边界。V1 shadow、V1 publish、旧 GitHub candidate baseline 和旧 GMGN history bootstrap 只能显式调用 `legacy_v1_proxy_fingerprint()`；它必须复现迁移前“去掉 name 后稳定 JSON”的旧语义。禁止为了兼容旧 profile 放宽 V2 schema，也禁止让 V1 默认关闭路径间接调用严格 fingerprint。已经进入 V2 的 active identity migration/reconcile 继续使用严格 canonical identity。

发布和重试工作流还必须调用共享 CLI 契约，而不是在 YAML 中重写校验逻辑：

```text
python -m scripts.validate_public_outputs candidate \
  --profile <local-clash.yaml> --status <local-status.json> \
  --metadata <local-candidate-metadata.json> \
  --profile-url <revision-bound-url> --status-url <revision-bound-url> \
  --metadata-url <revision-bound-url> --expected-revision <commit-or-ref> \
  --expected-main-sha <sha> --scope {staging,current} --evidence-dir <private-dir>

python -m scripts.cnb_gmgn_v2 prepare \
  --preflight <complete-preflight.json> --trigger <complete-trigger.json> ...
```

## 3. Contracts

### Candidate snapshot v2

- Candidate `status.json` 与 `candidate-metadata.json` 当前均为 schema 2；共享常量由 `scripts.candidate_contract` 持有，producer、CNB consumer、外部来源 evaluator 和 remote smoke validator 必须导入同一常量，不得各自硬编码“当前版本”。两份 sidecar 的 `kind`、自身 schema 及 status 中的 metadata schema binding 任一不符都失败关闭。
- `status.json` 必须绑定 `profile_sha256`、`candidate_metadata_sha256`、对应 schema/count、`identity_key_version`、`identity_epoch`、来源/地区门禁结果和 `main_sha`。
- `candidate-metadata.json` 以 HMAC `candidate_id` 为 key，并能与 `clash.yaml` 中每个规范化代理一一对应；不得重复保存完整 proxy 载荷。
- 裸 fingerprint 只存在于受控内部状态；公开 candidate/endpoint/server/exit 标识均为带域前缀的 HMAC opaque ID。
- 来源是否仍存在必须依据过滤前的完整 collection provenance；GitHub 单轮严格过滤后的最终 profile 只能决定本次发布内容，不能把被过滤的非亚洲节点误记为 source missing，也不能由 last-good 将其重新带回。
- profile 内 canonical fingerprint 相同的精确重复配置必须确定性合并来源、别名和地区证据；validator 必须重算去重后 count、snapshot ID、publish gate 和嵌套 source-health 守恒关系。
- source quorum 只统计本轮配置的 fixed sources；本轮成功的 `healthy`/`recovered`/`confirmed_missing` 与受 TTL 约束的 `using_last_good` 算 acceptable，dynamic discovery source 不得稀释 quorum。temporary failure 只有在 last-good 未过期时可 acceptable；连续成功采集仍缺失且满足确认窗口后才可进入 confirmed missing。
- collection、identity、publish 三个 GitHub job 必须固定同一触发 SHA，并按 job 最小化 token/Secret；V2 build/validate 失败不得进入 publish。显式关闭 V2 时恢复纯 V1 文件集，不保留与 V1 status/profile 不匹配的陈旧 `candidate-metadata.json`。
- Candidate 三件套发布必须先构建不可变 orphan commit，推送到非入口 staging ref，对该 exact commit 做防缓存 remote smoke，再以 observed output tip 做 lease 提升。提升后的 `ls-remote` 命令失败、零/多结果、tip 不等于 candidate 或 current smoke 失败都属于同一回滚域；回滚只能以 candidate commit 为 lease 恢复 previous tip（首发则删除分支），随后再次读取并精确确认 previous tip。外部 writer 已改变 tip 时 lease 必须拒绝，任务仍失败。
- Candidate publish job 的 timeout 必须覆盖两轮 remote smoke 的完整最坏重试预算、checkout/build/push 和回滚验证余量；不得把单轮 smoke 的预算误当整份 job 的预算。
- 外部扩展来源必须同时满足 Candidate V2 总开关和来源独立 feature flag；来源 flag 不能绕过 V2 进入 V1 发布。审计评估与生产裁剪必须复用同一 C3 canonical fingerprint/endpoint 排序及 `300/source`、`100/region`、`3/endpoint` 限额。
- `<5000` 候选总量与 GMGN runtime budget 门禁必须在 source last-good 合并后的最终 snapshot 再执行一次；source metadata 记录 last-success content hash、候选/地区计数和连续失败，成功恢复立即清零失败 streak。

### GMGN run v3

- 固定 4 个独立分片、每候选恰好 20 轮、GMGN HTTP 200、`<=1000 ms` 达标、3000 ms 请求上限。
- 同一候选的轮次顺序执行；首末采样初始至少跨 900 秒。不同候选和分片可并行。
- manifest/fragment 必须共享 source/profile/metadata hash、main SHA、policy/schema、`identity_key_version`、`identity_epoch`、Mihomo hash 和 canary set。
- HTTP 403/429/5xx、DNS/TLS/connect/auth/controller 等错误优先于任何同时出现的 delay 字段；只有 HTTP 200 且 delay `<=1000 ms` 才计入达标响应。
- 每个分片必须使用独立 controller 端口、工作目录、fragment path 和 controller secret；secret 只以 hash 参与 manifest/runtime 绑定。20 轮每轮前后各记录一次 controller 健康证据，共 40 次，并验证 controller/runtime 版本一致。
- canary set hash 必须从实际 canary public IDs 重算；节点汇总、20 轮 round trends、error counts、delay 分布、control/canary/egress 证据必须逐层守恒，不能只验证顶层总数。
- `valid_run` 只有在来源、四片、轮数、观察窗、controller、逐片出口、direct control、canary 和事故门禁全部通过时为 true。

### Region and selection v2

- region observation/cache 必须绑定 `identity_key_version`、`identity_epoch`、固定 provider schema 和 query plan；新鲜 cache TTL 为 7 天，历史节点最多 30 天 grace。过期、身份不匹配、provider 未知或 query plan 不覆盖候选时降为 unknown，不得享受亚洲宽松阈值。
- selection input 必须严格消费完整 C1 metadata 与 C2 accepted measurement，重验 validity policy、固定 error taxonomy、`no_result`、20 轮前后半程和 error/response 守恒；不得接受兼容性猜测或缺字段旧 payload。
- 超过 150 时，亚洲候补按质量、地区缺口和 exit/server/ASN/source 集中度确定性裁剪；非亚洲始终最多 20。非空 `👆手动优先测速` 不加入 `DIRECT`，候补不得进入该组或自动组；`DIRECT` 只用于避免空组无有效引用。
- public node-status 使用固定 allowlist，至少解释 tier/reason、`under_1000_count`、`over_1000_count`、`timeout_count`、前后半程和慢响应；不得包含原始 IP、来源 URL、proxy 载荷或私密错误。

### History and publication

- `history.json` v1 只公开 HMAC `candidate_id`/`exit_id`；裸 fingerprint、出口 IP 或私密 cache 不得写生成分支。
- history/public identity consumer 必须严格校验类型和规范格式，不得把字符串计数、隐式 trim 的 ID/fingerprint 或非规范时间戳静默转换为有效值。
- publisher 不得持有 `GMGN_IDENTITY_HMAC_KEY`；它只能消费受控 identity 阶段生成并已验证的一一映射 public ID map。HMAC owner 只有共享 identity 模块。
- 新 SHA 的 processed-source owner 使用非用户入口 `clash-cn-gmgn-v2-processed/<source_sha>` ref，以 CAS 保存精确单文件 `state.json`；事件至少区分 queued/running/failed_infrastructure/rejected，并绑定稳定 attempt ID、`retry_of` 和 retry token hash。accepted 的唯一权威仍是已远端 smoke 的 bundle/history，processed ref 不复制 accepted 事务。
- normal trigger tag 是 queued 的外部证据；若 Runner 在写 processed ref 前失败，只有确认该完整 SHA 的 normal tag 已存在，显式 retry 才能以 deterministic primary attempt 为 `retry_of` 接管。全局 lock 释放后遗留 running 视为 hard-abort，可由新 retry token记录 interrupted failure 后接管；同 token/attempt 不得重复执行。
- identity/prepare 阶段必须同时消费完整、已验证的 `preflight.json` 与 `trigger.json`，并从中重验 source SHA、attempt ID、retry 关系、retry token hash 和 processed tip。不得把这些字段拆成可由 workflow 任意传入的裸 CLI 参数，否则伪造/陈旧参数可绕过 processed-state 的事务绑定。
- `accepted` 与 `bad_countable` 分离：每个新 source SHA 的 accepted valid run 都推进顶层 `last_accepted_run_id/source_sha` 并与 current bundle 同步；只有零响应、不同 source SHA、距上次坏计数至少 21600 秒的运行才执行 `bad_streak += 1`。
- 任一新 accepted valid run 只要 `response_count >= 1`，即使距上次坏计数少于 21600 秒，也立即把 streak 清零并恢复/晋级；duplicate SHA 与 infrastructure retry 不产生第二次 transition。
- temporary source failure、last-good carry-forward 和本轮未显式观察到的节点不得伪造零响应 observation、增加 bad streak 或降为 `history_protected`；恢复/晋级必须同时具有本轮 measurement 和 staged decision。
- key/epoch 轮换时，当前可重算节点迁移到新 ID；当前快照外 tombstone 保留 legacy ID/epoch 和名称占用。旧 key 在 legacy tombstone 存在时不得退役；节点重现后迁移。初始 tombstone retention 为 90 天，只有输出可审计 GC 证据后才可删除 legacy tombstone/退役旧 key。
- active identity 迁移、新 ID 与 legacy tombstone/名称占用发生碰撞时必须失败关闭；legacy bootstrap 必须验证 profile hash/count、代理最小字段、组名唯一性和全部组引用，无效旧 profile 不能成为 history 基线。
- V2 shadow bundle 的 `clash.yaml`、`status.json`、`history.json`、current diagnostics 和 run index 必须同提交、同 `run_id`、同 source SHA、同 bundle hash。
- 发布顺序固定为：本地构建与 Mihomo 校验 → staging ref → 防缓存远端 smoke → CAS/lease 提升 current → current 再回读。

### Environment

- `GMGN_IDENTITY_HMAC_KEY`：必需 Secret，只注入生成/验证身份的受控 job，禁止日志输出和公开产物。
- identity job 只消费已安全校验的固定 snapshot/fixture，不执行订阅发现脚本、不启动 Mihomo、不访问原始来源；HMAC key 与发布 token 不进入处理不可信网络输入的同一阶段。
- `GMGN_IDENTITY_KEY_VERSION`、`GMGN_IDENTITY_EPOCH`：必需版本字段，可由受控配置提供，必须写入 snapshot/manifest/history/bundle。
- GitHub candidate producer 与 CNB validator 必须配置相同 key 字节、key version 和 epoch；两端在处理真实代理前用不含凭据的固定 test vector 计算四类 public ID，不一致立即失败关闭。
- 未提供 key、版本未知或 epoch 无迁移路径时失败关闭。
- C2 是不可信代理执行网络的实现 owner：域名在启动前解析并固定到已校验的公网地址，Mihomo/探测器运行于带版本化出站拒绝策略的隔离容器或 network namespace，阻断 loopback、link-local、RFC1918、CGNAT、组播、保留地址、Runner/CI 内网和云元数据地址；controller 通道必须留在隔离边界内。
- network guard 输入中的 `candidate_id` 必须唯一；launcher 只有在 backend/version、固定解析、deny self-test、controller isolation、candidate 绑定和启动 evidence 全部完整且一致时才允许启动。重复 ID、未知 backend、缺失 evidence 或 public→private rebinding 一律失败关闭。
- C5 是 CNB 工作流 owner：在任何分片启动前配置并执行 network-guard self-test，记录 guard backend/policy version；Runner 不支持所需隔离原语、固定解析漂移或 self-test 失败时，V2 live 运行失败关闭。探测 job 不得持有发布 token，publisher 不得重新访问不可信代理端点。
- 所有 Mihomo `-v`、`-t` 和 controller runtime 子进程必须通过共享 `minimal_mihomo_env(private_work_dir)` 启动：只保留运行所需的最小 `PATH`，把 `HOME`/临时目录固定到私密工作目录，禁止继承 CNB/GitHub token、HMAC key、askpass 或代理环境。stdout/stderr 只能抑制或写入私密 runtime 日志；公开错误只报告稳定的通用类别，不拼接原始 Mihomo 输出。
- GMGN V2 child image 必须包含其可信离线入口的完整运行时 import closure。`docker build` 成功只证明 COPY 源存在，不证明 Python 入口能导入；当 `scripts.*` 新增对另一顶层包的依赖时，必须同步 Dockerfile、专用 dockerignore 和镜像契约测试。镜像仍按最小文件集复制，并在 `--network none` 容器内实际执行 `python -m scripts.cnb_gmgn_v2 --help` 与 validator `--help`。

## 4. Validation & Error Matrix

| 条件 | 必须行为 |
| --- | --- |
| profile、metadata hash/count/schema 不一致 | 拒绝候选快照，不触发 CNB |
| metadata 无法一一覆盖 profile | 拒绝发布 GitHub candidate snapshot |
| 过滤后 profile 少于 provenance、或 fingerprint 重复 | provenance 决定 source presence；profile 去重合并证据，禁止误报 source missing 或重复 metadata |
| `confirmed_missing` 被计入 quorum、V2 build 失败或跨 job SHA 漂移 | 候选发布失败关闭，保持输出分支 last-good tip |
| 外部来源只开独立 flag、审计与生产裁剪不同、或 last-good 合并后超容量/预算 | 拒绝候选发布；关闭单一来源 flag 可回滚且不影响其他来源 |
| key 缺失、key version/identity epoch 未知 | 失败关闭，不把全部节点当新身份 |
| GitHub/CNB 固定 identity test vector 不一致 | 在候选发布/测速前失败关闭，不接受 metadata 映射 |
| publisher 持有 HMAC key、public ID/计数/时间发生隐式转换 | 拒绝 identity/history 输入，不构建 bundle |
| retry 无 primary tag/failed-or-orphan-running 证据、复用 retry token、processed ref 非单文件或 CAS 冲突 | 拒绝重试，不启动身份/探测，不改变 current/history |
| prepare 缺完整 preflight/trigger、二者 source/attempt/retry 绑定不一致 | 在 identity/Mihomo 前失败关闭，不接受 workflow 裸参数补值 |
| network guard 不可用、固定解析漂移或私网/元数据阻断自检失败 | 不启动 Mihomo 分片，不生成 selection，不改变 history/current bundle |
| Mihomo 子进程继承 CI Secret/代理环境，或失败消息包含原始 stdout/stderr | 拒绝启动/发布；日志只留私密目录，公开输出使用通用错误 |
| child image build 成功但离线入口缺顶层 import 依赖 | CI container smoke 失败；补齐最小 import closure 前不得认为镜像可发布 |
| 同一结果含 403/429/5xx 与 delay、或汇总不等于逐轮记录 | 按错误计数，`valid_run=false`；禁止以 delay 覆盖 HTTP/基础设施错误 |
| controller 证据不是 40 次、canary hash 不绑定实际 ID、四片 runtime 不独立 | `valid_run=false`，不生成 accepted selection 输入 |
| region identity/provider/query plan/TTL 不匹配 | 地区降为 unknown；不得套用亚洲 14/10 宽松线或旧 cache 结果 |
| selection input 缺 C1 metadata、C2 policy/error/no-result 守恒 | 拒绝 selection，不构建 profile/history |
| 轮换时存在快照外 tombstone | 保留 legacy ID/epoch；旧 key 不退役，不要求伪造 new ID |
| identity migration 与 active/legacy ID 或名称占用碰撞 | 迁移失败关闭，保留 previous history，不静默覆盖 |
| 缺片、重复候选、任一候选不是 20 轮、观察窗少于 900 秒 | `valid_run=false`，不选择、不更新历史 |
| controller/control/canary/分片出口不可比 | `valid_run=false`，保留 last-good |
| previous `history.json` 暂时不可读或 hash 不一致 | 失败关闭；只有明确无分支才允许首发 |
| staging smoke 失败 | 不提升 current |
| CAS/lease 冲突 | 旧运行退出，不使用裸 force 覆盖 |
| promotion 后 tip 查询失败/歧义、current 回读不等于已提升 bundle | 标记失败并以 candidate tip 为 lease 恢复 previous；恢复后精确验 tip，不提交 streak |
| rejected run | 只留私有 artifact/失败证据，不覆盖 current diagnostics |
| accepted 新 SHA 但距上次坏计数不足 21600 秒 | 推进 top-level accepted run；零响应不增加 streak，响应节点立即清零/恢复 |

## 5. Good / Base / Bad Cases

- Good：新 source SHA 的四片均完整且可比，900 秒满足，bundle 在 staging 和 current 回读一致；提交 profile/history/diagnostics，history 只计一次。
- Base：节点数量少于 80，但严格门槛、150 总上限和非亚洲 20 上限都满足；允许发布，不降标。
- Bad：某一分片 canary 明显偏离、metadata hash 不匹配、promotion 后 tip 无法确认，或 Mihomo 运行态继承 Secret；整轮拒绝并在需要时受控恢复 previous，V2 shadow last-good、正式 GMGN 和 gstatic 均不变化。

## 6. Tests Required

- identity：改名/重排不改 fingerprint/HMAC ID；配置变化产生新身份；GitHub/CNB 固定向量完全一致；key/epoch 迁移失败关闭；快照外 legacy tombstone 可轮换、重现迁移和 90 天审计 GC；公开字段扫描无裸 fingerprint/IP/凭据。
- snapshot：profile/metadata 一一覆盖、hash/schema/count、来源/五地区掉量、previous 暂时不可读与明确首发；过滤前 provenance 与过滤后 profile 分工、exact duplicate 证据合并、confirmed-missing quorum、V2 off/failed 和跨 job trigger SHA；外部来源双开关、审计/生产裁剪一致、last-good 后最终容量/预算及 timeout→last-good→recovered。
- measurement：N=4/5/2260/5000 稳定分片；fake clock 证明 20 轮顺序和 900 秒；HTTP 错误优先于 delay；节点 summary ↔ round trends/error counts 守恒；每片 40 次 controller 证据、实际 canary ID hash 和独立端口/目录/fragment/secret hash；缺片、control/canary/出口事故均无 selection 输入。
- network guard：恶意 loopback/私网/link-local/CGNAT/metadata/组播/IPv6 本地地址拒绝；重复 candidate ID、未知 backend、不完整 launcher evidence 失败；模拟 public→private DNS rebinding 不会改变固定目标；guard 未安装、规则未生效或 self-test 失败均在 Mihomo 启动前失败关闭，且 probe job 无发布凭据。
- region/selection：identity/provider/query-plan 绑定、7 天 TTL/30 天 grace、unknown 不享亚洲宽松；C1/C2 严格 decoder、14/10/16/18 与前后半程、response>=1 候补、150/20、多样性和地区缺口裁剪；十组引用有效，非空手动优先不含 `DIRECT`，候补不进手动优先/自动，node-status allowlist 含慢响应和半程但无敏感字段。
- history：`core → bad1 → bad2 → bad3/remove → recovered`，并插入重复 SHA、间隔不足但 accepted、快速响应恢复、temporary/last-good carry-forward、无效/拒绝运行；断言 top-level run 与 current bundle 始终一致。另测严格类型/时间、publisher 无 HMAC key、identity/legacy collision 和 bootstrap 悬空组引用。
- publication：staging 旧缓存、push 失败、CAS 冲突、current 回读不一致、Mihomo invalid 均保持 last-good。
- candidate workflow：断言 publish timeout 覆盖两轮 smoke；promotion 后 `ls-remote` 失败/零结果/多结果/tip mismatch/current smoke failure 全部进入 candidate-tip lease 回滚，外部 tip 漂移时 rollback 被拒绝且不会覆盖。
- orchestration：伪造裸 attempt/retry 参数不能替代完整 preflight/trigger；Mihomo version/config/runtime 测试断言环境中不存在 CNB/GitHub/HMAC/askpass Secret，原始输出不进入异常或公开日志。
- container：Dockerfile/dockerignore 契约断言跨顶层包依赖的精确最小 COPY 集；Linux CI 构建真实镜像并在 `--network none` 下执行两个可信离线入口，不能只检查 `docker build` 返回码。
- rollout：三次不同 SHA 且相隔达标，exact bundle 提升正式分支；gstatic URL 保留并标记 frozen。

## 7. Wrong vs Correct

### Wrong

```text
用过滤后 profile 推断来源已经消失
→ publisher 再持 HMAC key 现场重算 ID
→ 公开裸 fingerprint / 原始出口 IP
→ 先覆盖 shadow diagnostics
→ 再尝试生成 profile
→ git push --force 覆盖 current
```

这会泄露可关联身份，并再次造成 profile 与诊断错代、旧运行覆盖新运行。

### Correct

```text
过滤前 provenance 判断 source presence，过滤后 profile 决定发布
→ 独立 identity job：私有 fingerprint → 预计算 HMAC public IDs
→ publisher 只消费已验证 ID map，不持 HMAC key
→ 同 run 构建 profile + status + history + diagnostics
→ staging smoke
→ CAS/lease 提升 V2 shadow current
→ current tip + 防缓存回读
→ 任一 post-promotion 验证失败时仅以 candidate tip 为 lease 恢复 previous 并复验
```

任何一步失败都不改变 last-good，也不增加历史差评。

## Scenario: Candidate V2 provenance、安全清洗与私密 handoff

### 1. Scope / Trigger

- 修改 Candidate identity input schema、provenance/quarantine、DNS 错误分类、collect → identity artifact、或 FC/Mihomo 前处理顺序时，必须遵守本节。
- 目标是保留宽亚洲候选，同时保证任何不可信代理连接前已完成 endpoint 清洗，且跨 job artifact 不公开完整 proxy、凭据或裸 fingerprint。

### 2. Signatures

```python
def prepare_candidate_identity_input(...) -> Mapping[str, Any]: ...

def sanitize_candidate_profile(
    profile: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> SanitizedCandidateProfile: ...

class CandidateDnsResolutionSession:
    def __init__(
        self,
        *,
        expected_domain_hostnames: int,
        resolver: Callable[[str, int], Iterable[str]] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None: ...

    def resolve(self, host: str, port: int) -> list[str]: ...
    def finalize(self) -> None: ...

def build_endpoint_safety_evidence(
    result: SanitizedCandidateProfile,
    *,
    profile_bytes: bytes,
    provenance: Mapping[str, Any],
) -> dict[str, Any]: ...

def validate_endpoint_safety_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]: ...

def enforce_candidate_v2_pre_network_config(groups: dict) -> None: ...
```

```text
python -m scripts.candidate_handoff {encrypt,decrypt} \
  --input <private-or-encrypted-input> --output <encrypted-or-private-output> \
  --repository <owner/repo> --run-id <stable-github-run-id> \
  --trigger-sha <40-hex-trigger-sha>

python -m scripts.candidate_runtime_state {encrypt,decrypt} \
  --input <private-state-or-cache> --output <cache-or-private-state> \
  --repository <owner/repo> --key-epoch <runtime-key-vN>

python -m scripts.sanitize_candidate_endpoints \
  --profile <merged-clash.yaml> --provenance <staging.json> [--provenance ...] \
  --rebuild-from-provenance --safety-evidence <private-evidence.json>

python -m scripts.candidate_snapshot prepare \
  --profile <post-reachability.yaml> --provenance <staging.json> [--provenance ...] \
  --endpoint-safety-evidence <private-evidence.json> \
  --sanitized-profile <immutable-sanitized.yaml> ...
```

### 3. Contracts

- Candidate identity input schema 4 的 `observed_records` 必须精确等于安全 `records` 与 `quarantined_records` 的多重集合并集；合法重复 provenance 观察必须保留，且 `invalid_record_count + len(observed_records) == raw_count`。schema 4 还绑定 metadata schema 2、provenance staging schema 2、`candidate-source-v3` 与 `endpoint-safety-v2`。
- NXDOMAIN、坏 hostname、私网或混合公网/私网解析属于单候选隔离。候选生成阶段的默认 DNS resolver 对单个 hostname 的 `EAI_AGAIN/EAI_FAIL` 采用固定有界重试：总共 4 次解析，退避 `0.25 / 1 / 2` 秒；恢复后继续。耗尽后在同一 resolver 上检查三个公共 canary，至少两个返回非空且全部为公网地址时，等待 5 秒后二次观察目标；目标仍临时失败时只隔离该 hostname。canary 异常、普通 resolver 异常，或异常 hostname 至少 3 个且占预期域名数超过 2% 时，整轮失败关闭。数千 endpoint 的 sanitizer 不并发 DNS，避免 Runner resolver 过载制造假故障。
- `CandidateDnsResolutionSession` 是单次 sanitizer 运行的 DNS owner：成功、确定性失败和候选级临时失败均按小写 hostname 缓存，同 hostname 的不同端口不得重复解析。canary 只决定故障作用域，绝不能替代目标解析或把目标标成安全；出现过候选级隔离时，`finalize()` 必须再次验证 canary，防止运行后半程基础设施退化。
- sanitizer 必须生成私密 `candidate-endpoint-safety-evidence` schema 1，并绑定清洗后 profile SHA、合并 provenance SHA、safe/quarantined fingerprint 精确集合、每条 provenance observation 的完整多重集合分类、`raw_count` 与 `invalid_count`。分类集合不得重叠、缺少 observation 对应项或包含孤儿 fingerprint。
- reachability 之后的 identity prepare 可以只从 sanitizer 的 safe 集合中删除节点；不得新增节点或改变任何连接字段。prepare 必须同时校验不可变 sanitized profile、副本 SHA、provenance SHA 和 observation 多重集合，因此当前候选不重复做 DNS 决策；上一版中本轮未出现的候选仍必须重新解析，以阻止 last-good endpoint 漂移到私网。
- 当前公开 validator 只接受 `endpoint-safety-v2`。只有 `build_candidate_snapshot()` 校验 previous snapshot 的迁移边界允许 previous `endpoint-safety-v1`；status、metadata 与每个 candidate 的版本必须一致，未知/未来版本一律拒绝。新 snapshot 永远写 v2，不能把迁移 allowlist 暴露给普通消费者。
- V2 collect/crawler 必须关闭节点 liveness。合并 profile/provenance 后运行共享 sanitizer，只有其输出可进入 FC 和 Mihomo reachability；`location.regularize` 在 V2 下必须于任何任务/代理执行前拒绝，V1 不变。
- 早期 source-registry DNS 公网检查是无端口连接的纵深防护，不能替代合并后 sanitizer、启动时重解析或网络层 deny。
- collect → identity 只能上传 AES-256-GCM 认证密文。AAD 绑定 repository、稳定 `GITHUB_RUN_ID` 和触发 SHA，不绑定 `GITHUB_RUN_ATTEMPT`，以支持 failed-job rerun。
- 明文/密文输出从创建第一字节起使用 `0600` 临时文件并原子替换。publisher 不持有 handoff key。
- provenance staging 与 identity-input 明文同属该私密契约；不得先用 `Path.write_text/write_bytes` 以默认 umask 创建，再事后 `chmod`。
- `CANDIDATE_HANDOFF_AES_KEY` 是严格标准 Base64，解码后恰好 32 字节；不得复用 `GMGN_IDENTITY_HMAC_KEY`。identity handoff 仍只在 V2 collect/identity 阶段使用；为避免把 crawler/source 跨轮状态继续发布到公开分支，V1/V2 自动运行都必须通过 `scripts.candidate_runtime_state` 保存私密跨轮状态，并以 `CANDIDATE_RUNTIME_KEY_EPOCH` 域隔离派生 runtime cache 子密钥。cache schema、cache key、AAD 与派生子密钥必须同时绑定 epoch；轮换 AES key 时同步提升 epoch。旧 epoch 或认证损坏 cache 必须被拒绝，并从已验证 last-good 分支进行一次性迁移或由新采集重建；不得静默冷启动，也不得永久卡在同一不可解 cache。缺少 `CANDIDATE_HANDOFF_AES_KEY` 时自动发布必须失败关闭，不能在没有持久状态的情况下覆盖 last-good。
- 公开 metadata/alias 不得包含 endpoint、hostname、IP、port、凭据或裸 fingerprint。递归凭据扫描必须覆盖协议特有键（例如 `tlsmirror-opts.primary-key`、XHTTP 的 `x-padding-key` / `session-key` / `seq-key` / `uplink-data-key`）、列表 header 对象（例如 `{name: Authorization, value/values: ...}`）、Basic Authorization 解码后的账号/密码、inline private-key PEM body、Hysteria v1 `obfs`、需要用户密钥的 SSR `protocol-param`，以及 VLESS `mlkem768x25519plus` encryption 中实际可解码的客户端密钥段；同时保持 `public-key`、TLS `fingerprint`、Hysteria2 的普通 `obfs: salamander`、SSR 普通参数与 `encryption: none` 为非秘密连接材料。alias 与凭据比较必须大小写不敏感；长度小于 6 的短凭据仅在整串相等时拒绝，避免 `KR` 等合法地区标签误伤。
- 私有/动态订阅 URL 只允许在 provenance 建立时短暂处于内存中。此时必须提取 userinfo 与 query value，对原始节点 alias 做同样的大小写不敏感凭据复述检查；命中时只清空 alias，后续公开 metadata、profile、错误和日志均不得保存原 URL 或 token。
- `clash-verge-auto` 同一并发组的发布运行必须排队而不是自动取消。CAS/`force-with-lease` 只能阻止陈旧 writer，不能修复 promotion 已完成但 current smoke/rollback 尚未执行时的强制取消窗口。
- 公开输出必须先经过 `scripts.public_bundle` 的 exact allowlist：legacy 只允许 `README.md/clash.yaml/last-run.txt/status.json`，Candidate 再增加 `candidate-metadata.json`。历史 crawler/source health/subscription runtime 不得继续写入公开 artifact 或生成分支；需要跨运行保留时，只能由 `scripts.candidate_runtime_state` 使用 `CANDIDATE_HANDOFF_AES_KEY` 派生的独立 AES-GCM 子密钥写入认证加密 cache。
- Candidate build、remote snapshot validation 与 CNB candidate fetch 必须在全部 gate/schema/hash 校验通过后才创建输出/evidence/staging 目录；拒绝路径不得留下看似成功的空目录。publish-gate CLI stderr 只允许固定 reason code 与非负整数聚合，禁止串入 source ID、URL、alias、hostname、proxy 字段或凭据。
- 来源 URL 凭据扫描必须保留原始 percent-encoded 形式，并执行最多 4 层的有界 `unquote` 比较；所有 URL 检查 userinfo/query key/value，opaque URL 还检查 path/fragment。不得使用会把 `+` 变为空格的 `unquote_plus` 语义。
- `SOURCE_POLICY_VERSION` 是历史 alias 可继承性的隐私证明。previous snapshot 只有在严格通过当前 policy version 校验后，才允许在 `using_last_good` 时继承已验证 alias，保证 Clash 手动选择名称稳定；当前来源成功时只使用本轮 provenance alias，不能把旧 alias 合并回来。policy 升级必须让旧 V2 previous 失败关闭或走显式迁移，不能静默复用旧名称。
- SSR `http_simple/http_post` 的 `obfs-param` 中 `#` 后 header、任意 header value 内的认证 scheme、带引号的 Digest/Cookie 分量和 PEM body 的固定长度片段都属于 alias 隐私扫描输入。PEM 片段应在 PEM 提取阶段生成，不得对所有普通凭据做反向子串匹配，以免误删稳定人类名称。

### 4. Validation & Error Matrix

| 条件 | 必须行为 |
| --- | --- |
| observed 不是 safe + quarantine 的精确多重集合、两类交叉、伪造 fingerprint 或计数不守恒 | 拒绝 identity input，不生成 snapshot |
| evidence 的 profile/provenance SHA、分类集合、observation 多重集合或 invalid/raw count 不一致 | 在 identity 前拒绝；不得重新 DNS 后继续，也不得生成 snapshot |
| NXDOMAIN、私网或混合解析 | 隔离单候选并保留脱敏观察；全部隔离则整轮失败 |
| `EAI_AGAIN/EAI_FAIL` | 单 hostname 最多 4 次解析并按 `0.25 / 1 / 2` 秒退避；耗尽后以 2/3 健康公共 canary 和 5 秒目标二次观察区分候选故障与基础设施故障。孤立候选只隔离，至少 3 个且超过预期域名数 2% 时整轮失败 |
| 其他 DNS 基础设施异常 | 不重试，终止结果聚合并整轮失败关闭；公开异常不得包含 hostname、端口、凭据或 resolver 原始文本 |
| post-sanitizer profile 新增 fingerprint 或修改连接配置 | prepare 拒绝；只允许 reachability 删除 sanitizer 已证明安全的候选 |
| previous 是一致的 `endpoint-safety-v1` | 仅 snapshot build 的 previous 校验可接受并产出 v2；普通 validator 仍拒绝 v1 |
| previous policy 是未知/未来版本，或 status/metadata/candidate 版本不一致 | 迁移失败关闭，保留 last-good |
| V2 在 sanitizer 前启用 liveness/`regularize` | 在任何 FC/Mihomo 节点连接前拒绝本轮 |
| profile 节点无 provenance 覆盖 | sanitizer 失败关闭，拒绝注入节点 |
| handoff key 缺失、非严格 Base64、非 32 字节，或密文/AAD 被篡改 | identity job 失败，不创建明文输出，不进入 publisher |
| runtime cache 缺 key、epoch 不匹配、schema 过旧或认证失败 | 拒绝该 cache；仅允许从已验证 last-good 状态迁移或重新采集，恢复成功前不得发布；错误不得回显私密状态 |
| V1 默认路径未恢复 crawler/source runtime state | 视为发布前置条件不满足，禁止把冷启动结果覆盖 last-good |
| 同一 GitHub run 只重跑失败 job | 使用稳定 run ID 认证原 artifact，允许正常解密 |
| public bundle 出现额外 runtime 文件，或 encrypted cache 缺 key/认证失败 | 拒绝复制/恢复；公开分支不写额外文件，认证失败不创建明文输出 |
| Candidate gate/schema/hash 在 build、remote validator 或 CNB fetch 阶段失败 | 不创建目标目录；stderr/公开诊断只保留固定聚合错误 |
| V1/legacy profile 含 V2 allowlist 外但 Mihomo 可接受的旧字段 | 仅旧 baseline/bootstrap/shadow/publish 使用 legacy fingerprint；V2 current producer 仍拒绝 |
| alias 以任意大小写重复 proxy 凭据、XHTTP key、VLESS encryption 客户端密钥、Basic 解码值、private-key PEM body、Hysteria v1 obfs、认证型 SSR user key、订阅 userinfo/query token、`primary-key` 或列表 Authorization/X-Api-Key 值 | 丢弃该公开 alias；短凭据只做整串匹配，普通 User-Agent `{name,value}`、`public-key`、TLS `fingerprint`、Hysteria2 普通 obfs、SSR 普通参数和 `encryption: none` 不得被误判为凭据 |
| 新运行在 output promotion 后自动取消 | 禁止该并发策略；发布运行排队完成 current smoke 或 lease rollback |

### 5. Good / Base / Bad Cases

- Good：同一安全配置被多个来源重复观察，schema 4 保留全部观察并合并为一个公开候选；同一 run 的 failed-job rerun 能认证原密文。
- Base：个别 hostname NXDOMAIN 或解析到私网，只隔离这些候选；其余宽池继续，亚洲不会因一次 liveness timeout 被删除。
- Bad：解析器暂时异常、`regularize` 被误开、handoff 被跨 run/commit 替换，或 sanitizer 发现无 provenance 节点；整次 Candidate V2 拒绝且 last-good 不变。

### 6. Tests Required

- schema 4/evidence：safe/quarantine/observed 多重集合守恒、合法重复观察、invalid count、交叉类/伪造/orphan fingerprint、profile/provenance SHA 篡改、evidence subset/addition/config change、previous quarantine 必须属于 previous profile。
- DNS：NXDOMAIN/私网隔离且不重试；`EAI_AGAIN/EAI_FAIL` 两次后恢复、四次耗尽、退避序列固定；2/3 canary、5 秒二次观察、hostname 缓存和 2% 批量异常边界；普通异常不重试；基础设施失败穿过线程池，普通 worker 错误保持 V1 兼容，异常链和日志不泄露 hostname、凭据或底层 resolver 错误。
- 迁移：普通 validator 拒绝 v1；previous snapshot 的 v1→v2 单次受限迁移成功；status/metadata/candidate 混版和未来版本失败关闭。
- 网络顺序：workflow 断言 collect/crawler liveness 关闭，sanitizer 位于 FC/Mihomo 前；V2 regularize 在 push/task execution 前失败，V1 相同配置仍可用。
- handoff：AES-GCM round-trip、密文/nonce/AAD/错误 key 篡改、严格 32-byte Base64、跨 run/commit 拒绝、同 run attempt 重跑兼容、artifact 无明文、publisher 无 key、POSIX 首字节 `0600`。
- public/runtime boundary：legacy/Candidate exact file allowlist、额外 runtime 文件拒绝且错误不回显文件内容、V1/V2 都恢复跨轮状态、cache schema/key/AAD/子密钥全部绑定 epoch、错误 epoch/篡改 cache 不创建明文、last-good 一次性迁移与无 key 失败关闭；Candidate CLI gate 拒绝、remote validator 与 CNB fetch 的 hash/schema 拒绝均不创建输出目录且不泄露输入哨兵。
- V1/V2 identity：真实 legacy HTTP `udp`、gRPC `grpc-mode` 可完成分片、baseline 和 history bootstrap；同一字段作为 current V2 输入仍被严格拒绝。
- 隐私：公开 sidecar/alias 扫描无 hostname/IP/port/凭据/裸 fingerprint；覆盖大小写变化 UUID/password、四个 XHTTP key、VLESS encryption 密钥、Basic 解码值、private-key PEM body、Hysteria v1 obfs、认证型 SSR user key、订阅 URL userinfo/query token、`primary-key`、mapping/list header secret，以及短 `KR`、普通 header、`public-key`、TLS `fingerprint`、Hysteria2 普通 obfs、SSR 普通参数、`encryption: none` 反误判。
- workflow：断言 `clash-verge-auto` 的 concurrency 不自动取消，并继续保留 staging/output promotion/rollback 的精确 `force-with-lease`。

### 7. Wrong vs Correct

#### Wrong

```text
先对原始候选启动 Mihomo/regularize
→ 把 DNS 基础设施抖动吞成单节点失败
→ reachability 后重新解析当前候选并产生第二套安全决定
→ 允许普通 validator 接受旧 policy
→ 上传明文 identity-input artifact
→ 用 GITHUB_RUN_ATTEMPT 绑定密文
→ 让 V1 默认链路复用 V2 strict fingerprint
```

这会制造假 Timeout、误删亚洲候选、泄露完整配置，并让失败 Job 重跑无法读取上一阶段 artifact。

#### Correct

```text
宽收集（节点 liveness off）
→ 合并 profile + provenance
→ endpoint sanitizer（run-scoped DNS session、NXDOMAIN/私网隔离、DNS infra fail-closed）
→ 私密 evidence 绑定 sanitized profile + provenance + observation 分类
→ FC/Mihomo 严格网络步骤
→ prepare 只允许安全集合的子集，并复用 evidence 而不重复当前 DNS 决策
→ schema 4 provenance 守恒
→ previous v1 只在 snapshot build 边界受限迁移为 v2
→ AES-256-GCM 私密 handoff（stable run ID）
→ V1/V2 crawler/source 状态只进入 epoch-bound 加密 cache，绝不进入公开分支
→ 独立 identity build
→ V1 legacy fingerprint 与 V2 strict fingerprint 显式隔离
→ staging smoke + lease publish
```
