# GMGN 测量有效性与并发标定

## Goal

把现有 CNB GMGN 四分片 20 轮探测升级为“可证明有效的测量”：固定同一 GitHub 候选快照，保证每个候选恰好 20 次、同一候选轮次按时间顺序且首末采样跨度至少 900 秒；每片独立记录 Runner 出口、Mihomo/controller 健康、直连 GMGN control 和共享 canary；只有来源、分片、观察窗、控制面和跨片可比性全部通过的运行才产生可供历史/选择器消费的输入。

性能目标是在不制造假 Timeout 或 controller 错误的前提下尽快完成。生产默认保持每片 16 workers，先以受控基准比较 8/16/24/32；本任务不引入运行时动态自调并发。

## Dependencies and Ownership

- 前置契约：父任务设计、`aggregator` specs 和 V2 schema/policy 已冻结。
- C1 提供 `clash.yaml + status.json + candidate-metadata.json` 固定快照；C3 提供稳定 HMAC `candidate_id`。本任务可用 fixtures 并行开发，但最终组件验收必须校验 C1 双 hash 并使用 C3 identity，不得重新发明 fingerprint。
- C4 只能消费本任务标记为 `valid_run=true` 的测量；C3/C5 不得把无效运行计入 history 或发布。
- `.cnb.yml` 由 C5 最终独占集成。本任务只修改测量 Python 模块、测试和 benchmark 支持，不直接改变线上 trigger、分支或工作流。
- DNS/私网防护所有权：C1 做候选快照生成时校验；C2 拥有 probe-time resolver、固定映射、network-guard policy/launcher/self-test，在每个 shard 启动 Mihomo 前拒绝 non-global/private/link-local/metadata 等安全漂移；C5 在 `.cnb.yml` 提供所需网络隔离原语、调用 C2 guard 并保证 probe job 无发布凭据。解析重查与网络隔离必须同时存在。
- CNB 在启动任何 Mihomo 前运行独立受控 identity validator：只消费固定 snapshot 与 C3 非秘密 fixture，使用与 GitHub 完全相同的 HMAC key bytes/`identity_key_version`/`identity_epoch` 重算 metadata `identity_preflight` 和 profile candidate IDs。validator 不访问原始来源、不启动 Mihomo、不持发布 token；四个 probe jobs 不持 HMAC key。

## Requirements

### R1. 固定来源与 manifest v3

- coordinator 必须防缓存下载同一 GitHub snapshot 的 status、profile 和 metadata，验证 schema、新鲜度、`profile_sha256`、`candidate_metadata_sha256`、数量及一对一 candidate 映射后再写运行目录。
- manifest 固定为 `kind=cnb-gmgn-shadow-manifest`、`schema_version=3`、4 shards、20 rounds、目标 `https://gmgn.ai/`、期望 HTTP 200、请求上限 3000 ms、达标线 1000 ms、最短观察窗 900 秒。
- manifest 还必须记录 `run_id`、snapshot/source/main SHA、profile/metadata SHA、metadata schema/count、`identity_key_version`、`identity_epoch`、其余 schema/policy version、workers、分片错峰、canary set hash、Python/PyYAML/Mihomo 版本和 Mihomo 二进制 SHA-256。
- 未知 schema/policy、hash 不一致、snapshot 过旧/未来时间、candidate 重复/缺失均失败关闭，不产生 probe manifest。
- 固定 fixture 的 candidate/server/endpoint/exit public IDs 任一与 GitHub metadata preflight 不同，说明 key bytes/version/epoch 或实现漂移；必须在分片/Mihomo 启动前失败关闭。

### R2. 每候选恰好 20 次且覆盖 900 秒

- 固定快照内每个 candidate 必须恰好产生 20 个终态样本；Timeout、慢响应、HTTP 错误和 controller 请求失败都各占一轮。
- 不允许单轮预筛、数学提前淘汰或候选在失败后跳过后续轮次。
- 同一 candidate 的第 N+1 次请求只能在第 N 次结束后开始；不同 candidate 可以在同一轮并发。
- 每个样本记录 `round`、`started_at`、`finished_at`、delay 或规范化 error category。
- 第一轮全部候选开始后，以“第一轮最后一个样本的开始时间”为 pacing anchor；第 1–19 轮不得早于 `anchor + round_index × 900/19` 启动。最终逐 candidate 校验第 20 次开始时间与第 1 次开始时间之差至少 900 秒。
- 四片允许固定错峰 0/15/30/45 秒，但每片都必须独立满足 900 秒，而不是只看全局作业耗时。

### R3. 确定性四分片与独立运行时

- 候选按 C3 `candidate_id` 排序后 round-robin 到 4 片；N=4、5、2260、5000 与输入重排时必须无遗漏、无重复、片差不超过 1 且归属稳定。
- 每片使用独立 Mihomo 进程、controller/mixed port、secret、工作目录、私密日志和 fragment 输出。
- 每片启动 Mihomo 前重新解析其全部域名 server；任一 A/AAAA 变为不可接受地址即判 source safety mismatch、`valid_run=false`，且不启动任何 shard Mihomo。该检查使用版本化 resolver policy，并由 C5 网络层 deny 处理解析后的 TOCTOU/DNS rebinding。
- C2 guard 必须输出版本化 backend/policy/self-test 结果，并固定 Mihomo 使用的安全解析；隔离需阻断 loopback、link-local、RFC1918、CGNAT、组播、保留地址、Runner/CI 内网和云元数据。backend 不可用、deny 自检失败或固定解析漂移时不启动任何 Mihomo。
- 每轮前后验证 Mihomo `/version` 与进程健康；controller 中途死亡、版本/hash 与 manifest 不一致或轮次记录不完整使整轮无效。
- private fragment、redacted fragment 和 manifest 的 source/profile/metadata hash、run/policy/schema、identity key version、identity epoch、runtime/shard 参数必须严格一致。

### R4. 完整统计与错误分类

每节点汇总至少包含：

- `attempt_count=20`；
- `within_1000_count`、`slow_response_count`、`no_result_count`；
- min/max/median/P90、jitter；
- 前后 10 轮与四个 5 轮窗口的达标数；
- 下列 error category 计数：`target_403`、`target_429`、`target_5xx`、`dns`、`tls`、`connect`、`proxy_auth`、`client_timeout`、`controller_request`、`controller_unhealthy`、`other`。

守恒关系必须可回算：response + no_result = 20，within + slow = response，窗口和 round trends 与节点总数一致。Timeout 不进入延迟分位数，但必须进入 `no_result_count`、error counts 和排名所需的成功次数，不能从评分中消失。

### R5. 每片 control、canary 与出口证据

- 每片在探测前后独立记录实际 Runner 出口；原始 IP 仅留私密目录，公开数据只包含 country/region/org 和由 C3 `exit_id(public_ip)` 生成的 HMAC opaque egress ID，C2 不自行散列出口。
- valid-run v1 初始要求 Runner country 为 `CN`，四片 region 一致，同一片前后 egress ID 不变；具体省份只做遥测，不硬编码广东。
- 每轮执行不经过 candidate proxy 的 GMGN 直连 control；每片 20 轮至少 18 次成功，且不得连续失败 3 轮。
- 每片测试同一 canary set；每个 canary 每片至少 16/20 响应，四片成功次数差不超过 4，median 差不超过 `max(300 ms, 较快片 median 的 50%)`。
- canary 集、目标和判断门槛必须有版本/hash；更新 canary 或门槛需要提升 policy version。

### R6. `valid_run` 系统事故门禁

以下任一情况令 `valid_run=false`，不得输出“accepted selection input”，不得推进 history：

- 来源/schema/hash/identity/policy 不一致；缺片、重复片、候选少于/多于 20 次；
- 任一片 Mihomo/controller unhealthy 或 900 秒观察窗不满足；
- Runner 非 CN、四片 region 不一致或同片前后出口变化；
- control/canary 未达到 R5 门槛；
- 全局 candidate 请求中 403+429 比例超过 2%，或任一轮 403+429 达到/超过 10%；
- shard error/control/canary 差异触发版本化可比性门槛。

免费代理总体 Timeout 比例很高本身不直接判无效；只有 control/canary/controller/跨片证据表明基础设施或目标异常时才拒绝，避免把真实候选质量差误判为系统事故。

### R7. 公开/私密数据边界

- private sample/selection fragment 可包含完整 proxy、逐轮时间和原始安全分类上下文，只能位于 `.cnb-runtime` 私密根、模式 `0600`，不得进入 `.git` 或 `public-cn*`。
- public redacted fragment 只允许 HMAC `candidate_id`、亚洲提示、计数、延迟汇总、错误计数、control/canary/出口聚合；禁止 name、server、port、UUID/password、裸 fingerprint、原始错误、逐轮私密样本和 Runner IP。
- Mihomo 启动失败或 controller 异常不得把日志尾部/配置回显到公开异常。
- Runner 出口原始 IP 由 probe 写入最小私密 handoff；独立 identity/redaction stage 使用 HMAC key 生成 `exit_id`，该 stage 不运行代理、不持发布 token。probe 和 publisher 均不持 HMAC key。

### R8. 并发基准与固定默认值

- 使用同一受控候选子集、同一 runtime/policy/canary，比较 8/16/24/32 workers，每档至少 2 次非发布影子基准；20 轮与 900 秒观察窗不缩短。
- 基准记录每片 wall time、吞吐、shard skew、candidate no-result、403/429、controller 分类、control/canary 成功和 CPU/内存可用遥测。
- 16 workers 是初始生产默认。只有替代档位相对 16 workers 的重复基准 p50 wall time 至少改善 10%，且 candidate no-result 增幅不超过 2 个百分点、controller request 增幅不超过 0.5 个百分点、无 controller-unhealthy、control/canary 全部通过、shard duration skew 不超过 10%，才可通过 policy version 修改默认值。
- 不在单次生产运行中动态升降 workers；未来自调属于独立任务。

### R9. 兼容与上线边界

- schema v3 与 valid-run gate 先作为默认关闭的 V2 能力；本任务完成不修改 `.cnb.yml`、不触发真实 CNB、不写 shadow/正式分支。
- 当前 schema v2/正式 GMGN 路径保持可运行，直到 C5 用独立 `clash-cn-gmgn-v2-shadow` 接入并完成 rollout 门禁。

## In Scope

- GMGN manifest/private/redacted fragment 的测量字段和严格 validator。
- 20 轮 scheduler、900 秒 fake-clock 可测观察窗、四分片完整性。
- per-shard egress/control/canary/controller 证据、错误分类和 `valid_run` 纯校验。
- workers 8/16/24/32 基准工具、证据格式和固定默认政策。
- 隐私路径、文件权限、公开 allowlist 和失败关闭测试。

## Out of Scope

- 来源采集/provenance/发布掉量保护（C1）。
- identity/HMAC/history/stable name（C3）。
- 出口地区作为节点地区、质量层级、多样性和 Clash 分组（C4）。
- `.cnb.yml`、trigger、CAS/lease、远端发布和 history commit（C5）。
- 真实入口迁移和 gstatic 冻结（C7）。

## Acceptance Criteria

- [ ] 1–3 个 fake candidate 的完整运行证明每个 API 调用恰好 20 次，Timeout/慢响应/HTTP/controller 错误各占一轮，无早退或重复。
- [ ] manifest 与 private/redacted fragments 对 source/profile/metadata SHA、metadata schema/count、`identity_key_version`、`identity_epoch`、runtime/policy 使用严格一致校验，任一漂移均在 probe/merge 前失败关闭。
- [ ] GitHub/CNB identity preflight 固定向量逐项一致；HMAC key bytes、identity key version 或 epoch 任一改变都会在 Mihomo 启动前拒绝，workflow 测试证明 probe/publisher 无 HMAC key、identity stage 无原始来源/Mihomo/发布 token。
- [ ] fake clock 证明每个 candidate 的第 20 次与第 1 次开始时间跨度至少 900 秒，同一 candidate 无重叠；不同 candidate 仍可并发。
- [ ] N=4、5、2260、5000 和输入重排证明四片稳定、完整、平衡；四片各使用独立端口、目录、secret 和 fragment。
- [ ] 1000 ms 算达标、1001 ms 算慢；统计、前后半程、5 轮块、round trends 和 error counts 的全部守恒关系有精确边界测试。
- [ ] 每片独立记录前后出口、20 个 control 和同一 canary set；公开 egress ID 由 C3 `exit_id` 生成，country/region/egress、18/20、连续 3 次、16/20、差 4 次和 median 容差边界均被测试。
- [ ] 缺片、重复片、19/21 轮、900 秒不足、controller 死亡、403/429 系统事故、出口变化或 canary 偏离均产生 `valid_run=false`，且不生成 accepted selection input。
- [ ] 单纯 candidate no-result 很高但 control/canary/各片正常时仍可判为有效运行。
- [ ] private fragment 路径/0600 和 public allowlist 测试通过；假 secret、proxy name/server、原始错误和 Runner IP 不出现在公开输出/异常。
- [ ] public→private DNS rebinding、恶意 IPv4/IPv6 私网/metadata 地址、guard backend 缺失和 deny self-test 失败均在 Mihomo 启动前失败关闭；probe job 无发布 token，accepted/history 输入不产生。
- [ ] 8/16/24/32 每档至少 2 次基准证据可由工具解析；默认仍为 16，只有达到 R8 的量化条件才允许版本化变更。
- [ ] 当前线上 schema v2 和分支未被本任务修改；C5 接入前没有真实 CNB 写操作。
- [ ] 目标测试、完整 `unittest` 和 `git diff --check` 通过。

## Rollback Point

本任务不接管 `.cnb.yml` 或远端分支。回滚点是保持 V2/schema v3 开关关闭并继续使用当前 schema v2 测量；所有 benchmark/组件证据只写入 `D:\xiangmu\linshi\gmgn-measurement-validity`。无效运行只生成脱敏失败摘要，不得替换任何 last-good。
