# GMGN 亚洲节点选拔与订阅发布技术设计

## 1. 设计目标

将现有“GitHub 候选池 + CNB 单次选拔”升级为可解释、可恢复、面向 Clash Verge 手动选择的完整供应链：

```text
GitHub 来源发现与健康管理
  → 安全清洗、精确去重、provenance 合并
  → 固定候选快照（profile SHA）
  → CNB 协调器准备统一 manifest
  → 4 个独立 Mihomo 分片按时间顺序完成 GMGN × 20
  → 完整性、出口与 canary 可比性门禁
  → 真实出口、历史保护和多样性选拔
  → 原子生成 profile / status / history / diagnostics
  → Mihomo 校验、远端 smoke、发布或保留 last-good
```

核心原则：

- GitHub 负责宽候选与来源健康，不用单轮网络结果删除亚洲候选。
- CNB 对每个固定快照候选留下完整 20 轮观测。
- `<=1000 ms` 决定主力等级；至少一次 GMGN 响应即可进入亚洲手动候补。
- 亚洲候补宽松、非亚洲严格；80 是期望容量，150 是硬上限。
- 只有有效运行才能改变历史；失败运行不得覆盖 last-good。
- 用户最终仍在 Clash Verge 本机测速并手动选择。

## 2. 组件与责任边界

| 组件 | 主要责任 | 主要文件 |
|---|---|---|
| 来源与采集 | 固定/动态源、机场轮转、来源健康、last-good | `scripts/build_crawler_config.py`, `subscribe/crawl.py`, `subscribe/collect.py`, `subscribe/process.py` |
| 候选规范化 | 配置 allowlist、指纹、provenance 合并、精确去重、地区提示 | `subscribe/clash.py`, `subscribe/asia.py`, `scripts/merge_clash_profiles.py` |
| GitHub 发布 | 候选状态、区域/来源掉量门禁、远端 smoke、CNB 触发 | `scripts/prepare_github_publish.py`, `scripts/filter_reachability.py`, `.github/workflows/clash-verge-auto.yml`, `.github/workflows/sync-cnb.yml` |
| CNB 测量 | 新鲜快照固定、manifest、分片、20轮、canary、错误分类 | `scripts/cnb_gmgn_shadow.py`, `.cnb.yml` |
| CNB 选拔 | 有效运行门禁、历史、出口、多样性、稳定名称与分组 | `scripts/cnb_gmgn_publish.py`, `subscribe/location.py`, `scripts/pipeline_utils.py` |
| 诊断与回滚 | content-addressed run 摘要、last-good、远端 smoke、gstatic 冻结 | `.cnb.yml`, `CNB_SETUP.md`, `CLASH_VERGE_AUTO.md` |

不新增第二个仓库。只有候选长期超过约 8000、完整运行稳定超过 60 分钟或确认触及 CNB 单仓库硬限制时，才设计 Worker 仓库。

## 3. GitHub 候选快照契约

### 3.1 稳定候选身份

以规范化代理配置计算私有稳定 `fingerprint`：排除易变 `name` 和内部辅助字段，保留会改变实际连接身份的协议、服务器、端口、凭据、传输和 TLS/REALITY 参数。所有阶段共享同一实现，禁止各脚本自行计算不同指纹。

裸 `fingerprint` 只用于受控的内部状态关联，不进入公开 status、provenance 或 diagnostics。公开 `candidate_id`、`endpoint_id`、`server_id` 和 `exit_id` 使用带域前缀、`identity_key_version` 与 `identity_epoch` 的 HMAC 派生；密钥缺失、未知 epoch 或无法完成显式迁移时失败关闭，不能把全部历史节点静默当成新节点。

身份轮换采用 legacy tombstone 分阶段迁移：当前快照内可重算节点迁移到新 ID；快照外 removed tombstone 保留旧 `candidate_id`/epoch 和名称占用。旧 key 在 legacy tombstone 存在时不得退役，节点重现时用旧 key 匹配后迁移；初始 tombstone retention 为 90 天，只有产生可审计 GC 证据后才允许删除剩余 legacy tombstone 或退役旧 key。公开分支不为迁移持久化裸 fingerprint。

GitHub producer 与 CNB validator 必须配置同一 HMAC key、`identity_key_version` 和 `identity_epoch`。两端在解析真实候选前使用无凭据固定 test vector 计算 candidate/server/endpoint/exit ID；结果不一致时分别在候选发布或 probe prepare 前失败关闭。

精确重复配置合并而不是覆盖：

- `source_ids` 取并集；
- `protected_asia` 只要任一来源有可靠地区证据即保留；
- `first_seen_at` 取最早，`last_seen_at` 取最新；
- GitHub 测试状态、地区提示和来源健康按字段合并；
- 输出展示名不参与身份判断。

### 3.2 `status.json` v2

GitHub 候选状态升级为版本化契约，至少包含：

- `kind`, `schema_version`, `run_id`, `run_at`, `main_sha`；
- `profile_sha256`, `profile_url`；
- `candidate_metadata_url`, `candidate_metadata_sha256`, metadata schema/count；
- 原始、配置有效、精确唯一、唯一 `server:port` 和最终候选数量；
- HK/JP/KR/SG/TW 名称提示数量及非亚洲/未知数量；
- 来源总数、成功/last-good/失败/确认消失数量；
- GitHub-tested 与亚洲 bypass 数量；
- 与上一版的总量、亚洲、单地区和来源差异；
- 配置/来源策略版本、`identity_key_version` 与 `identity_epoch`。

GitHub 发布门禁同时检查总量、亚洲总量、五地区、来源 quorum 和上一版比例。上一版读取暂时失败时 fail-closed；只有明确确认输出分支不存在才允许首发。

### 3.3 `candidate-metadata.json`

新增可供 CNB 消费的脱敏 sidecar，以公开 opaque `candidate_id` 为 key，并由受控生产端保留其与私有 `fingerprint` 的关联。sidecar 中每条记录必须与 `clash.yaml` 的一个规范化代理一一对应；orphan、重复映射、数量或 hash 不一致都在触发 CNB 前失败关闭：

- 安全 `source_ids`，不得包含私有订阅 URL/token；
- `first_seen_at`, `last_seen_at`, `source_last_success_at`；
- `region_hints`, `protected_asia`, `region_evidence`；
- `github_tested`, `github_test_result`；
- 协议、HMAC 端点/服务器 ID 和可用于多样性的非敏感字段。

公开来源可使用稳定别名；私有/动态来源使用持久化不透明 ID。是否将私有订阅派生节点公开必须由显式配置开启。

### 3.4 来源健康与消失

固定 raw 源也维护 last-good，而不是本轮失败即清空。初始 tombstone 规则在影子数据校准前采用：

- HTTP/限流/解析失败：来源进入观察状态并沿用未过期 last-good；
- 至少连续 3 次健康采集均确认缺失，且距最后成功至少达到配置化 TTL，才标记 confirmed missing；
- confirmed missing 的代理可移除；观察状态不触发节点删除或地区掉量发布。

机场轮转对 known-good、untried 和 due-retry 分别保留配额，避免新来源饥饿。

## 4. CNB manifest、分片与样本契约

### 4.1 统一 manifest

协调器防缓存下载 `status.json`、`clash.yaml` 和 metadata，验证 schema、时间、SHA 和计数后生成不可变 manifest：

- `run_id`, `source_sha256`, `main_sha`, `policy_version`, `identity_key_version`, `identity_epoch`；
- GMGN URL、HTTP 200、1000 ms 合格线、3000 ms 请求上限、20轮；
- shard 数量、workers、最短观察窗口、canary 版本；
- Python/PyYAML/Mihomo 版本和二进制 hash；
- 候选总数、分片 hash、触发来源。

同一 `profile_sha256` 只允许一个正常正式运行；基础设施失败重试沿用同一逻辑运行身份，但不得重复增加历史差评。

### 4.2 分片执行

候选按稳定 HMAC `candidate_id` 排序后轮询分为 4 片，保证无遗漏、无重复、数量均衡且输入重排不改变归属。每片使用独立 Mihomo、控制端口、工作目录和日志。

- 不同候选在同一轮内并发；
- 同一候选的第 N+1 次请求只能在第 N 次结束后发生；
- 每轮记录实际开始/结束时间；
- 每个候选必须有恰好 20 条结果；
- 首末采样初始至少覆盖 900 秒，作为版本化策略字段；实际全量运行更长时自然满足，影子数据证明不合适时只能通过策略版本显式调整；
- 分片可错峰启动，避免瞬时连接峰值。

生产默认并发不动态变化。先用受控候选集比较 8/16/24/32 workers，依据吞吐、Timeout、controller 错误和 canary 结果选择版本化固定值；当前 16 workers 是基线。

### 4.3 样本和错误分类

私有节点记录至少包含：

- 20 次尝试的时间戳、延迟/无结果和规范化错误类别；
- `within_1000_count`, `slow_response_count`, `no_result_count`；
- Timeout、HTTP 403/429、DNS、TLS、connect、proxy-auth、target-status、controller-unhealthy、other；
- min/max/median/P90、抖动、前后半程、四个五轮块。

Timeout 不写入延迟分位数，但始终进入 `no_result_count` 和排名第一关键字之前的成功计数，不能从评分中消失。原始错误文本和代理配置只留在私有运行目录。

### 4.4 分片可比性与有效运行

四个 probe job 分别记录实际 Runner 出口，并测试同一组版本化 canary：

- 直接访问 GMGN 的目标健康检查；
- Mihomo/controller 健康；
- 若已有上一版稳定节点，复制少量锚点到每片，仅用于比较、不参与候选计分。

以下任一条件使运行无效并拒绝发布：

- 来源/manifest/hash/schema 不一致；
- 缺片、重复片、候选不是恰好 20 次；
- Mihomo/controller 中途异常；
- 目标对照出现系统性 403/429/Timeout；
- 分片出口或 canary 差异超过版本化容差；
- 最短观察窗口未达到；
- 运行预计或实际超过平台安全预算。

候选总体无结果率很高本身不等于基础设施失败；有效性主要由目标对照、controller 和跨片 canary 判断。

初始 `valid-run-v1` 数值冻结为：每片 direct control 至少 `18/20` 且最大连续失败小于 3；每个 canary 每片至少 `16/20` 响应，四片成功次数差不超过 4，median 差不超过 `max(300 ms, 较快片 median × 50%)`；全局 403+429 不超过全部候选尝试的 2%，任一轮必须低于 10%；Runner country 为 CN、四片 region 一致且同片前后 opaque egress ID 不变。所有数值都进入 policy version，后续只能通过影子证据和版本升级调整。

## 5. 历史、出口与选拔

### 5.1 `history.json`

当前 V2 权威 bundle 分支保存可跨运行读取的版本化历史：影子阶段是 `clash-cn-gmgn-v2-shadow`，迁移后是 `clash-cn-gmgn-output`。`history.json` 以 HMAC `candidate_id` 为公开关联键；publisher 可在私密运行时用 canonical fingerprint 重算/校验身份，但不得把裸 fingerprint 或原始出口 IP 序列化到生成分支：

- 稳定 `output_name`；
- 当前/上一层级与迁移原因；
- `bad_streak`, `last_counted_bad_at`, `last_good_run_id`；
- 最近至少 3 次有效运行的计数摘要；
- 来源 last-seen/confirmed-missing 状态；
- HMAC `exit_id`、国家/地区、ASN/opaque ASN ID、查询时间、TTL 与 stale 标记；
- 首次/最后选中时间。

history 只有在本轮有效、选择完成、配置通过 Mihomo 校验且 bundle 发布被接受时才更新。每个新 source SHA 的 accepted run 都推进顶层 last-accepted run/source 并与 current profile 同步；失败、拒绝发布和同 SHA retry 保持权威 history 不变。

history reducer 的完整输入固定为：previous validated history、C1 的 source-health/confirmed-missing events、C2 的 `ValidRun` 与节点测量、candidate snapshot，以及 C4 staged selection/region decisions。C3 是状态迁移唯一 owner；C4 不自行更新 streak，C5 只决定 staged reduction 是否随 accepted bundle 原子提交。

### 5.2 真实出口验证

复用 `subscribe/location.py` 的 per-proxy listener 思路，只查询：

- 本轮至少得到一次 GMGN 响应的候选；
- 全部严格入选候选；
- 仍在历史保护窗口内的亚洲候补。

结果按 HMAC `candidate_id` 缓存并设置 TTL，出口本身只持久化 HMAC `exit_id` 与非敏感地区/ASN 摘要。查询服务失败不使整轮失败。未验证出口的模糊名称标签不能进入亚洲核心/弹性，只能进入明确标记的未知地区手动候补。

### 5.3 分层规则

初始版本：

- 亚洲核心：真实出口为 HK/JP/KR/SG/TW，`>=14/20`，前后十轮各 `>=5`；
- 亚洲弹性：真实出口为目标亚洲，`10–13/20`；
- 亚洲手动候补：目标亚洲或可靠亚洲提示，本轮 `response_count >=1` 但未达到弹性；
- 历史保护候补：上一版亚洲入选/候补，本轮零响应，且连续有效坏运行少于 3 次；
- 非亚洲稳定：基础最多 10 个且 `>=16/20`，扩展总数最多 20 个且 `>=18/20`。

亚洲候补的“坏运行”定义为：在有效运行中来源仍存在、配置有效，但本轮 20 次均无 GMGN 响应。`accepted` 与 `bad_countable` 分离：不同 source SHA 但距上次坏计数少于 21600 秒的 accepted run 仍随 bundle 写入 history，只是不增加 streak；只有不同 SHA 且达到间隔的零响应运行才执行 `bad_streak += 1`。任一新 accepted valid run 只要重新有一次响应，即使未满 21600 秒也立即清零并恢复；达到核心/弹性时立即晋级。三个 bad 计数必须来自不同有效来源 SHA。

新出现且 20 次均无响应的亚洲节点只留在 GitHub 全候选池，不进入 CNB 正式订阅。非亚洲不享受候补历史保护。

### 5.4 排名、容量与多样性

主排序：

1. 层级；
2. `within_1000_count`；
3. `response_count`；
4. P90；
5. median；
6. jitter；
7. 稳定 `candidate_id`。

总数上限 150。80 只作为状态中的期望容量，不触发降标。

严格主力、手动优先和自动组对同故障域使用初始硬上限：同一 `exit_id` 最多 3、同一 server 最多 3、同一 ASN 最多 `max(3, ceil(strict_target × 0.30))`、同一来源最多 `max(2, ceil(strict_target × 0.25))`。亚洲候补在总数未满 150 时只降权和标记，不因重复直接删除。超过 150 时按以下顺序保留：核心/非亚洲严格、弹性、历史保护候补、当前手动候补，再结合地区覆盖和故障域多样性裁剪。

## 6. 名称与 Clash 分组

首次选中时生成不含延迟、成功率和排名的输出名，并在 `history.json` 持久化 `candidate_id → output_name`。以后源名称变化、输入重排或层级变化不改名；只有 canonical identity 变化并产生新 `candidate_id` 才生成新名。

最终配置至少包含：

- `👆手动优先测速`：经多样性硬限制的亚洲核心、亚洲弹性和非亚洲稳定；
- `🇭🇰香港`, `🇯🇵日本`, `🇰🇷韩国`, `🇸🇬新加坡`, `🇹🇼台湾`：按真实出口分组；
- `🌏亚洲候补`：当前手动候补与历史保护候补；
- `🌍非亚洲稳定`：严格非亚洲；
- `📦全部入选`：所有最终节点，包括亚洲候补与历史保护候补；
- `GMGN自动`：仅亚洲核心和非亚洲稳定，不包含弹性/候补。

地区查询失败节点进入手动相关组和明确的未知状态，不伪装成已验证亚洲。所有代理组引用在发布前后均校验。

## 7. 发布、诊断与触发

### 7.1 自动触发

代码门禁完成后仍只允许手动触发 V2 shadow；单次真实有效影子通过后，才启用“GitHub 每次成功发布新的 profile SHA → 一次 V2 shadow”自动触发。稳态下同 SHA 已成功或正在运行时跳过，基础设施重试复用同一 source SHA 且不重复提交历史。任务锁防止并发发布，旧运行必须检查当前远端状态并拒绝覆盖更新结果。

### 7.2 V2 影子与正式 bundle

代码完成和真实影子阶段只允许写独立的 `clash-cn-gmgn-v2-shadow`；现有 `clash-cn-gmgn-output` 与 `clash-cn-output` 不得被 V2 实现改写。V2 影子不是零散诊断分支，而是与未来正式产物同构的完整 bundle，同一提交至少包含：

- `clash.yaml`；
- `status.json`；
- `history.json`；
- 面向已发布节点的脱敏 `node-status.json`；
- 最近至少 3 次与正式 profile 对应的 content-addressed run 摘要。

所有可从 shadow 原样提升到正式分支的 bundle payload 必须 branch-neutral：不写 shadow/formal mode、分支名、订阅绝对 URL 或 promotion time。状态只记录相对 profile path、逻辑 bundle ID/hash 和运行关联；实际 URL/渠道只存在于 rollout evidence 与用户文档。

profile、history 和对应诊断先在本地 staging 完整构建、解析、hash、引用检查和 Mihomo `-t`，再推送临时 staging ref；只有防缓存远端 smoke 通过后，才用基于已读取 tip 的 `--force-with-lease`/CAS 等价机制提升 V2 shadow current。任何失败都保持整个 V2 shadow last-good 不变。

被拒绝运行只能保留为私有工作流 artifact 或专用失败证据，不能覆盖 V2 shadow 的 current profile、`history.json` 或 current diagnostics。shadow bundle 必须始终保留与当前 profile 对应的同 `run_id` 诊断，因此不会再出现“旧 profile A 只剩诊断 B”的断链。

连续三次有效影子验收且用户明确同意迁移后，将最后一个已验收的同一 bundle 按原 `run_id`、source SHA 和 bundle hash 提升到 `clash-cn-gmgn-output`，不得重新测速或重新选择。正式分支同样通过 staging smoke 与 CAS，远端回读必须证明其内容与验收 bundle 完全一致。

### 7.3 远端 smoke

staging 推送后和 current 提升后都以防缓存 URL 重新下载远端文件并验证：

- schema、SHA、计数、run/source/main/policy 关联；
- 分组名称、引用和稳定节点名；
- 20轮/四分片摘要；
- 目标 Mihomo 版本可加载。

staging smoke 失败时不提升 current；current 提升后的 smoke 失败时任务标红，并只允许使用已记录 previous tip/bundle 与 lease 做受控恢复，绝不能把该 run 宣告为成功或提交 history 差评。

## 8. 安全边界

- 外部配置只接受项目显式支持的协议和字段；拒绝 loopback、link-local、私网、云元数据和非法端点。
- C2 负责可测试的 `network guard`：代理 server 域名在分片启动前解析、验证并固定到公网地址，Mihomo/探测器置于隔离容器或 network namespace；版本化出站策略阻断 loopback、link-local、RFC1918、CGNAT、组播、保留地址、Runner/CI 内网和云元数据地址，controller 通道留在同一隔离边界内。模拟 public→private DNS rebinding 时不得重新命中私网地址。
- C5 负责在 `.cnb.yml` 中配置隔离原语、在每个分片启动前执行 self-test，并把 guard backend/policy version 写入私密 manifest/安全状态。CNB Runner 无法提供隔离、规则未生效或固定解析漂移时整轮失败关闭；V2 rollout 不允许以“只做字符串校验”替代该门禁。
- 来源解析/测速与正式写分支凭据隔离；不可信配置运行阶段不持有发布 token 或私有订阅 secrets。
- 公共 status/provenance/diagnostics 不含代理凭据、原始错误、私有 URL/token 或可逆的私有来源标识。
- Mihomo controller 只绑定 loopback，使用独立 secret/端口/工作目录；运行日志不得打印完整代理配置。

## 9. 外部来源接入

第一阶段只受控接入一个边际增益明确的小来源，优先 `awesome-vpn/awesome-vpn`；随后评估 Mahdibland 亚洲子集。V2Hive 仅作为带每源/每地区/每端点限额的 discovery reservoir。

每个来源在接入前记录 raw、精确唯一、唯一端点、与现池重叠、五地区数量、最后更新时间和生成/验证透明度。候选接近约 5000 时先做容量评估，不无界扩池。

## 10. Rollout 与 gstatic 生命周期

1. **代码门禁**：离线单元/组件/工作流契约和目标 Mihomo 校验全部通过。
2. **单次影子**：新逻辑生成诊断与独立订阅，不覆盖推荐入口。
3. **三次有效影子**：验证历史降级/恢复、名称、地区、多样性、错误门禁和远端 smoke。
4. **入口迁移**：用户确认本机 Clash Verge 结果后，将 GMGN 文档和推荐入口设为默认。
5. **gstatic 冻结**：停止其自动触发，保留 `clash-cn-output` 最后一版和 URL，状态明确标记 frozen/legacy；只有 GMGN 长期不可用时受控手动恢复。

每一阶段通过不自动授权下一阶段。旧 GMGN/gstatic 产物在 canary 期间均不得被新代码原地破坏。

## 11. 兼容与迁移

- 新 status/history/schema 均版本化；旧 schema 只允许显式迁移，不把解析失败当首发。
- 现有 `clash-cn-gmgn-output` 首次迁移时从旧 profile 计算 fingerprint/name 映射，无法可靠迁移的节点生成稳定新名并记录原因。
- GitHub/CNB 文档同时列出候选、GMGN 正式和冻结 gstatic 的用途，避免刷新错误 URL。
- 用户订阅 URL 在 GMGN 正式分支内保持不变；未来多 Worker 也不能要求用户更换链接。

## 12. 明确拒绝的方案

- 不用 GitHub 单轮 GMGN 预筛删除亚洲候选。
- 不为凑 80 降低核心/弹性/非亚洲阈值。
- 不让同一节点的20轮并发执行，也不提前结束正式观测。
- 不在第一版生产中动态自调 workers。
- 不因一个来源本轮失败或一个 CNB 无效运行增加节点差评。
- 不在当前规模下拆仓库。
- 不把 gstatic 长期作为与 GMGN 同等推荐的第二套默认系统。
