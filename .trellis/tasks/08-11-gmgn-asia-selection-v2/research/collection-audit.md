# Research: GitHub 侧亚洲候选采集与发布审计

> Historical audit snapshot: findings describe the pre-V2 code at audit time. Current implementation requirements live in the parent/child task artifacts and `gmgn-v2-contract.md`.

- Query: 审计 GitHub Actions 采集、来源、新鲜度、去重、HK/JP/KR/SG/TW 识别与保护、GMGN 预筛、输出分支/状态契约、性能和测试；核对 2026 年仍活跃的外部候选源。
- Scope: mixed（仓库内部 + 只读 GitHub API/raw 内容）
- Date: 2026-08-11

## Findings

### 结论摘要

当前实现已经有一个明确且有效的核心策略：识别为 HK/JP/KR/SG/TW 的节点会绕过 GitHub 侧普通存活检查、可选中国 TCP 预筛以及 GMGN/Google/YouTube 单轮严格筛选，从而把较宽的亚洲候选交给 CNB 做 20 轮 GMGN 选拔。相关路径见 `subscribe/workflow.py:150-167`、`scripts/apply_tcp_probe.py:43-49`、`scripts/filter_reachability.py:60-81`。

但它尚不能稳定满足“尽可能多、尽可能新、尽可能独立”的目标，主要有四个高优先级缺口：

1. **单个来源一轮失败可以删除该来源的亚洲节点并发布缩水版。** 发布门槛只比较总节点数，没有亚洲总量、单地区数量或来源 quorum；只要剩余总量仍过线，就会覆盖分支。只有整次 job 失败或总量地板失败时，旧分支才保留。
2. **发布前丢失 provenance。** `sub`、`liveness` 等来源信息在生成最终配置前被删除，最终 `status.json` 也只记录总数和亚洲总数，无法回答每个地区来自哪些仓库、某来源贡献多少、是否发生来源集中或异常掉量。
3. **精确配置已去重，但“独立节点”没有定义。** 当前线上 2260 个配置没有精确指纹重复，却只有 1752 个不同 `server:port`，仍有 508 个同入口别名/凭据变体；没有 ASN、网段、供应商或来源多样性约束。
4. **机场轮转会让新来源饥饿。** 已知成功站点永远排在未尝试/到期重试站点之前；一旦 known-good 数量达到 `AIRPORT_MAX_DOMAINS=192`，新的独立机场可能长期没有运行配额。

### 当前线上候选池快照

只读核对 `clash-verge-output`，状态时间为 `2026-08-11T02:41:10Z`，profile SHA-256 与 `status.json` 一致：

| 指标 | 数量 |
|---|---:|
| 总配置 | 2260 |
| 受保护亚洲 | 1163 |
| HK | 259 |
| JP | 376 |
| KR | 121 |
| SG | 271 |
| TW | 136 |
| 非亚洲 | 1097 |
| 不同 `server:port` | 1752 |
| 同 `server:port` 别名/变体 | 508 |
| 最终精确配置指纹重复 | 0 |

线上状态只提供 `proxy_count=2260` 和 `protected_asia_count=1163`，无法从发布物恢复上述节点的来源分布。快照来源：

- `https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/status.json`
- `https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/clash.yaml`

### 数据流与已有保护

GitHub workflow 每天一次 collect、每天三次 refresh；手动任务也共用同一并发组，后启动任务会取消在跑任务（`.github/workflows/clash-verge-auto.yml:3-10`、`.github/workflows/clash-verge-auto.yml:42-44`）。主链路为：

`机场注册采集 + crawler` → 合并 → 可选中国 TCP 预筛 → GMGN/Google/YouTube 过滤 → 状态文件 → orphan 分支强推。

关键实现：

- 机场采集最多运行 192 个域名，发现验证最多 256 个（`.github/workflows/clash-verge-auto.yml:57-60`、`subscribe/collect.py:284-298`、`subscribe/crawl.py:2261-2286`）。
- crawler 当前配置包含 15 个固定社区订阅、1 个日期滚动 ClashFree 文件、5 个 Au1rxx 国家文件和 4 个混合亚洲文件（`scripts/build_crawler_config.py:15-31`、`scripts/build_crawler_config.py:43-112`、`scripts/build_crawler_config.py:115-140`）。五个国家文件都来自同一 Au1rxx 仓库，因此是五个流，不是五个独立上游。
- 亚洲专用任务关闭普通 liveness，并为国家流增加地区前缀、为混合流增加 `ASIA-KEEP`（`scripts/build_crawler_config.py:43-112`、`scripts/build_crawler_config.py:164-179`）。
- 其他动态来源还包括 GitHub code search、搜索引擎、Telegram、Twitter、最新 200 个 forks（默认两页）和 v2rayse/nodebuf（`scripts/build_crawler_config.py:223-327`）。
- 合并时再次调用 `clash.filter_proxies`，然后把 url-test 指向 GMGN（`scripts/merge_clash_profiles.py:17-52`）。

#### GMGN 预筛结论

受保护亚洲节点**不会**在 GitHub 侧做 GMGN 单轮预筛：

- 普通 liveness 阶段直接放入 `nochecks`（`subscribe/workflow.py:150-167`）。
- 中国 TCP 探针不检查、不删除受保护亚洲（`scripts/apply_tcp_probe.py:43-49`、`scripts/apply_tcp_probe.py:74-88`）。
- 最终 GMGN/Google/YouTube 检查只测试非亚洲；亚洲直接进入 `passed`（`scripts/filter_reachability.py:85-89`、`scripts/filter_reachability.py:118-120`、`scripts/filter_reachability.py:175-191`）。

这符合给 CNB 20 轮筛选保留宽池的目标。风险在于：未被名称规则识别的真实亚洲节点仍会被当作非亚洲做三站单轮预筛。识别器覆盖 HK/HKG、JP/JPN、KR/KOR、SG/SGP、TW/TWN 和常见城市，但没有显式覆盖 `TPE/KHH/NRT/KIX/ICN/SIN` 等常见机场代码（`subscribe/asia.py:10-30`）。

### 单轮失败是否会删除亚洲节点

**会，条件性发生。** 具体行为如下：

- workflow 只恢复订阅/域名/crawler 状态，不恢复上一版 `clash.yaml`、`collect-clash.yaml` 或 `crawler-clash.yaml` 作为本轮节点输入（`.github/workflows/clash-verge-auto.yml:97-114`）。
- crawler 使用 `--overwrite`，不会把上一版组输出作为 remains 合并（`.github/workflows/clash-verge-auto.yml:221-241`；`subscribe/process.py:536-545`）。
- 固定亚洲 raw 源没有 last-good 内容缓存；某源本轮空或超时，该源节点就不进入新 profile。
- 发布地板只读取上一版 `proxy_count`，计算总量下限；它不读取上一版 `protected_asia_count`，也没有 HK/JP/KR/SG/TW 单区下限（`scripts/filter_reachability.py:52-57`、`scripts/filter_reachability.py:181-191`）。

因此，只要非亚洲或其他亚洲来源让总数仍过线，本轮可以发布“某一地区大幅掉量甚至亚洲为零”的新分支。反过来，如果 profile 为空、全部校验失败、目标检测异常或总量低于地板，步骤会失败，后续强推不会发生，旧分支保留（`scripts/filter_reachability.py:94-108`、`scripts/filter_reachability.py:145-170`、`scripts/filter_reachability.py:187-191`）。

### 来源新鲜度与覆盖瓶颈

1. **机场运行配额不公平。** `select_airport_domains` 按 known-good → untried → due 排序，达到 limit 即停止（`subscribe/collect.py:90-115`）。当 known-good ≥ 192 时，新站点没有最低探索配额，直接违背“尽可能多的新独立候选”。
2. **动态订阅有失败计数，但固定 raw 源没有同等机制。** crawler 持久化订阅会合并旧记录并在失败阈值内继续观察（`subscribe/crawl.py:354-375`、`subscribe/crawl.py:389-460`）；固定 `COMMUNITY_SUBS`/`ASIA_SOURCE_SPECS` 每轮直接抓取，没有逐源 last-success 快照或掉量门槛。
3. **GitHub 搜索“新鲜”仅是弱信号。** 六个固定查询只取每个查询的第一页，并按 indexed 排序；没有 pushed/created 时间窗、亚洲地区查询或每仓库配额（`subscribe/crawl.py:67-74`、`subscribe/crawl.py:1075-1121`、`subscribe/crawl.py:1159-1208`）。
4. **fork 扫描默认只看最新两页。** 旧持久化订阅会继续验证，这是好的；但“新 fork”不等于“内容新鲜”，完整历史扫描只能手动开启（`scripts/build_crawler_config.py:279-294`、`subscribe/scripts/gitforks.py:201-225`）。
5. **滚动文件只按文件名最大值选择。** ClashFree resolver 没有验证文件日期与当前日期接近，也没有检查 commit age（`scripts/build_crawler_config.py:115-140`）。

### 去重与 provenance 丢失路径

#### 去重

- 最终 proxy 去重先按名称排序，再按 `server:port` 和协议凭据判重（`subscribe/clash.py:83-91`、`subscribe/clash.py:137-175`）。它能删除完全相同配置，但会保留同入口的不同凭据/协议，也没有 IP/ASN/网段级独立性。
- 名称排序决定重复项保留哪一份。若同一配置同时来自普通源和带 `ASIA-KEEP`/地区前缀的源，字典序更早的普通名称可能先保留，保护标记和来源语义可能随重复项丢失。当前没有“合并保护位与 provenance”的逻辑。
- task 层还有一个明显缺陷：`workflow.exists` 的循环无条件在第一次比较后 `break`，实际只与任务列表第一项判重（`subscribe/workflow.py:191-216`）。最终 proxy 去重会掩盖结果重复，但无法避免重复下载、解析与测试成本。

#### provenance

`AirPort.parse` 给节点附加 `sub` 和 `liveness`（`subscribe/airport.py:852-857`），随后：

- 机场链路在写 profile 前删除 `chatgpt`、`liveness` 和 `sub`（`subscribe/collect.py:438-448`）。
- crawler 链路在输出前删除 `sub`（`subscribe/process.py:629-637`），liveness 分流时也会弹出相关字段（`subscribe/workflow.py:154-165`）。
- merge 仅拼接 proxy dict，没有单独 provenance sidecar（`scripts/merge_clash_profiles.py:17-44`）。
- `status.json` 只写总数、亚洲总数、URL、哈希和 main SHA（`scripts/prepare_github_publish.py:35-54`）。

结果是：线上 1163 个亚洲节点无法按 repo、订阅 URL、机场域名、发现渠道或采集时间归因，也无法判断 259 个 HK 是否实际集中于一两个上游。

### 输出分支与状态契约

好的部分：

- 发布分支每次重建为单个 orphan commit，避免历史无限增长；任何过滤步骤失败时不会执行强推，旧分支天然保留（`.github/workflows/clash-verge-auto.yml:287-323`）。
- CNB 读取 `run_at` 和 `profile_sha256`，下载 profile 后校验哈希和新鲜度，GitHub→CNB 快照边界是 fail-closed 的（`scripts/cnb_gmgn_shadow.py:229-289`、`.cnb.yml:330-380`）。

缺口：

- `status.json` 没有 `kind`/`schema_version`、五地区计数、来源计数、候选/实测计数、降级原因和上一版比较。
- `alive_check` 是请求参数字符串，而非真实测试覆盖率；当前即使为 `"true"`，受保护亚洲仍完全跳过网络检查（`scripts/prepare_github_publish.py:45-54`）。对手动 Clash 使用者，这会误导为“全部节点已测活”。
- 同一 profile 混合“未经 GitHub 网络检查的亚洲候选”和“通过三站检查的非亚洲节点”，README 只给 URL 和时间，没有说明该混合语义（`scripts/prepare_github_publish.py:60-65`）。
- manual 模式只禁止发布原始 `subscribes.txt`，但最终 `clash.yaml` 本身仍包含派生代理凭据；这是公开订阅的既有行为，不能把“隐藏原订阅 URL”理解为保密（`.github/workflows/clash-verge-auto.yml:261-285`）。

### 性能风险

- GitHub job 上限 210 分钟，机场注册、crawler 解析、Mihomo liveness 和三站检查顺序执行（`.github/workflows/clash-verge-auto.yml:71-95`、`.github/workflows/clash-verge-auto.yml:173-259`）。
- 固定 raw 源单文件允许读取到 15 MiB（`subscribe/airport.py:717-725`），crawler 没有总候选上限或每来源节点上限；增加一个几千节点聚合源会同时放大解析、去重、配置生成和 CNB 20 轮开销。
- CNB GMGN prepare 会按 4 shards × 16 workers 估算全超时时长，超过 6600 秒就拒绝启动（`.cnb.yml:347-349`、`scripts/cnb_gmgn_shadow.py:661-713`）。按当前 3000ms 超时和 20 轮配置，总池约到 5.2k 左右就接近该安全预算。
- 当前 508 个同 `server:port` 变体会重复消耗 CNB 20 轮配额；若目标是独立候选，应在“精确配置去重”之外增加入口/网段多样性度量，但不要直接删除所有共享入口变体，避免误伤不同协议或有效凭据。

### 只读 GitHub 外部候选核对

以下时间与数量来自 2026-08-11 的 GitHub API/raw 只读快照；没有修改源列表。

| 项目/产物 | 最近产物提交 | 格式与五区数量 | 价值 | 重复/信任风险 |
|---|---|---|---|---|
| `awesome-vpn/awesome-vpn` `clash.yaml` | 2026-08-11 01:08Z | Clash YAML；127 总，亚洲 20（HK8/JP3/KR5/SG2/TW2） | 使用 GeoLite 标地区，并通过 sing-box 实际代理访问验证，适合作为小而相对干净的补充 | 上游 URL 与 Telegram 列表来自 Secrets，公开仓库无法审计来源；仍是聚合器，与现有源有重叠 |
| `mahdibland/V2RayAggregator` `Eternity.yml` | 2026-08-11 02:55Z | Clash YAML；201 总，亚洲 84（HK10/JP39/KR33/SG1/TW1） | 已做 GitHub 机房速度筛选，可作为 JP/KR 补充 | 与本仓库已有多个社区源高度重叠；GitHub 视角测速不代表中国/GMGN；地区分布偏斜 |
| 同项目 `sub/sub_merge_yaml.yml` | 2026-08-11 02:24Z | Clash YAML；5213 总，亚洲约 728 | 宽池很大 | 215 个精确重复，且完整池本身已接近 CNB 单次安全预算；只能先按亚洲/来源限额抽取，不能无界加入 |
| `cybersecplayground/V2Hive` `by-country/*.txt` | 2026-08-11 04:00Z | URI lists；HK603/JP2775/KR368/SG695/TW137，共 4578 | 五区文件齐全、更新频繁，是很大的发现 reservoir | 公开仓库没有生成脚本/工作流，验证和 GeoIP 方法不可审计；JP 内有约 424 个同入口别名，且与 Mahdibland 入口大量重叠；全量加入可能触发 CNB 预算保护 |
| `Epodonios/v2ray-configs` `All_Configs_Sub.txt` | 2026-08-11 04:39Z | URI list；6933 行 | 更新很频繁 | 当前名称规则识别不到五区，且约 2081 行为精确重复；没有 GeoIP 前不适合作为亚洲源 |
| `ALIILAPRO/v2rayNG-Config` `sub.txt` | 2026-08-11 04:50Z | URI list；1661 行，仅识别到 3 个亚洲名称 | 可作一般发现源 | 对五区增益极低，来源/验证透明度不足 |
| `free-nodes/clashfree` `sub.yml` | 2026-08-11 02:50Z | Clash YAML；1393 总，当前名称规则识别不到五区 | 已通过滚动 ClashFree 被现有配置使用 | 约 343 个精确重复；不是新的独立来源 |

现有 Au1rxx 五个国家文件同次刷新共 726 条原始记录，但只约 279 个不同精确配置指纹，说明“源文件条数”不能直接当作独立候选数。对外部新源应记录：raw 数、精确唯一数、唯一入口数、与现池重叠数、五区数和最后提交时间。

外部参考：

- `https://github.com/awesome-vpn/awesome-vpn`
- `https://github.com/mahdibland/V2RayAggregator`
- `https://github.com/cybersecplayground/V2Hive`
- `https://github.com/Epodonios/v2ray-configs`
- `https://github.com/ALIILAPRO/v2rayNG-Config`
- `https://github.com/free-nodes/clashfree`

### 缺失测试

现有 `tests/test_asia_retention.py` 只验证识别样例、九个固定亚洲任务和两个 bypass helper（`tests/test_asia_retention.py:21-93`）。最重要的缺口是：

1. 单个亚洲源失败、某地区归零但总量仍过线时，发布应保留 last-good 或 fail-closed。
2. `previous protected_asia_count`、HK/JP/KR/SG/TW 绝对数与保留比例门槛。
3. 普通源与 `ASIA-KEEP` 源含同一配置时，去重后仍保留亚洲保护位和全部 provenance。
4. `workflow.exists` 必须遍历全部任务，而非只比较第一项。
5. known-good 超过 192 时仍给 untried/due 固定探索配额。
6. GitHub 搜索查询 fan-out、第一页限制、限流/空响应和 source-health 行为。
7. `prepare_github_publish` 的 schema、布尔类型、五区/来源计数、candidate-vs-tested 计数和 YAML 解析失败行为。
8. collect+crawler→merge→TCP→reachability→publish 的 fixture 级端到端测试。
9. 输出 workflow 契约测试：恢复哪些文件、发布哪些文件、失败时不覆盖分支、status/profile 哈希一致。
10. 性能回归：大源、同入口大量别名、CNB 估算预算边界。

### 建议优先级

1. **先补发布保护契约。** `status.json` 增加 schema、五地区计数、来源数、candidate/tested 数；基于上一版设置亚洲总量和单地区绝对/比例地板。异常掉量时保留上一版并发布 diagnostics，不覆盖订阅。
2. **保留 provenance sidecar。** 以稳定 proxy fingerprint 为 key，记录 source repo/URL、discovered_at、last_seen、地区判断依据、是否 GitHub-tested；不要依赖最终显示名称反推来源。
3. **让去重合并元数据。** 精确重复项应合并 `protected_asia` 与来源集合，再决定展示名称；另输出 server:port、IP/ASN/网段多样性指标供 CNB 选拔，而不是把配置条数等同独立节点数。
4. **把机场轮转改为配额制。** known-good、untried、due 各保留固定比例，确保持续探索；对每个固定 raw 源维护 last-good 快照和掉量检测。
5. **区分“宽候选”与“已测可用”语义。** 最理想是 broad candidate 分支供 CNB 和人工挑选，strict/manual-friendly 分支供普通 Clash；若暂不拆分，至少在 README/status 明确亚洲节点未在 GitHub 做网络验证。
6. **外部源按边际增益接入。** 优先小而验证透明的 `awesome-vpn`，再评估 Mahdibland 的受控亚洲子集；V2Hive 只适合作为限额 discovery reservoir，必须先做 freshness、fingerprint、入口多样性和现池重叠审计。

## Files Found

- `.github/workflows/clash-verge-auto.yml` — GitHub 采集、过滤和发布总入口。
- `scripts/build_crawler_config.py` — 固定社区源、亚洲专用源和动态 crawler 配置。
- `subscribe/crawl.py` — GitHub/search/Telegram/机场发现、持久化和 source health。
- `subscribe/collect.py` — 机场任务轮转、存活检查和订阅/profile 输出。
- `subscribe/process.py` — crawler 任务执行、liveness 分流和输出。
- `subscribe/asia.py` — 五地区名称识别契约。
- `subscribe/workflow.py` — task 去重和亚洲 liveness bypass。
- `subscribe/clash.py` — proxy 配置验证前后的精确去重与重命名。
- `scripts/merge_clash_profiles.py` — collect/crawler 合并边界。
- `scripts/apply_tcp_probe.py` — 可选中国入口探针及亚洲保护。
- `scripts/filter_reachability.py` — GitHub 三站过滤、总量发布地板。
- `scripts/prepare_github_publish.py` — GitHub 状态/README 契约。
- `.cnb.yml`、`scripts/cnb_gmgn_shadow.py` — GitHub 快照消费、新鲜度/哈希和 CNB 性能预算。
- `tests/test_asia_retention.py` — 当前亚洲识别和 bypass 的主要测试。

## Related Specs

- `.trellis/spec/guides/cross-layer-thinking-guide.md` — 本任务跨越 source → transform → branch/status → CNB consumer，适用边界契约与完整数据流检查。
- `.trellis/spec/guides/code-reuse-thinking-guide.md` — 亚洲识别、去重和状态计数应保持单一 owner，避免不同阶段重新实现。
- 审计当时 `.trellis/spec/` 只有 `manager` 包规范，没有覆盖根目录 Python 采集脚本、GitHub Actions 和输出分支契约；规划阶段随后已补齐 `.trellis/spec/aggregator/` 并设为默认包。

## Caveats / Not Found

- 审计当时任务 PRD 尚未完成，本报告因此以派发目标和现有代码行为作为审计基准；当前正式 PRD/design/implement 已补齐并作为实施权威。
- 线上数量和外部项目数量是 2026-08-11 的瞬时快照，自动更新后会变化。
- 外部重复统计分为精确配置/URI 重复和 `server:port` 入口重叠；入口相同不必然代表配置等价，但足以说明它们不是完全独立的网络候选。
- 没有运行会写入仓库缓存或业务文件的集成测试；结论来自代码审计、只读 API/raw 数据和内存解析。
