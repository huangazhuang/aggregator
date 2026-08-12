# Research: GitHub/CNB 测试、公开分支契约与运维流程审计

> Historical audit snapshot: gaps describe the repository at audit time. Current acceptance and rollout contracts live in the parent/child task artifacts and `gmgn-v2-contract.md`.

- Query: 审计 GitHub/CNB 订阅流水线的现有测试、文档、公开分支契约和运行流程，判断是否真实证明 20 轮、四分片、新鲜源固定、发布安全、历史保留、地区分组、稳定名称、诊断、缓存/更新和真实输出校验。
- Scope: mixed（仓库代码/测试/工作流/文档 + 只读公开分支快照）
- Date: 2026-08-11

## Findings

### 总结结论

- 现有测试对“合成数据上的选择策略、字段完整性、脱敏、失败门槛”覆盖较强；对“真实工作流执行、跨运行状态、公开分支最终结果”覆盖明显不足。
- GMGN 当前基线已经有恰好 20 轮、四分片、全部分片一致性、旧版本读取失败关闭、10/40% 发布门槛和发布前 Mihomo 配置检查等实现。但多数运维保证只由配置文本或合成 JSON/YAML 证明，没有完整的 prepare → 4 probe → merge → history → render → Mihomo → push → remote fetch 端到端测试。
- 与当前 PRD 相比，尚未被实现或证明的核心项是：最短观察时间窗、多轮历史状态机、真实出口地区与地区分组、跨运行稳定节点名、公开节点到诊断记录的安全关联、缓存恢复失败时的失败关闭、发布后远端校验。
- 所有公开结果分支都采用强制推送最新单提交；这能保留“最后一版分支 tip”，但不会保留可审计的提交历史。文档要求连续观察 2–3 轮，当前公开分支本身无法提供这 2–3 轮历史。
- 2026-08-11 的只读实况快照显示当前 GitHub、gstatic、GMGN 和 shadow 输出结构一致，GMGN 确实为 20 轮/4 分片；但这只是本次人工审计证据，不是仓库自动化测试。

### 主要文件

| 文件 | 作用 |
|---|---|
| .github/workflows/tests.yml | PR/push 单元测试入口，只运行 unittest discover。 |
| .github/workflows/clash-verge-auto.yml | GitHub 候选池收集、缓存恢复、严格过滤和 clash-verge-output 发布。 |
| .github/workflows/sync-cnb.yml | GitHub main 到 CNB main 的同步及两个 CNB 标签触发器。 |
| .cnb.yml | gstatic 正式任务、GMGN 四分片任务、CNB 输出/诊断分支发布。 |
| scripts/cnb_gmgn_shadow.py | 新鲜源固定、分片、20 轮探测、fragment 验证和脱敏 shadow 合并。 |
| scripts/cnb_gmgn_publish.py | 四个私有 fragment 校验、GMGN 分层选择、旧版本读取、迟滞和订阅渲染。 |
| scripts/cnb_mihomo_filter.py | gstatic 3+17 全量探测、分层选择、失败诊断和状态输出。 |
| scripts/cnb_diagnostics.py | gstatic 脱敏失败摘要、回放数据和策略快照。 |
| scripts/prepare_github_publish.py | GitHub status.json、last-run.txt 和 README 生成。 |
| scripts/pipeline_utils.py | 发布门槛、REALITY 序列化、代理组引用过滤。 |
| subscribe/asia.py | HK/TW/SG/JP/KR 名称启发式识别。 |
| tests/test_cnb_gmgn_shadow.py | GMGN 指标、隐私、分片、workflow 静态结构和 merge 校验。 |
| tests/test_cnb_gmgn_publish.py | GMGN 分层政策、四 fragment、旧版本、发布门槛和固定组名。 |
| tests/test_asia_retention.py | 亚洲名称识别、过滤绕过和 gstatic 选择边界。 |
| tests/test_cnb_policy_replay.py | 诊断脱敏、策略回放、schema 和 run_id/source_sha 一致性。 |
| tests/test_pipeline_utils.py | 发布门槛、REALITY 字符串和代理组引用过滤。 |
| CNB_SETUP.md / CLASH_VERGE_AUTO.md | 公开订阅地址、运行规则和用户操作契约。 |

### 逐项覆盖审计

#### 1. 恰好 20 轮：部分充分，未证明真实 20 次采样和时间窗

已有证据：

- GMGN prepare 明确拒绝 19/21 轮：tests/test_cnb_gmgn_shadow.py:187-207。
- probe 和 merge 都会在读取 shard/result 前拒绝非 20 轮 manifest：tests/test_cnb_gmgn_shadow.py:498-523、946-963。
- fragment 校验要求每节点 attempts 等于 total_rounds，并交叉核对逐轮趋势、前后半程、5 轮块和错误总数：scripts/cnb_gmgn_shadow.py:1185-1255、1298-1418。
- gstatic 主流程明确让所有节点先跑 preliminary_rounds，再让同一全集补足 total_rounds：scripts/cnb_mihomo_filter.py:1085-1136；完成后拒绝 attempts 不等于 total_rounds 的结果：1162-1181。
- 合成选择测试覆盖 14/20、12/20、10/20、16/20、18/20 等阈值边界：tests/test_asia_retention.py:161-226、tests/test_cnb_gmgn_publish.py:253-318。

缺口：

- 没有测试让两个以上真实/模拟节点完整经历 20 次 API 请求，并断言每个节点调用次数恰好为 20、没有早退、没有重复。
- tests/test_asia_retention.py:120-147 只直接执行 2 个探测轮次；因此 CNB_SETUP.md:184 声称“测试覆盖 3+17 轮采样”高于实际证明强度。
- PRD 要求“明确的最短观察窗口”（prd.md:37），当前只配置 round gap 0.75 秒（.cnb.yml:344-345），没有 wall-clock 下限、可注入时钟或耗时断言。快速响应时 20 轮可能在很短窗口内完成。

结论：⚠️ 形式不变量较强；真实采样次数与时间覆盖未证明。

#### 2. 四分片：配置和合成 fragment 较强，缺少全链路四进程集成

已有证据：

- partition 测试证明 4 片完整、平衡、无重复且不受输入顺序影响：tests/test_cnb_gmgn_shadow.py:347-369。
- workflow 测试解析 .cnb.yml，断言四个 job、独立端口、独立 private output 和固定 16 workers：tests/test_cnb_gmgn_shadow.py:747-817。
- GMGN publisher 强制 manifest 为 4 shards/20 rounds，且测试拒绝少一个私有 fragment：scripts/cnb_gmgn_publish.py:310-330、tests/test_cnb_gmgn_publish.py:494-503。
- .cnb.yml 的 merge/publish 明确列出 shard-0..3：.cnb.yml:382-458、519-530。

缺口：

- shadow merge 的“成功合并” fixture 只构造 1 个 shard：tests/test_cnb_gmgn_shadow.py:870-930、984-1017。
- publisher 测试会生成 4 个合成 selection fragment，但没有执行 prepare、四个独立 probe 进程、公开 shadow merge 和 publisher 的完整链。
- 静态 YAML 断言不能证明 CNB 实际并行调度、跨 job 文件可见性、锁行为或端口冲突。

结论：⚠️ 分片契约有较好单元/组件证明；真实并行链未自动化。

#### 3. 新鲜源固定：实现正确方向，负面路径覆盖很少

已有实现：

- GMGN 使用同一 nonce 给 status/profile 加防缓存参数，校验 profile_sha256 和 run_at 年龄，失败可轮询等待：scripts/cnb_gmgn_shadow.py:229-289。
- gstatic 在 .cnb.yml 内嵌 Python 中使用同一 cache key、no-cache 头、时间窗口和 SHA-256，再把通过校验的两份文件写到本次运行目录：.cnb.yml:97-185。
- 当前唯一直接测试验证“status 缺失 profile_sha256 时即使 YAML 有效也拒绝”：tests/test_cnb_gmgn_shadow.py:388-420。

缺口：

- 没有覆盖：正确新鲜 pair 成功、过旧、未来超过 300 秒、hash mismatch、第一次 mismatch 后第二次成功、等待超时、每次 retry 更换 nonce、profile/status 使用同一 nonce、Cache-Control/Pragma 请求头。
- gstatic 的固定逻辑仍是工作流内嵌 Python，没有独立单元测试。CNB_SETUP.md:166 声称工作流“不再包含大段内嵌 Python”，与 .cnb.yml:101-174 不一致。
- gstatic 内部 load_source_snapshot 在没有 expected hash 时可接受未固定 profile（scripts/cnb_mihomo_filter.py:178-193）；生产 workflow 的前置快照目前补上了这一保护，但直接调用脚本的契约不是严格 fail-closed。

结论：⚠️ 生产路径有 pinning；测试不足，且 gstatic 有双重实现漂移风险。

#### 4. 发布安全：GMGN 局部较强，GitHub/gstatic 的旧状态读取会失败打开

GMGN 已有较强证据：

- 已确认分支不存在时才允许首发且不读 raw URL；已存在分支的 404、单边 404、HTTP 500、坏 YAML、hash/count mismatch 全部失败关闭：tests/test_cnb_gmgn_publish.py:587-721。
- 首发少于 10 个时拒绝且 output 目录不创建；后续门槛为 max(10, previous × 40%)：tests/test_cnb_gmgn_publish.py:723-779。
- 渲染后会重新 safe_load 并核对 proxy 数量：scripts/cnb_gmgn_publish.py:845-879。
- CNB build 在 push 前执行仓库内 Mihomo 二进制的配置检查：.cnb.yml:531-535；workflow 测试仅静态确认该命令存在：tests/test_cnb_gmgn_shadow.py:795-812。

关键缺口：

- GitHub 恢复旧 output branch 时 git fetch 使用 “|| true”，恢复失败会静默冷启动：.github/workflows/clash-verge-auto.yml:97-114。previous-status 不存在时 previous count 退化为 0：scripts/filter_reachability.py:52-57，因此相对保留门槛可从旧大版本退化成绝对 20。
- gstatic previous status 使用 load_optional_json；任何下载/解析失败都返回空对象：scripts/cnb_mihomo_filter.py:145-153、1151-1161，因此相对门槛可退化成绝对 50。测试只覆盖成功读取 JSON：tests/test_pipeline_utils.py:39-41。
- GitHub/gstatic 没有对“旧状态读取失败时不得覆盖旧分支”的主流程测试。
- push 都是无 compare-and-swap 的 force push。锁降低同类任务并发，但不能证明外部修改或异常重试不会覆盖较新 tip。
- 没有测试真实执行 Mihomo -t；只测试 YAML 解析或 workflow 字符串。

结论：⚠️ GMGN publisher 的本地失败关闭较强；GitHub/gstatic 旧状态恢复存在实际 fail-open 风险。

#### 5. 历史保留：只有一次迟滞；没有 PRD 要求的多轮历史状态机

已有证据：

- proxy_fingerprint 排除易变 name：scripts/cnb_gmgn_publish.py:163-175。
- 当前逻辑只允许“上一版 stable 且上一版不在 observation”并且本轮 12–13/20 的亚洲节点进入一次 observation：scripts/cnb_gmgn_publish.py:647-725。
- 测试明确证明 one-run hysteresis、旧 observation 不再继续观察、低于 10 直接删除：tests/test_cnb_gmgn_publish.py:417-447；发布输出会把一次保留节点放入 GMGN观察保留：854-894。

缺口：

- 没有持久化连续失败次数、上次层级、迁移原因和恢复记录；不能实现 PRD R5 的“连续 2 或 3 次后移除”和自动恢复（prd.md:56-62）。
- 没有 3–5 次连续运行 fixture，覆盖 core → candidate → observation → removed → recovered、source disappeared、invalid config。
- GitHub output 每次创建 orphan commit 并 force push：.github/workflows/clash-verge-auto.yml:293-323。
- CNB 的 clash-cn-output、clash-cn-diagnostics、clash-cn-gmgn-shadow、clash-cn-gmgn-output 都从新 git init 目录 force push：.cnb.yml:238-255、274-300、472-485、547-559。
- 因此公开分支只保留最新 tip，不保留可供“连续观察 2–3 轮”的提交历史；shadow/diagnostics 也只保留最新一次。

结论：❌ 多轮历史保留尚未实现；现有测试只证明一次迟滞。

#### 6. 地区分组：当前只有 Asia 布尔启发式和 tier 组

已有证据：

- HK/TW/SG/JP/KR 名称/旗帜/短标签识别有测试：tests/test_asia_retention.py:21-59。
- 当前 GMGN 固定组名为 手动选择、GMGN稳定、亚洲弹性、GMGN观察保留、GMGN自动：scripts/cnb_gmgn_publish.py:72-76、766-809；测试断言恰好这 5 组：tests/test_cnb_gmgn_publish.py:780-852。
- shadow/status 明确标记地区分类只是 source-label heuristic、未验证出口：scripts/cnb_gmgn_shadow.py:1571-1606、scripts/cnb_gmgn_publish.py:904-905。

缺口：

- 没有真实出口 country/region、IP、ASN 的最终节点验证和缓存契约。
- 没有 PRD R7 要求的香港、日本、韩国、新加坡、台湾、亚洲候补、非亚洲稳定、全部入选等组（prd.md:71-76）。
- 没有地区未知、查询失败、IP/ASN 集中度、同 server/source 上限测试。
- 当前测试验证的是旧 5 组，未来实现新契约时必须同步替换，而不是在旧断言上追加。

结论：❌ PRD 所需地区组和真实地区验证不存在。

#### 7. 稳定名称：组名稳定，节点输出名不稳定

已有证据：

- GMGN 组名是常量并被精确断言。
- 历史关联使用不含 name 的 fingerprint，因此源名称变化不会单独破坏迟滞身份。
- 每次输出会避免代理名与组名/内置名冲突：scripts/cnb_gmgn_publish.py:729-740。

缺口：

- 输出名仍直接取本轮 source name；如果源改名，同一 fingerprint 的公开名称会变化。
- 重名 suffix 由当前遍历顺序分配；gstatic unique_proxy_names 同样按输入顺序追加 -2/-3：scripts/cnb_mihomo_filter.py:252-266。
- 没有跨运行测试证明：输入重排、源名称变化、同名碰撞、tier/rank 变化后同一 fingerprint 保持相同公开名。
- 没有持久化 fingerprint → output_name 映射。

结论：❌ 稳定组名已证明；稳定节点名未实现。

#### 8. 诊断：隐私和回放较强，公开节点可解释性及运维发布较弱

已有证据：

- gstatic 诊断测试验证随机 opaque node_id、凭据/名称/原始错误不泄露、小型 failure 摘要和独立 replay 文件：tests/test_cnb_policy_replay.py:64-197。
- failure 与 replay 的 run_id/source_sha 对齐、错误 bundle 拒绝、策略 schema/缺字段拒绝均有测试：tests/test_cnb_policy_replay.py:321-462。
- GMGN shadow 测试验证私有 selection 与公开 redacted fragment 分离、敏感字段不进入公开文件：tests/test_cnb_gmgn_shadow.py:525-719、984-1042。
- shadow merge 会交叉校验 node totals、round trends、half/block totals、error counts：scripts/cnb_gmgn_shadow.py:1298-1418。

缺口：

- 当前 shadow node_id 每轮随机，GMGN 输出 status/profile 没有把公开节点安全关联到对应诊断 ID；因此无法满足 PRD R3 “解释某个公开节点为何入选、降级或淘汰”（prd.md:46）。
- tests 正在证明“不含 name”，但没有测试一个不泄密的 public diagnostic key 或 reason 映射。
- 没有解析 .cnb.yml failStages 并验证诊断分支名、只复制允许文件、失败 push 不改变原始失败状态的 workflow 测试。
- GMGN 正式发布失败没有独立 failStages/失败摘要；成功 shadow 可用于推断总量，但不能记录 history/render/Mihomo/push 阶段的失败原因。
- diagnostics/shadow 分支 force push，只保留最新一次。

结论：⚠️ 数据隐私与离线回放强；公开可解释性和远端诊断生命周期不足。

#### 9. 缓存与更新：实现较多，测试几乎只做静态字符串断言

已有实现：

- GitHub output branch 保存 subscribes/domains/crawler/source-health 等状态，下轮 shallow restore：.github/workflows/clash-verge-auto.yml:97-114。
- auto 模式按 cron 选择 collect/refresh，缺少 subscribes 时回 collect：.github/workflows/clash-verge-auto.yml:131-151。
- GMGN source 与 previous profile/status 都加 cache-busting query 和 no-cache headers：scripts/cnb_gmgn_shadow.py:248-289、scripts/cnb_gmgn_publish.py:459-495。
- workflow 测试静态断言 previous_cache_key、previous profile/status 参数存在：tests/test_cnb_gmgn_shadow.py:795-810。

缺口：

- 没有测试 GitHub restore 成功/失败、refresh/collect 选择、缓存文件缺一项、旧 schema、缓存污染、force-push 后 restore。
- 没有测试 HTTP 请求实际包含预期 query/header、同一 pair 的 nonce 一致、retry nonce 更新。
- GitHub restore 和 gstatic previous status 的失败打开问题会直接削弱发布保留门槛。
- 测试环境安装 requirements.lock 中 PyYAML 6.0.3；CNB workflow 显式安装 PyYAML 6.0.2（.cnb.yml:90、355）。序列化/解析契约没有在与生产完全相同的依赖版本上验证。
- 仓库内 clash/clash-linux-amd 被直接执行，但 status/日志和测试没有固定或断言 Mihomo 版本/hash。

结论：⚠️ 有缓存机制；缺少可执行的更新/恢复契约测试，且测试/生产依赖有漂移。

#### 10. 真实输出校验：没有自动化 public-contract smoke

现状：

- tests.yml 和 GitHub 发布任务都只运行 python -m unittest discover -s tests -v：.github/workflows/tests.yml:35-36、.github/workflows/clash-verge-auto.yml:94-95。
- GitHub push 后只输出 URL，没有重新下载远端 status/profile。
- CNB GMGN 在 push 前执行 Mihomo -t，但 push 后不重新下载远端文件；gstatic 最终只 safe_load YAML，没有 output profile SHA 或最终 Mihomo -t。
- GitHub status 有 profile_sha256；GMGN status 有 kind/schema/profile_sha256；gstatic status 只有 source_sha256，没有已发布 clash.yaml 的 profile_sha256：scripts/cnb_mihomo_filter.py:1333-1423。

2026-08-11 只读公开快照：

| 输出 | 本次实况 |
|---|---|
| GitHub clash-verge-output | 2260 proxies；status 数量与 YAML 一致；profile SHA-256 20701b963a798db1139eb149c1a741241a50c2ac7dd94ac111e57893d79542d3 匹配；组为 automatic / 🌐 Proxy。 |
| CNB clash-cn-output | 84 proxies；status total_rounds=20、candidate_count=2260；YAML 数量一致；组仍为 automatic / 🌐 Proxy；status 没有 output profile hash。 |
| CNB clash-cn-gmgn-output | 26 proxies；status total_rounds=20、shard_count=4；profile hash 2abdb84211fe0ecbd6e9bc72ef7b8de66c39006faeed6b68cc5daa2ce0ea1911 匹配；组为当前旧 5 组。 |
| CNB clash-cn-gmgn-shadow | source/result 都为 2260；4 个 shard proxy_count 合计 2260；round_trends 长度 20；shadow/results/GMGN publish 的 run_id 与 source_sha 一致。 |
| 三份 clash.yaml | YAML 可解析；代理名/组名无重复；组引用无缺失。未在本机执行 Linux Mihomo，因此不构成真实客户端兼容性证明。 |

结论：❌ 当前实况看起来一致，但仓库没有自动化远端校验，无法防止 push/CDN/缓存/分支内容与本地构建不同。

### 文档与公开分支契约风险

- 文档已清楚列出三个用户入口及用途：CLASH_VERGE_AUTO.md:5-35、CNB_SETUP.md:14-26。
- CNB_SETUP.md:164-184 对本地测试能力有两处过度陈述：gstatic 仍含内嵌 Python；现有测试没有真正执行 3+17 全流程。
- CLASH_VERGE_AUTO.md:96-116 描述最新状态与缓存文件，但未说明 clash-verge-output 是 orphan + force-push、没有历史。
- CNB_SETUP.md:26、70-72、97 要求用户观察多轮，但 shadow/diagnostic/output 分支都只保留最新一次。
- GitHub status.json 没有 kind/schema_version；gstatic status.json 没有 top-level kind/schema_version 和 output profile hash；只有 GMGN output/shadow 有明确版本化 kind/schema。这使公开 contract smoke 难以稳定演进。
- 分支隔离在配置中明确：clash-verge-output、clash-cn-output、clash-cn-diagnostics、clash-cn-gmgn-shadow、clash-cn-gmgn-output；现有测试只对 GMGN 分支和部分触发器做静态断言，没有覆盖所有 branch/file allowlist。

### 推荐验证矩阵

| ID | 层级/触发 | 场景 | 必须断言 |
|---|---|---|---|
| U-20 | PR 单元测试 | 1–3 个节点跑完整模拟 20 轮 | 每节点 API 调用恰好 20；慢响应/timeout/HTTP 错误均占一轮；无早退/重复；round trends 与节点汇总一致。 |
| U-WINDOW | PR 单元测试 | 注入 fake clock/sleeper | 20 轮总观察时长不低于版本化下限；并发节点不改变同一节点顺序；测试不依赖真实 sleep。 |
| U-SHARD | PR 属性/参数化测试 | N=4、5、2260、5000 和输入重排 | 每候选恰好一片、无重复/遗漏、平衡、稳定 partition、容量估算不低估。 |
| C-4SHARD | PR 组件测试 | prepare fixture → 4 个 fake probe → merge → publish | 四片非空/含空片边界都通过；缺片、重复片、source/main/threshold/hash 不一致全部失败；最终数量等于源。 |
| C-SOURCE | PR 本地 HTTP server | stale、future、hash mismatch、先错后对、timeout | 同一 pair 同 nonce/no-cache；retry 使用新 nonce；只有新鲜且 hash 匹配才写快照；超时不产生 publish input。 |
| C-HISTORY | PR 多运行状态机 | core → 低分 1 → 低分 2/3 → removed → recovered | 配置化连续次数、稳定 fingerprint、迁移原因、source missing/invalid 直接移除、恢复自动晋级。 |
| C-NAME | PR 多运行 fixture | 改 source name、重排、同名碰撞、排名变化 | 同一 fingerprint 的 output_name 稳定；名称不含延迟/排名；冲突后仍稳定且所有组引用有效。 |
| C-REGION | PR mock provider | HK/JP/KR/SG/TW/unknown、查询失败、同 IP/ASN/source 集中 | 真实地区覆盖目标节点；精确生成 PRD 组名和顺序；每组成员正确；未知策略明确；IP/ASN/server/source 上限生效。 |
| C-DIAG | PR 组件测试 | 每个 selected/downgraded/dropped candidate | 公开 profile/status 与诊断共享不泄密的 diagnostic key；可查 tier/reason/history transition；凭据、server、原始错误和私有 IP 不泄露。 |
| C-PUBLISH | Ubuntu PR/merge 集成 | 生成完整 clash.yaml 后运行真实 Mihomo -t | exact Mihomo 版本/hash 被记录；所有组引用、REALITY 字段、规则加载通过；失败时 output staging 不可发布。 |
| W-CONTRACT | PR workflow contract | 解析 .github/.cnb.yml | 固定分支名、文件 allowlist、锁、trigger→pipeline 映射、四 job、timeouts、旧默认分支不被 GMGN 写入、生产 PyYAML/Mihomo 版本一致。 |
| W-RESTORE | PR shell/component | previous branch/status 不存在、暂时网络失败、坏 JSON/hash、真正首发 | 只有“明确确认分支不存在”允许首发；暂时失败不得把 previous count 退为 0；不得覆盖旧 tip。 |
| LIVE-SMOKE | 每次发布后/定时 | 防缓存下载每个公开 status/profile/results | status schema；run_at 新鲜；profile hash/count；精确组名；引用完整；GMGN 20/4；shadow source/shard/result/round totals；真实 Mihomo -t。 |
| LIVE-ROLLBACK | 受控 CNB canary | 缺片、stale source、history corruption、Mihomo invalid、push failure | 远端旧 branch SHA/content 不变；失败诊断出现且不含凭据；其他输出分支不受影响。 |
| LIVE-MULTIRUN | 至少连续 3 次独立 shadow | 同一受控节点跨轮状态变化 | 历史次数、名称、地区、迁移原因与恢复行为符合 R5/R7；公开产物可回看至少所需轮数。 |

建议门禁分层：

1. PR 必跑：U-*、C-*、W-CONTRACT，全部离线、确定性。
2. Ubuntu 合并门禁：真实 Mihomo -t，使用与 CNB 相同 Python/PyYAML/Mihomo 版本。
3. 发布后门禁：LIVE-SMOKE；若失败则标红且不得把该 tip 宣告为成功。
4. 真实 CNB 验收：先独立 canary/shadow 连续运行至少 3 次，完成 LIVE-ROLLBACK 与 LIVE-MULTIRUN 后才考虑迁移默认入口。

### Trellis package/spec 规划风险

- .trellis/config.yaml:161-165 只声明 manager，并把 manager 设为 default_package；本任务实际修改仓库根目录 Python/scripts/tests/.github/.cnb.yml。
- .trellis/spec/manager/backend/index.md:17-21 和 quality-guidelines.md:19-51 仍是 To fill 占位模板，不能提供本任务所需的 Python、unittest、GitHub Actions、CNB、发布分支和安全约束。
- 当前 PRD 已明确记录该偏差与验收要求：prd.md:18-20、103。
- 审计时任务目录尚无 design.md / implement.md；本任务显然是复杂跨层任务，而 .trellis/workflow.md:161-164、269 要求复杂任务在 start 前补齐二者。
- 规划建议：在实现前先为 aggregator 根包建立/加载真实 spec，明确生产依赖版本、测试临时目录、公开 schema、分支发布与回滚契约；不要让 implement/check agent 仅加载 manager 占位规范。

### External references

- GitHub 候选 status/profile：
  - https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/status.json
  - https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/clash.yaml
- CNB gstatic：
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-output/status.json
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-output/clash.yaml
- CNB GMGN：
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/status.json
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/clash.yaml
- CNB shadow：
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-shadow/status.json
  - https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-shadow/gmgn-shadow-results.json
- CI/runtime versions observed:
  - GitHub tests: Python 3.12, actions/checkout@v5, actions/setup-python@v6, requirements.lock（PyYAML 6.0.3）。
  - CNB: python:3.12-bookworm，工作流显式 PyYAML 6.0.2，仓库内 clash/clash-linux-amd；Mihomo 版本未在状态/测试中声明。

## Caveats / Not Found

- 本研究角色未执行单元测试套件，也未修改业务代码；结论来自测试定义、实现、工作流和只读公开输出快照。实际 green/red 结果应由后续 check 阶段在规定测试临时目录中运行确认。
- 公开快照会随下一次 force push 改变；上面的数量/hash 只代表 2026-08-11 审计时刻。
- 本机为 Windows，未执行 Linux clash-linux-amd，因此只验证了 YAML/JSON、hash、计数和引用结构，没有验证当前远端文件可被目标 Mihomo 版本加载。
- 未找到任何现有自动化测试会在 push 后读取 GitHub/CNB 公开 URL。
- 未找到多轮持久历史文件、地区/ASN 状态存储、稳定 output-name 映射或 PRD 所列 9 个最终分组的实现。
- 未找到机器可验证的 GitHub/gstatic public status schema；GMGN output/shadow 是目前唯一带 kind/schema_version 的公开状态契约。
