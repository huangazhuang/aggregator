# CNB 中国大陆节点实测

这套流水线不会修改现有的 `clash-verge-output`。它从该分支读取完整订阅，在 CNB 云端用 Mihomo 对每个节点做两阶段、总计 20 轮的协议级实测，再按成功率、P90 延迟、中位延迟和抖动筛出稳定节点，发布到 CNB 仓库的 `clash-cn-output` 分支。最终结果以亚洲节点为主，非亚洲节点只保留最稳定的一小部分。

仓库中历史遗留的 `manager` 子模块默认设置为不更新；它不参与当前聚合或测速流程，避免 CNB 因无法连接 GitHub 子模块而在任务准备阶段失败。

## 一次性开通

1. 登录 [CNB](https://cnb.cool/)，新建组织并选择“导入外部仓库”。
2. 导入 `https://github.com/huangazhuang/aggregator`，仓库可见性选“公开”。只有公开仓库的原始文件地址才能直接作为 Clash Verge 订阅。
3. 打开 CNB 仓库的 `main` 分支详情页，点击“立即筛选中国可用节点”。首次运行不需要配置任何密钥，流水线使用仅在本次构建期间有效的 `CNB_TOKEN` 发布结果。
4. 构建成功后，日志末尾会显示 `Subscription URL`。将它添加到 Clash Verge 即可。

订阅地址格式如下：

```text
https://cnb.cool/<你的组织>/<仓库>/-/git/raw/clash-cn-output/clash.yaml
```

## 自动运行

配置 `CNB_MIRROR_TOKEN` 后，GitHub `main` 每次收到新提交都会运行 `Sync GitHub main to CNB`，通常会在几十秒到几分钟内将同一提交快进推送到 CNB。

启用近实时同步只需操作一次：

1. 在 CNB 创建一个具有当前仓库 Git 写入权限的新访问令牌。
2. 打开 GitHub 仓库的 `Settings > Secrets and variables > Actions`。
3. 新建 Repository secret，名称填写 `CNB_MIRROR_TOKEN`，值填写刚创建的 CNB 令牌。
4. 再次向 GitHub `main` 推送提交，或在 GitHub Actions 中手动运行 `Sync GitHub main to CNB`。手动运行时必须在分支选择器中选 `main`；工作流也会硬性拒绝其他分支。把 `trigger_probe` 设为 `true`，会先确认 CNB `main` 已同步到同一提交，再向 CNB 单独推送一个唯一的 `cnb-probe-*` 标签，由受信任的 `tag_push` 事件启动同一套大陆探测。若只想运行不会改动订阅的 GMGN 影子测速，则把 `trigger_gmgn_shadow` 设为 `true`；它会推送独立的 `cnb-gmgn-shadow-*` 标签。标签只存在于 CNB、用于追踪手动运行，不会写入 GitHub；令牌只从 GitHub Secret 注入，不写入日志。

请勿使用 Repository variable 保存令牌，变量不会像 Secret 一样自动脱敏。

CNB 使用中国标准时间。每天 `10:00` 和 `22:00` 仍会自动从 GitHub 同步一次，作为实时推送失败时的兜底；`11:10` 和 `23:10` 运行大陆节点实测。测速时间刻意晚于 GitHub 源订阅刷新；开跑前会用同一防缓存标识下载 GitHub `status.json` 和 `clash.yaml`，要求生成时间不超过 5 小时且 SHA-256 完全匹配，再把这份已校验快照固定到本次运行目录，最多等待 20 分钟。若 GitHub 严重排队、刷新失败或两份文件尚未同步，CNB 会在耗费约 26 分钟测速前直接失败并保留旧订阅，而不是继续测试上一轮快照。临时需要同步代码时，也可在 CNB `main` 分支详情页点击“立即同步 GitHub main”。

大陆测速流水线配置了独占锁 `aggregator-mainland-probe`：定时任务和手动点击触发的任务不会并行运行，也不会同时强制推送 `clash-cn-output`。等待或锁租约最长为 2 小时，足以覆盖当前约 30–40 分钟的全量 20 轮测速和失败诊断发布。若前一次任务异常终止，租约到期后才会允许下一次任务接管；不应通过重复点击来绕过锁。

同步只允许正常的快进更新。如果有人直接修改 CNB 的 `main` 导致它与 GitHub 分叉，任务会失败而不是强制覆盖；此项目应始终在 GitHub 修改代码。节点数据本身始终从 GitHub 最新的 `clash-verge-output` 下载，不依赖代码同步时间。

正式探测流水线申请 2 个 CPU，同步流水线申请 1 个 CPU。手动 GMGN 影子测速申请 4 个 CPU，但当前不设定时任务，只在校准和性能调优时运行。按当前频率运行，月用量仍应明显低于 CNB 社区版每月 160 CPU 核时的免费额度。

## GMGN 影子测速校准

在把正式选拔目标从 gstatic 切换到 GMGN 之前，仓库提供一套完全隔离的影子任务：

- 测速目标为 `https://gmgn.ai/`，期望 HTTP 200；
- Mihomo 每轮最多等待 3000 ms，以区分“1001–3000 ms 有响应但太慢”和“无结果”；
- 每个节点测试 20 轮，只有延迟不高于 1000 ms 的轮次才记为 Clash 对齐达标；
- 同一 CNB Runner 内启动 4 个独立 Mihomo 分片，每片 16 个并发线程，总并发 64。节点之间并行，同一节点的 20 轮仍保持顺序；
- 4 个分片必须全部完成、源 SHA 和规则参数完全一致，才会原子生成报告；缺少任意分片都会失败，不发布半份数据；
- 每轮结束都会复查 Mihomo 进程和控制器健康；基础设施中途退出不会伪装成一批节点超时。合并时还会逐项核对节点计数、轮次计数、错误计数与脱敏字段；
- 任务会等待最多 20 分钟获取带 SHA 校验的 GitHub 快照，并接受最近 10 小时内的输出，以覆盖 6 小时刷新周期和较长的收集任务；更旧或哈希不一致的源仍会拒绝；
- 4×16 布局按全超时估算可覆盖约 5000 个候选。超过单 Runner 的 110 分钟安全预算时会在测速前明确失败，届时再增加分片或拆分仓库，而不是跑到最后才超时；
- 结果发布到独立的 `clash-cn-gmgn-shadow` 分支。该分支不是 Clash 订阅，也不会写入或覆盖 `clash-cn-output`。

手动运行方式：打开 GitHub Actions 的 `Sync GitHub main to CNB`，将 `trigger_gmgn_shadow` 设为 `true`。报告地址：

```text
https://cnb.cool/<你的组织>/<仓库>/-/git/raw/clash-cn-gmgn-shadow/status.json
https://cnb.cool/<你的组织>/<仓库>/-/git/raw/clash-cn-gmgn-shadow/gmgn-shadow-results.json
```

`status.json` 保存 20/18/16/14/12/10 轮在 1000 ms 内达标的亚洲/非亚洲候选数量、逐轮总体趋势、分片耗时和尽力分类的错误数量。第一轮的亚洲口径仍来自源名称/标记，只用于观察大致分布，并不等同于真实出口地区；正式切换前还要补出口地区验证。`gmgn-shadow-results.json` 另含逐节点脱敏汇总，但不会发布名称、server、port、UUID、密码、原始错误、逐轮样本或 Runner 公网 IP；匿名 ID 每次运行重新生成，不能跨运行追踪。

第一轮影子数据只用于确认 GMGN 实际分布、是否存在后半程整体成功率下降以及合适的正式门槛。在完成分析前，正式 `clash-cn-output` 继续使用现有 gstatic 20 轮逻辑。

## 筛选规则

- 使用仓库自带的 Mihomo，对所有源节点发起真实代理请求，而非只做 TCP 端口探测。
- 所有节点先测 3 轮，再让全部节点补测 17 轮，总计 20 轮。以当前约 1450 个源节点计算，约需 29,000 次真实请求；任务超时上限为 50 分钟，避免低质节点大量 timeout 时被过早中断。
- 旧版 CNB 任务可能仍携带 `candidate-limit`、`asia-candidate-target` 等参数；当前脚本会兼容接收但忽略这些候选上限，始终对源中的全部节点完成 20 轮，直到 CNB main 同步到最新提交。
- 每轮单次等待 3 秒。成功率至少达到 70%（20 轮中至少成功 14 次），且成功样本的 P90 延迟不高于 2800 ms，才算合格。
- 排名依次比较成功率、P90 延迟、中位延迟、抖动和最低延迟；不会因偶尔出现一次很低的延迟就把经常 timeout 的节点排在前面。
- 优选目标为 80 个，先保留最稳的 10 个非亚洲节点，再由亚洲节点填充主体。非亚洲的硬合格线仍是 14/20 且 P90 不高于 2800 ms，最多 20 个。
- 亚洲采用三级基础填充：严格层为 14/20；基础兜底层为 12/20；仍未达到 80 个优选目标时才启用应急兜底层 10/20。两级兜底仍要求 P90 不高于 2800 ms，只用于向 80 个目标补齐，不能用于超过 80 的扩容；不会为了凑数继续降低质量线。
- 达到 90% 成功率且 P90 不高于 2000 ms 的高质量节点可以继续扩容。若存在尚未选中的精英亚洲节点，会优先用于替换基础配置中的较弱亚洲兜底；随后只有精英节点可以新增名额，兜底节点自身永远不能把配置扩到 80 以上。最终数量会按真实质量在 50–150 个之间动态变化，非亚洲仍然最多 20 个。
- 如果合格且符合地区上限的节点少于动态 `required_count`（默认 50），本轮拒绝覆盖，继续保留上一版订阅；达到 50–79 个时则发布全部真实合格节点。
- 发布保护门槛取绝对下限 50 与保留比例计算值中的较大者；上一版发布量最高只按基础目标 80 计算并乘以 50%，所以曾经扩容到 150 也不会把下一轮硬门槛抬到 75。
- REALITY `short-id` 在 CNB 二次生成 YAML 时始终强制保留为带引号字符串，避免 `08`、`54462e21` 被 YAML 当成数值导致 Mihomo 整体启动失败。
- 格式无效、Mihomo 无法解析的节点仍会丢弃，否则会导致整份 Clash 配置无法启动。
- `status.json` 保存本次汇总；`probe-results.json` 保存每轮样本、成功率、P90、中位数、抖动、全量复测/合格/发布状态和淘汰原因。

### 失败诊断与保留策略

测速阶段失败时，CNB 会跳过正常发布阶段；这是故意的 fail-closed 行为，最后一版可用的 `clash-cn-output/clash.yaml` 不会被覆盖。筛选程序会在 `public-cn/failure.json` 写入脱敏的失败汇总，并在构建日志中打印亚洲 10/12/14 次成功门槛的 what-if 矩阵，便于判断下一轮是否仍需增加源节点。

CNB 的 `failStages` 会在本次流水线失败后把最新脱敏报告写入与订阅分离的 `clash-cn-diagnostics` 分支；如果测速在生成汇总前就中止，失败阶段只打印提示，不会影响原始失败状态：

- `failure.json`：小型失败摘要，包含失败类型、主分支/源 SHA、required/selected 数量、旧 profile 基线、0–20 次成功直方图、10/12/14/18 次门槛模拟，以及回放文件引用；
- `redacted-probe-results.json`：逐节点记录只包含每轮随机匿名 ID、亚洲标记、完成轮数、成功次数、成功率、最低/P90/中位延迟、抖动和质量层标记；文件顶层另含随机运行 ID、策略参数、主分支/源 SHA 及脱敏说明，供回放时校验两份文件属于同一轮；
- 诊断分支不复制节点名、运行时 YAML、UUID、password、server、port、原始错误文本或逐轮样本。

诊断地址格式：

```text
https://cnb.cool/<你的组织>/<仓库>/-/git/raw/clash-cn-diagnostics/failure.json
https://cnb.cool/<你的组织>/<仓库>/-/git/raw/clash-cn-diagnostics/redacted-probe-results.json
```

失败诊断不得复制含 UUID、password 或其他凭据的运行时 YAML。逐节点匿名 ID 每轮随机生成，无法用公开源订阅枚举反查，也不能跨轮追踪；诊断不保存 server、port 或原始错误文本。诊断发布失败不能覆盖或删除最后一版订阅，也不能把失败尝试的数量写成 `published_count`。

`status.json` 还记录以下追踪信息：

- `source_run_at`：本次输入订阅在 GitHub 的生成时间。
- `source_sha256`：实际下载到的源 `clash.yaml` 的 SHA-256。
- `main_sha`：CNB 本次执行所使用的主分支提交。
- `runner_public_ip`、`runner_country`、`runner_region`、`runner_city`：第三方 IP 定位服务返回的公网出口与地区。
- `candidate_count`、`qualified_count`、`published_asia_count`、`published_non_asia_count`：全量复测和最终地区构成。
- `strict_qualified_count`、`asia_fallback_count`、`asia_emergency_count`、`qualification_tier_counts`：各质量层数量。
- `asia_threshold_matrix`、`asia_success_histogram`、`non_asia_success_histogram`：亚洲分级门槛和成功次数分布。
- `required_count`、`previous_publish_baseline`：本轮覆盖门槛及兼容旧版状态后的计算基线。

公网出口和地区是尽力查询的观测信息；定位服务不可用时会留空，不影响节点探测。CNB 共享 Runner 的出口可能调整，最终仍应以 Clash Verge 的实际可用率为准。

## 调整参数

可直接修改根目录 `.cnb.yml`：

- `TIMEOUT_MS`：每一轮测速的超时，默认 3000 毫秒。不建议直接改成 1000，否则容易误删可用但首连较慢的免费节点。
- `TARGET_URL` / `EXPECTED_STATUS`：测速目标及预期 HTTP 状态码，默认使用返回 204 的 Google 静态地址。
- `PRELIMINARY_ROUNDS` / `TOTAL_ROUNDS`：全量初筛 3 轮、全量总计 20 轮。
- `MIN_SUCCESS_RATE`：硬合格线，默认 0.70；`BASE_PREFERRED_SUCCESS_RATE` 默认 0.80。
- `ELITE_MIN_SUCCESS_RATE`：允许从基础 80 个继续扩容到 150 的高质量成功率门槛，默认 0.90。
- `MAX_QUALIFIED_P90_MS` / `ELITE_MAX_P90_MS`：普通合格和高质量扩容的 P90 上限，默认 2800 / 2000 ms。
- `BASE_TARGET` / `MAX_NODES`：优选目标为 80 个，达到精英门槛后最多动态扩容到 150 个；当真实合格节点不足 80 时不会为了凑数而降低质量线。
- `NON_ASIA_MIN` / `NON_ASIA_MAX`：非亚洲节点软目标为 10 个、硬上限为 20 个。
- `ASIA_FALLBACK_MIN_SUCCESS` / `ASIA_EMERGENCY_MIN_SUCCESS`：亚洲基础/应急兜底成功次数，默认 12/10（20 轮）。
- `ASIA_EMERGENCY_MAX_P90_MS`：亚洲应急兜底 P90 上限，默认 2800 ms；`ASIA_EMERGENCY_MAX_COUNT=0` 表示只取达到基础目标所需的数量。
- `MIN_SUCCESS`：允许覆盖旧订阅所需的绝对最少节点数，默认 50。它只控制安全发布下限，与 80 个优选目标解耦，因此可发布 50–79 个真实合格节点。
- `MIN_RETAIN_RATIO`：相对上一版基础目标内节点数的最低保留比例，默认 0.50；超过 80 的精英扩容不会抬高下一轮硬门槛。

## 本地验证

流水线逻辑位于 `scripts/`，工作流不再包含大段内嵌 Python。提交前可运行：

```bash
python -m unittest discover -s tests -v
```

拿到一次失败运行产生的两个诊断文件后，可以不再重复执行 20 轮网络测速，直接在本地回放生产选择器并覆盖参数：

```bash
python -m scripts.cnb_policy_replay redacted-probe-results.json
python -m scripts.cnb_policy_replay failure.json --json
python -m scripts.cnb_policy_replay redacted-probe-results.json \
  --fallback-min-success 11 \
  --emergency-min-success 8
```

回放命令不会恢复或输出节点配置，只报告合格/选中数量、亚洲/非亚洲构成、各 Tier 数量和发布门槛失败原因。

测试覆盖 3+17 轮采样、成功率/P90/抖动统计、生产使用的 `asia_tiering=True` 分级路径、亚洲优先与非亚洲 10–20 上限、80 个优选目标与动态 50–150 发布容量、脱敏回放、发布门槛、代理组过滤、REALITY 字符串序列化和 TCP 探针错误分类。
