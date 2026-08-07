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
4. 再次向 GitHub `main` 推送提交，或在 GitHub Actions 中手动运行 `Sync GitHub main to CNB`。

请勿使用 Repository variable 保存令牌，变量不会像 Secret 一样自动脱敏。

CNB 使用中国标准时间。每天 `10:00` 和 `22:00` 仍会自动从 GitHub 同步一次，作为实时推送失败时的兜底；`10:30` 和 `22:30` 运行大陆节点实测。临时需要同步代码时，也可在 CNB `main` 分支详情页点击“立即同步 GitHub main”。

同步只允许正常的快进更新。如果有人直接修改 CNB 的 `main` 导致它与 GitHub 分叉，任务会失败而不是强制覆盖；此项目应始终在 GitHub 修改代码。节点数据本身始终从 GitHub 最新的 `clash-verge-output` 下载，不依赖代码同步时间。

探测流水线申请 2 个 CPU，同步流水线申请 1 个 CPU。按当前频率运行，月用量明显低于 CNB 社区版每月 160 CPU 核时的免费额度。

## 筛选规则

- 使用仓库自带的 Mihomo，对所有源节点发起真实代理请求，而非只做 TCP 端口探测。
- 所有节点先测 3 轮，再让全部节点补测 17 轮，总计 20 轮。以当前约 1450 个源节点计算，约需 29,000 次真实请求；任务超时上限为 50 分钟，避免低质节点大量 timeout 时被过早中断。
- 每轮单次等待 3 秒。成功率至少达到 70%（20 轮中至少成功 14 次），且成功样本的 P90 延迟不高于 2800 ms，才算合格。
- 排名依次比较成功率、P90 延迟、中位延迟、抖动和最低延迟；不会因偶尔出现一次很低的延迟就把经常 timeout 的节点排在前面。
- 基础发布目标为 80 个，优先使用成功率至少 80% 的节点；有足够合格节点时先保留最稳的 10 个非亚洲节点，再由亚洲节点填充主体。非亚洲最多 20 个，因此正常发布 80 个时亚洲节点至少有 60 个；非亚洲不足 10 个时不会为了凑数降低门槛。
- 达到 90% 成功率且 P90 不高于 2000 ms 的高质量节点可以继续扩容。扩容阶段按稳定性统一排名，非亚洲仍然最多 20 个，最终数量会在 80–150 个之间动态变化，亚洲节点没有 50 或 60 个的上限。
- 如果达不到至少 80 个合格且符合地区上限的节点，本轮拒绝覆盖，继续保留上一版订阅。
- 发布保护门槛绝对不少于 80 个；上一版发布量最高按 150 计算并乘以 50%，所以默认配置允许结果按本轮质量从 150 安全回落到 80。
- REALITY `short-id` 在 CNB 二次生成 YAML 时始终强制保留为带引号字符串，避免 `08`、`54462e21` 被 YAML 当成数值导致 Mihomo 整体启动失败。
- 格式无效、Mihomo 无法解析的节点仍会丢弃，否则会导致整份 Clash 配置无法启动。
- `status.json` 保存本次汇总；`probe-results.json` 保存每轮样本、成功率、P90、中位数、抖动、全量复测/合格/发布状态和淘汰原因。

`status.json` 还记录以下追踪信息：

- `source_run_at`：本次输入订阅在 GitHub 的生成时间。
- `source_sha256`：实际下载到的源 `clash.yaml` 的 SHA-256。
- `main_sha`：CNB 本次执行所使用的主分支提交。
- `runner_public_ip`、`runner_country`、`runner_region`、`runner_city`：第三方 IP 定位服务返回的公网出口与地区。
- `candidate_count`、`qualified_count`、`published_asia_count`、`published_non_asia_count`：全量复测和最终地区构成。
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
- `BASE_TARGET` / `MAX_NODES`：基础发布 80 个，达到精英门槛后最多动态扩容到 150 个。
- `NON_ASIA_MIN` / `NON_ASIA_MAX`：非亚洲节点软目标为 10 个、硬上限为 20 个。
- `MIN_SUCCESS`：允许覆盖旧订阅所需的绝对最少节点数，默认 80。
- `MIN_RETAIN_RATIO`：相对上一版发布量的最低保留比例，默认 0.50。

## 本地验证

流水线逻辑位于 `scripts/`，工作流不再包含大段内嵌 Python。提交前可运行：

```bash
python -m unittest discover -s tests -v
```

测试覆盖 3+17 轮采样、成功率/P90/抖动统计、亚洲优先与非亚洲 10–20 上限、动态 80–150 容量、发布门槛、代理组过滤、REALITY 字符串序列化和 TCP 探针错误分类。
