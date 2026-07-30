# CNB 中国大陆节点实测

这套流水线不会修改现有的 `clash-verge-output`。它从该分支读取完整订阅，在 CNB 云端用 Mihomo 逐个进行协议级请求，并把所有实测通过的独立入口发布到 CNB 仓库的 `clash-cn-output` 分支。

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

- 使用仓库自带的 Mihomo，对所有候选节点发起真实代理请求，而非只做 TCP 端口探测。
- 单次等待 3 秒，失败节点再试一次，降低网络抖动造成的误杀。
- 按实测延迟排序，发布通过节点中最快的前 80 个；不足 80 个时发布全部通过节点。
- 覆盖门槛默认为 20 个，且不能低于上一版发布量的 25%，两者取较大值；未达到时任务失败并保留上一版。
- REALITY `short-id` 在 CNB 二次生成 YAML 时始终强制保留为带引号字符串，避免 `08`、`54462e21` 被 YAML 当成数值导致 Mihomo 整体启动失败。
- `status.json` 保存本次汇总，`probe-results.json` 保存每个节点的成功状态和延迟，便于排查。

`status.json` 还记录以下追踪信息：

- `source_run_at`：本次输入订阅在 GitHub 的生成时间。
- `source_sha256`：实际下载到的源 `clash.yaml` 的 SHA-256。
- `main_sha`：CNB 本次执行所使用的主分支提交。
- `runner_public_ip`、`runner_country`、`runner_region`、`runner_city`：第三方 IP 定位服务返回的公网出口与地区。
- `required_count`、`previous_published_count`：本轮覆盖门槛及其计算基线。

公网出口和地区是尽力查询的观测信息；定位服务不可用时会留空，不影响节点探测。CNB 共享 Runner 的出口可能调整，最终仍应以 Clash Verge 的实际可用率为准。

## 调整参数

可直接修改根目录 `.cnb.yml`：

- `TIMEOUT_MS`：云端初筛超时，默认 3000 毫秒。不建议直接改成 1000，否则容易误删可用但首连较慢的免费节点。
- `TARGET_URL`：测速目标，默认使用返回 204 的 Google 静态地址。
- `MIN_SUCCESS`：允许覆盖旧订阅所需的绝对最少成功节点数，默认 20。
- `MIN_RETAIN_RATIO`：相对上一版发布量的最低保留比例，默认 0.25。

## 本地验证

流水线逻辑位于 `scripts/`，工作流不再包含大段内嵌 Python。提交前可运行：

```bash
python -m unittest discover -s tests -v
```

测试覆盖动态门槛、代理组过滤、REALITY 字符串序列化和 TCP 探针错误分类。
