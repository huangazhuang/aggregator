# CNB 中国大陆节点实测

这套流水线不会修改现有的 `clash-verge-output`。它从该分支读取完整订阅，在 CNB 云端用 Mihomo 逐个进行协议级请求，最后把延迟最低的最多 80 个独立入口发布到 CNB 仓库的 `clash-cn-output` 分支。

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

CNB 使用中国标准时间。当前配置每天 `10:30` 和 `22:30` 各运行一次，避开 GitHub 上游订阅的生成时段。流水线申请 2 个 CPU；即使每次运行 5 分钟，每月也只消耗约 10 CPU 核时，明显低于 CNB 社区版每月 160 CPU 核时的免费额度。

## 筛选规则

- 使用仓库自带的 Mihomo，对所有候选节点发起真实代理请求，而非只做 TCP 端口探测。
- 单次等待 3 秒，失败节点再试一次，降低网络抖动造成的误杀。
- 按实测延迟排序，最多发布 80 个；上游聚合阶段已经做过凭据级去重。
- 少于 5 个节点通过时任务直接失败，不覆盖上一次可用订阅。
- `status.json` 保存本次汇总，`probe-results.json` 保存每个节点的成功状态和延迟，便于排查。

第一次运行后请在 `status.json` 中检查 `runner_ip`。CNB 是国内平台，但共享 Runner 的具体出口可能调整；最终应以 Clash Verge 的实际可用率为准。

## 调整参数

可直接修改根目录 `.cnb.yml`：

- `MAX_NODES`：发布节点上限，默认 80。
- `TIMEOUT_MS`：云端初筛超时，默认 3000 毫秒。不建议直接改成 1000，否则容易误删可用但首连较慢的免费节点。
- `TARGET_URL`：测速目标，默认使用返回 204 的 Google 静态地址。
- `MIN_SUCCESS`：允许覆盖旧订阅所需的最少成功节点数，默认 5。
