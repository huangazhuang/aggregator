# Clash Verge 自动订阅

这个 fork 已经加了一个专门给 Clash Verge 使用的 workflow：`.github/workflows/clash-verge-auto.yml`。

## 订阅地址

首次运行成功后，把下面这个 URL 导入 Clash Verge：

```text
https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/clash.yaml
```

Clash Verge 中进入 `Profiles`，选择从 URL 导入，粘贴上面的地址即可。建议把更新间隔设为 360 分钟或 720 分钟。

如果更关心中国大陆实际可用性，当前默认仍使用 CNB 国内 Runner 以 gstatic 实测后的订阅：

```text
https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-output/clash.yaml
```

该订阅会对全部节点先测 3 轮，再全部补足到 20 轮，按成功率、P90、中位延迟和抖动筛选。80 个是优选目标而不是硬性发布数量，真实合格节点较少时可以发布 50–79 个，质量足够时最多扩展到 150 个。它继续作为当前默认和备用链接，不会被新的 GMGN 任务覆盖。详细说明见 [`CNB_SETUP.md`](CNB_SETUP.md)。

如果主要依靠 Clash Verge 手动测速、手动选节点，可另外导入独立的 GMGN 优先手测订阅：

```text
https://cnb.cool/ASD12321_446/aggregator/-/git/raw/clash-cn-gmgn-output/clash.yaml
```

GMGN 任务使用 4 个独立 Mihomo 分片、每片 16 个并发线程，总并发 64。所有节点完整测试 20 轮，每次请求最多等待 3000 ms，但只有延迟不高于 1000 ms 的轮次算达标，不会因为预检或某一轮 timeout 直接淘汰节点。亚洲核心要求至少 14/20，且前后 10 轮各至少 5 次达标；亚洲 10–13/20 单独进入弹性组。非亚洲先保留最多 10 个至少 16/20 的节点，额外名额只给至少 18/20 的节点，总量最多 20 个。

该订阅不强凑 80 个，总上限为 150 个；第一轮真实数据预计只有约 20–22 个达到当前规则。上一轮亚洲核心本轮降到 12–13 次时可以迟滞保留一个周期，少于 10 次不保留。若本轮总数低于 `max(10, 上一版数量 × 40%)`，任务拒绝覆盖旧 GMGN 订阅。

配置提供 `手动选择`、`GMGN稳定`、`亚洲弹性`、`GMGN观察保留` 和 `GMGN自动` 分组。对习惯手动使用的用户，直接在 `手动选择` 中刷新本机延迟后选择即可，默认入口优先指向 `GMGN稳定`；`亚洲弹性` 收纳本轮 10–13/20 的亚洲候选，`GMGN观察保留` 单独标出只获得一次迟滞机会的旧核心节点，自动组可以不用。

仓库仍会把 GMGN 的脱敏统计发布到 `clash-cn-gmgn-shadow`，用于检查逐轮趋势、容量和四分片性能；影子报告不是 Clash 订阅，也不会泄露节点配置。现有 `clash-cn-output` 会继续沿用 gstatic 20 轮逻辑，至少连续观察 2–3 轮 GMGN 结果并与 Clash Verge 本机手测对比后，再决定是否替换默认链接。

## 推荐配置

要长期可用，建议使用你自己的稳定订阅源，而不是只依赖项目自动注册免费站点。

到仓库 `Settings` -> `Secrets and variables` -> `Actions` -> `Secrets` 添加：

- `CLASH_SUBSCRIPTIONS`：一行一个订阅 URL，可以放多个。

也可以添加：

- `CLASH_SUBSCRIPTION_URL`：一个远程文本文件 URL，文件中一行一个订阅 URL。
- `CHECKIN_CONFIG_JSON`：可选，用于机场每日签到保流量。

如果准备开启实验性的 GitHub Candidate V2，还必须新增 Repository secret
`CANDIDATE_HANDOFF_AES_KEY`。它必须是**随机 32 字节密钥的标准 Base64 编码**；
例如可在可信本机生成后直接粘贴输出（不要把输出提交到仓库）：

```bash
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

该密钥只用于把收集 job 产生的完整候选身份输入加密后交给独立 identity
job。Actions artifact 只保存 AES-256-GCM 认证密文，不保存完整 proxy、hostname、
port、凭据、裸 fingerprint 或 previous profile。密钥缺失、Base64 无效、长度不是
32 字节，或密文/运行上下文认证失败时，Candidate V2 会失败关闭并保留上一版输出。
Candidate V2 关闭时不需要配置此密钥。它与 `GMGN_IDENTITY_HMAC_KEY` 用途不同，
不得复用；后者仍只负责生成稳定的公开身份 ID。

订阅 URL 只能保存在 `Secrets` 中，不要使用 `Variables`。GitHub 会自动遮盖 Secret，普通变量则可能在 Actions 日志中显示明文。

`CHECKIN_CONFIG_JSON` 示例：

```json
{
  "domains": [
    {
      "domain": "https://example.com",
      "param": {
        "email": "name@example.com",
        "passwd": "password",
        "login": "/auth/login",
        "checkin": "/user/checkin"
      }
    }
  ]
}
```

## 首次运行

1. 打开仓库的 `Actions` 页面。
2. 如果 GitHub 提示 fork 仓库的 workflows 未启用，先点击启用。
3. 选择 `Clash Verge Auto`。
4. 点击 `Run workflow`。
5. 没有配置 `CLASH_SUBSCRIPTIONS` 时，`mode` 选 `collect`，`alive_check` 选 `true`。
6. 等待运行完成后，再导入上面的订阅地址。

## 默认运行模式

没有配置 `CLASH_SUBSCRIPTIONS` 时，`Clash Verge Auto` 会使用双模式：

- `collect.py`：从原项目所有机场来源收集候选站点，自动注册、购买免费套餐并提取订阅。
- `process.py`：同时启用爬虫聚合，默认包含 GitHub、Google、DuckDuckGo、Yahoo、Twitter、Telegram 和 GitHub forks 等公开来源。

两部分结果会合并到同一个 `clash.yaml`。`alive_check=true` 是默认值，会在 GitHub Actions runner 上用 Mihomo/Clash 测活。最终发布前还会强制检查 GMGN、Google 和 YouTube；普通节点只有同时通过三个目标才会进入严格版，香港、台湾、新加坡、日本、韩国节点跳过连通性筛选并始终保留。格式无效、Mihomo 无法解析的配置仍会丢弃，否则会导致整份订阅无法加载。

亚洲节点还会从 9 个专用任务补充：`Au1rxx/free-vpn-subscriptions` 的香港、台湾、新加坡、日本、韩国分类源，以及 `multi-proxy-config-fetcher`、`ovmvo/FreeSub`、`daily_free_vpn`、`FreeSubsCheck` 中名称能识别出目标地区的节点。原有全球来源仍然保留，因此输出不是“只有亚洲节点”。

严格筛选采用失败关闭策略：任一目标检测异常，或最终通过数少于 20，或少于上一版的 25% 时，本次任务停止发布，`clash-verge-output` 保持上一版。可通过仓库变量 `STRICT_MIN_NODES` 和 `STRICT_MIN_RETAIN_RATIO` 调整门槛。

可选的阿里云 FC TCP 探针现在会检查 SS、SSR、Snell、HTTP、SOCKS5 等 TCP 协议，只跳过 TUIC、Hysteria 和 Hysteria2。连接被拒绝或重置说明链路已到达目标，按入口可达处理；超时、DNS、无路由和未知系统错误按不可达处理。部署方法见 [`probe/README.md`](probe/README.md)。

为提高自动注册成功率，已增加多临时邮箱服务商轮换，包括 `tempmail.lol`、`mail.tm`、`moakt`、`snapmail`、`linshiyouxiang` 等。遇到发信失败、收信超时或验证码提取失败时，会换邮箱服务商重试。

## 自动运行策略

- 每天 02:17、14:17、20:17（Asia/Shanghai）刷新已有订阅。
- 每天 08:17（Asia/Shanghai）重新收集来源。
- 每天 10:45（Asia/Shanghai）自动执行签到；只有配置 `CHECKIN_CONFIG_JSON` 时才会实际签到。
- 每次运行都会更新 `clash-verge-output` 分支的 `last-run.txt`，用于保活 Actions 和确认最近运行时间。
- 没有 `CLASH_SUBSCRIPTIONS` 时，会按双模式尽可能多收集来源；这个方式不保证每次都有可用节点，且耗时可能很长。

## 输出分支

生成结果会发布到 `clash-verge-output` 分支：

- `clash.yaml`：Clash Verge 导入用配置。
- `subscribes.txt`：保留下次刷新用的订阅源。
- `domains.txt`：保留下次收集用的站点来源。
- `valid-domains.txt`：最近一次可用来源域名。
- `crawler-*.txt/json/yaml`：爬虫模式的中间结果，用于下次运行复用。
- `status.json`：最近一次运行状态。
- `last-run.txt`：最近一次运行时间。

工作流中的配置生成、合并、探针过滤、严格筛选和发布元数据逻辑均位于 `scripts/`，并在每次运行开始时执行 `tests/` 中的单元测试。

## 说明

这个方案不需要 Gist，也不需要配置 `GIST_PAT` / `GIST_LINK`。原来的 `Collect`、`Refresh`、`Process` workflow 已改成只支持手动运行，避免缺少 Gist secrets 时定时报错。

如果仓库改成 private，raw.githubusercontent.com 链接无法被 Clash Verge 直接拉取。保持仓库 public，或改回 Gist 输出方案。
