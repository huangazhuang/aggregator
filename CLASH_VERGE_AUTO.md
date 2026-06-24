# Clash Verge 自动订阅

这个 fork 已经加了一个专门给 Clash Verge 使用的 workflow：`.github/workflows/clash-verge-auto.yml`。

## 订阅地址

首次运行成功后，把下面这个 URL 导入 Clash Verge：

```text
https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/clash.yaml
```

Clash Verge 中进入 `Profiles`，选择从 URL 导入，粘贴上面的地址即可。建议把更新间隔设为 360 分钟或 720 分钟。

## 推荐配置

要长期可用，建议使用你自己的稳定订阅源，而不是只依赖项目自动注册免费站点。

到仓库 `Settings` -> `Secrets and variables` -> `Actions` -> `Secrets` 添加：

- `CLASH_SUBSCRIPTIONS`：一行一个订阅 URL，可以放多个。

也可以添加：

- `CLASH_SUBSCRIPTION_URL`：一个远程文本文件 URL，文件中一行一个订阅 URL。
- `CHECKIN_CONFIG_JSON`：可选，用于机场每日签到保流量。

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
- `process.py`：同时启用爬虫聚合，默认包含 GitHub、Google、Yandex、Twitter、GitHub forks 和 v2rayse 公开分享来源。

两部分结果会合并到同一个 `clash.yaml`。`alive_check=true` 是默认值，会在 GitHub Actions runner 上用 Mihomo/Clash 测活后再发布。这个测活环境不是中国大陆电信网络，因此仍可能和你本地 Clash Verge 的连通性有差异，但它能避免明显死节点直接发布。

为提高自动注册成功率，已增加多临时邮箱服务商轮换，包括 `tempmail.lol`、`mail.tm`、`moakt`、`snapmail`、`linshiyouxiang` 等。遇到发信失败、收信超时或验证码提取失败时，会换邮箱服务商重试。

## 自动运行策略

- 每 6 小时自动刷新已有订阅。
- 每周一 08:47（Asia/Shanghai）自动重新收集来源。
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

## 说明

这个方案不需要 Gist，也不需要配置 `GIST_PAT` / `GIST_LINK`。原来的 `Collect`、`Refresh`、`Process` workflow 已改成只支持手动运行，避免缺少 Gist secrets 时定时报错。

如果仓库改成 private，raw.githubusercontent.com 链接无法被 Clash Verge 直接拉取。保持仓库 public，或改回 Gist 输出方案。
