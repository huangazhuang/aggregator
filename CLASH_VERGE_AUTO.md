# Clash Verge 自动订阅

这个 fork 已经加了一个专门给 Clash Verge 使用的 workflow：`.github/workflows/clash-verge-auto.yml`。

## 订阅地址

首次运行成功后，把下面这个 URL 导入 Clash Verge：

```text
https://raw.githubusercontent.com/huangazhuang/aggregator/clash-verge-output/clash.yaml
```

Clash Verge 中进入 `Profiles`，选择从 URL 导入，粘贴上面的地址即可。建议把更新间隔设为 360 分钟或 720 分钟。

## 首次运行

1. 打开仓库的 `Actions` 页面。
2. 如果 GitHub 提示 fork 仓库的 workflows 未启用，先点击启用。
3. 选择 `Clash Verge Auto`。
4. 点击 `Run workflow`。
5. `mode` 选 `collect`，`alive_check` 选 `true`。
6. 等待运行完成后，再导入上面的订阅地址。

## 自动运行策略

- 每 6 小时自动刷新已有订阅。
- 每周一 08:47（Asia/Shanghai）自动重新收集来源。
- 每次运行都会更新 `clash-verge-output` 分支的 `last-run.txt`，用于保活 Actions 和确认最近运行时间。

## 输出分支

生成结果会发布到 `clash-verge-output` 分支：

- `clash.yaml`：Clash Verge 导入用配置。
- `subscribes.txt`：保留下次刷新用的订阅源。
- `domains.txt`：保留下次收集用的站点来源。
- `valid-domains.txt`：最近一次可用来源域名。
- `status.json`：最近一次运行状态。
- `last-run.txt`：最近一次运行时间。

## 说明

这个方案不需要 Gist，也不需要配置 `GIST_PAT` / `GIST_LINK`。原来的 `Collect`、`Refresh`、`Process` workflow 已改成只支持手动运行，避免缺少 Gist secrets 时定时报错。

如果仓库改成 private，raw.githubusercontent.com 链接无法被 Clash Verge 直接拉取。保持仓库 public，或改回 Gist 输出方案。
