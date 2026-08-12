# GMGN 事务发布触发与远端校验设计

## 1. 发布状态机

```text
trigger(source_sha)
  → idempotency/lock
  → load + validate previous tip/bundle/history
  → consume valid C1–C4 outputs
  → build immutable local bundle
  → local schema/hash/group/Mihomo validation
  → push exact candidate commit to staging ref
  → no-cache remote smoke on staging commit
  → CAS/lease promote V2 shadow
  → no-cache smoke on authoritative ref
  → mark source SHA processed + accepted
```

任何步骤失败都不进入后续 success transition。history、accepted run index 和 processed-source success 必须随 authoritative bundle 同一事务生效，不能在 smoke 前单独写入。

## 2. Bundle 契约

建议新增单一 `publish-bundle` manifest，列出所有公开文件的相对路径、最终 SHA-256、schema 和公开 allowlist 版本。

逻辑 `bundle_hash` 的非递归算法固定为：

1. 排除 `bundle.json`，按相对路径排序全部 payload；
2. JSON payload 移除顶层 `bundle_hash` 后使用 canonical JSON，`clash.yaml` 使用精确字节；
3. 对 `path + NUL + content` 序列计算 SHA-256；
4. 将结果写入各 JSON 的 `bundle_hash`；
5. 最后生成 `bundle.json`，记录逻辑 hash 和每个最终 payload 文件的精确 hash。`bundle.json` 自身由 remote commit/tip 固定，不进入逻辑 hash。

validator 必须重算逻辑 hash、逐文件 hash 和 remote commit 关联。这样各状态文件共享同一 bundle hash，同时不存在 status/manifest 自引用。

目录结构：

```text
clash.yaml
status.json
history.json
node-status.json
bundle.json
runs/index.json
runs/<run_id>/diagnostics.json
```

`runs/index.json` 保存最近 5 个 accepted run 的 run ID、source SHA、bundle ID、时间和 diagnostics hash。公开 diagnostics 只记录聚合结果和 opaque ID；完整 fragments 始终留在 `.cnb-runtime` 私密目录。

公开 `history.json` 与 `node-status.json` 只使用 C3 的 HMAC `candidate_id`/`exit_id`。裸 canonical fingerprint、真实出口 IP 和原始地区 cache 不属于 publish bundle；若状态 reducer 需要它们，只能从受控私密状态读取。

所有 bundle payload 必须 branch-neutral：不写 shadow/formal、branch、订阅绝对 URL 或 promotion time。rollout 提升的是同一文件树；渠道和推荐入口由远端 ref 与文档表达。

## 3. Staging 与 CAS

使用固定、非用户入口 staging ref 保存待验证 commit。publisher 先读取 authoritative shadow observed tip，然后：

1. 推送新 commit 到 staging ref；
2. 按 exact staging commit URL 远端校验；
3. 用 observed shadow tip 做 `force-with-lease` 提升；
4. 读取 authoritative ref tip 并再次 smoke；
5. post-promotion smoke 失败时，用当前 tip 作为 lease 推回本地已获取的 previous commit。

staging ref 不是订阅入口，不能出现在用户文档。CAS 冲突视为存在更晚 publisher，本轮直接终止，不循环裸强推。

## 4. 幂等触发模型

完整 `profile_sha256` 是 trigger/lock/processed registry 的主键。状态至少区分 `queued`、`running`、`failed_infrastructure`、`accepted`：

- `accepted`、`running`、`queued` 的重复事件 no-op；
- `failed_infrastructure` 允许显式 retry，生成新 run ID 但保留 `retry_of` 和同一 source SHA；
- selection rejected 或 valid-run=false 不标记 accepted，也不推进 history；
- source SHA 相同的 retry 永远不产生第二次 history transition。

GitHub tag 是第一层去重，CNB registry/authoritative status 是第二层，lease 是最终并发保护。

## 5. Validator

`scripts.validate_public_outputs` 作为共享 owner：

- `run`: 验证一个 candidate snapshot 与一个 V2 bundle；
- `series`: 验证多次 accepted bundle 的 distinct SHA、间隔、版本稳定和 history canary；
- `migration`: 验证正式 GMGN 等于已验收 bundle且 gstatic 已冻结。

HTTP fetcher 注入 nonce/header，区分明确 404、暂时网络失败和内容错误。所有下载写入调用者指定的 `D:\xiangmu\linshi` 证据目录；单元测试使用本地 HTTP server 和 mock，不依赖真实网络。

## 6. Workflow 边界

- `.cnb.yml` 是 CNB V2 最终 owner，只负责阶段编排、环境、锁、端口和调用 Python 模块。
- C2 拥有 network-guard policy/launcher/self-test；C5 在 `.cnb.yml` 中拥有隔离原语与调用顺序。每片必须先验证 guard backend、固定 DNS 映射和私网/metadata deny self-test，再启动 Mihomo。无法建立隔离时整轮失败关闭，不允许退化为仅字符串/IP 预检。
- `.github/workflows/clash-verge-auto.yml` 由 C1 完成候选发布，C5 只在尾段接幂等 trigger。
- `.github/workflows/sync-cnb.yml` 暴露手动 source SHA 输入并同步/触发 CNB；代码门禁默认自动模式 off。
- `.github/workflows/tests.yml` 增加 workflow contract、transaction 和 validator 测试，但不获得写权限。

## 7. 失败与回滚

- local/staging 失败：authoritative shadow 不变。
- lease conflict：认为有更新 publisher，保留远端 current 并退出。
- post-promotion smoke 失败：尝试 lease 恢复 previous；无论恢复是否成功都保持任务失败并保存脱敏证据。
- 自动 trigger 异常：切回 manual/off，不影响既有 V2 last-good。
- 本子任务永不改旧 gstatic、现有正式 GMGN 或推荐入口，因此上线前回滚只需关闭 V2 触发。
