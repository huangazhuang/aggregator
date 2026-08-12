# GMGN V2 影子验收与入口迁移设计

## 1. Rollout 状态机

```text
CODE_READY
  → MANUAL_SHADOW_ACCEPTED
  → AUTO_SHADOW_ENABLED
  → THREE_ACCEPTED_RUNS
  → MIGRATION_REPORT_READY
  → USER_APPROVED
  → GMGN_PROMOTED
  → GSTATIC_FROZEN
```

状态只能按顺序推进。代码完成不授权 live，单次 shadow 不授权正式，三次 shadow 不授权迁移；`USER_APPROVED` 必须来自迁移报告之后的新用户回复。

## 2. 证据模型

每个 live run 证据目录包含：

- before/after remote refs；
- candidate status/profile/metadata hash；
- manifest、四片和 valid-run summary；
- accepted bundle status/profile/history/node-status/run diagnostics；
- validator JSON 与固定 Mihomo 输出；
- policy/schema/runtime、`identity_epoch`、`identity_key_version` 和 binary hashes；
- 允许变化与禁止变化的 ref diff。

证据目录只位于 `D:\xiangmu\linshi\gmgn-v2-rollout\<run_id>`。公开分支仍只保存脱敏 bundle，私密 fragments 不复制到证据以外的公开位置。

## 3. 单次门禁

手动 trigger 必须显式传完整 source SHA。C5 的 `run` validator 负责 profile/metadata 绑定、20/4/900 秒、出口/canary、selection/groups/history/bundle 和 remote smoke。额外比较三个受保护分支 refs，确保只有 V2 shadow 变化。

单次通过后提交一个独立配置变更将自动模式设为 `shadow`。该变更不得同时修改 policy/schema、正式分支或文档入口，便于独立回滚。

## 4. 三次门禁

`series` validator 读取三个 accepted evidence：

- distinct source SHA；
- 相邻 accepted 时间至少 21600 秒；
- schema/policy/runtime、`identity_epoch`、`identity_key_version` 完全相同；
- 每次 valid、CAS、remote smoke 成功；
- history/name/region/cache/run index 连续一致。

invalid/retry/rejected 记录可留在时间线，但从 accepted count 排除。版本变化重置序列。history 完整轨迹由确定性 canary/replay 证明，不等待不稳定免费节点自然变化。

## 5. Exact promotion

用户批准后，publisher 读取最后 accepted V2 commit/bundle，不重新运行 probe/selection/render。将同一 branch-neutral 文件树通过 C5 CAS 流程提升到 `clash-cn-gmgn-output`；commit 元数据可因目标 ref 不同而变化，但所有 bundle payload 字节、逻辑 bundle hash 和逐文件 hash保持一致。随后用 `migration` validator 对照 V2 bundle。

文档更新只在 promotion smoke 成功后进行。推荐 URL 指向既有正式 GMGN 分支，因此 Clash Verge 用户只需刷新正确 URL；GitHub 宽候选与 gstatic legacy 地址继续列出但用途清晰。

## 6. gstatic freeze

freeze 是生命周期变更，不是数据删除：

1. 记录现有 gstatic tip/profile hash；
2. 用同一 `clash.yaml` 生成仅增加 frozen metadata/README 的 bundle；
3. 验证 profile hash未变并发布 frozen status；
4. 停止 schedule/自动 tag，保留手动入口；
5. 再次远端下载旧 URL 验证可读。

GMGN 异常时只能人工执行恢复：先把文档/入口回退到保留的 gstatic，恢复 schedule 或手动运行，再通过 remote smoke。不得自动健康探测后双向切换。

## 7. 回滚层级

- live shadow 前：只回滚代码/config，线上不变。
- manual/series：模式切回 off，V2 last-good 保留。
- promotion：用迁移前正式 GMGN tip/bundle 进行 lease 回滚，推荐文档同步回退。
- gstatic freeze：恢复 schedule/trigger，但保留 frozen 历史字段和旧 URL；不删除 GMGN bundle。
