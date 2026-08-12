# GMGN V2 规划冲突收敛记录

本文件只记录研究提案之间的冲突如何在父任务正式规划中收敛。实施时的权威顺序为：父/子任务 `prd.md`、`design.md`、`implement.md` 高于 `research/*.md`；研究文件用于证据和备选方案，不得覆盖已冻结契约。

## 已冻结决定

- 候选快照使用 `clash.yaml + status.json + candidate-metadata.json`。本轮不新增包含重复代理载荷的 `candidates.jsonl`；CNB 通过 profile hash 将 Clash 配置与 metadata 绑定。
- 私有 canonical fingerprint 与公开身份分离。C3 是 fingerprint/HMAC identity 模块唯一实现 owner；公开 candidate/endpoint/server/exit ID 使用带域前缀、`identity_key_version` 和 `identity_epoch` 的 HMAC。
- C1、C2、C3 可以并行启动，但 C1 的最终 metadata 联调依赖 C3 冻结 identity API；C1 不另写第二套 fingerprint。
- `accepted` 与 `bad_countable` 分离：21600 秒只限制零响应坏 streak 增加；新 accepted valid run 有响应时立即清零恢复，间隔不足的新 SHA 仍推进 history 顶层 run/source。
- key/epoch 轮换使用 legacy tombstone：快照外 tombstone 保留旧 ID/epoch 与名称占用，旧 key 在 legacy 存在时不退役；初始保留期 90 天，GC 必须可审计。
- 20 轮初始最短逐节点观察窗口统一为版本化的 900 秒。研究提案中的 600 秒、1200 秒均不再是 MVP 默认值；后续只能依据影子基准通过策略版本显式调整。
- V2 代码和影子验收只写 `clash-cn-gmgn-v2-shadow`。现有 `clash-cn-gmgn-output` 与 gstatic `clash-cn-output` 在用户批准迁移前保持不变。
- V2 shadow 的 profile、status、`history.json` 和 current diagnostics 必须处于同一 bundle/提交并共享 `run_id`、source SHA 和 bundle hash。拒绝运行不能覆盖 last-good。
- 发布顺序为本地完整构建与 Mihomo 校验、staging ref、防缓存远端 smoke、CAS/lease 提升 current、提升后再次回读。连续三次有效影子后，正式迁移提升同一个已验收 bundle，不重新测速或选择。
- 亚洲核心为 `>=14/20` 且前后十轮各至少 5 次，亚洲弹性为 `10–13/20`；新亚洲节点只要本轮至少一次响应即可进入仅手动候补。历史亚洲候补连续三次可计数有效零响应才移除。
- 非亚洲最多 20 个且使用严格门槛；80 是期望容量，150 是总硬上限，不为凑数降标。亚洲候补在未超过 150 时不因 IP/ASN/来源集中而硬删除。
- 输出包含手动优先、HK/JP/KR/SG/TW、亚洲候补、非亚洲稳定、全部入选；辅助自动组只含严格稳定层。
- gstatic 仅作为 rollout 回退对照。连续三次有效 V2 影子通过并经用户确认迁移后停止自动更新，但保留冻结分支、URL、最后 bundle 与受控恢复入口。
