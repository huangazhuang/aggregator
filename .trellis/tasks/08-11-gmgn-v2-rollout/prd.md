# GMGN V2 影子验收与入口迁移

## Goal

用可审计的真实 CNB 证据完成 GMGN V2 的分阶段上线：先在独立 `clash-cn-gmgn-v2-shadow` 手动运行一次，再对三个不同 GitHub candidate profile SHA 完成有效且 accepted 的自动影子验收；只有向用户提交迁移报告并再次获得明确同意后，才把同一个已验收 bundle 提升到正式 `clash-cn-gmgn-output`，更新推荐入口，并停止 gstatic 自动更新。

gstatic 不删除：`clash-cn-output` 保留最后一版 `clash.yaml`、原 URL、最后 bundle 和受控手动恢复入口，状态明确标记 frozen/legacy。rollout 任何阶段失败都保留当前默认和 last-good，不重新测速、不降低门槛、不自动切换回退源。

## Dependencies

- C1–C6 的代码、测试、schema 和文件 owner 必须完成并通过父任务集成审查。
- `08-11-gmgn-publication-orchestration-v2` 必须提供独立 V2 shadow、manual/off 自动模式、bundle/CAS、远端 validator 的 `run/series/migration` 模式。
- C2 冻结每节点恰好 20 轮、初始最短观察窗口 900 秒、四片出口/canary 与 `valid_run`。
- C3/C4 冻结历史、稳定名称、真实地区、亚洲宽松候补、非亚洲严格、80/150/20 和十组契约。
- 用户在连续三次验收报告之后的单独明确回复，是正式迁移和 gstatic 冻结的必要授权；此前任何“开始实现”或早期同意都不等价于迁移授权。

## In Scope

- 代码完成门禁、单次真实 V2 shadow、连续三次有效 shadow 的证据收集与验证。
- 单次通过后把自动模式从 `off` 切到仅写 V2 shadow 的 `shadow`。
- 三次通过后生成迁移候选报告并等待用户明确批准。
- 获批后提升 exact accepted bundle、远端 smoke、文档/推荐入口迁移、gstatic frozen/legacy 标记与手动恢复说明。
- 迁移前后 refs/bundle hash 记录、失败注入、回滚演练和证据归档。

## Out of Scope

- 在 rollout 中重写 C1–C6 算法、临时降低 14/10/16/18、20 轮、1000 ms 或 900 秒窗口。
- 为了得到三次成功而把 invalid/rejected/retry 运行计入验收。
- 在用户批准前修改 `clash-cn-gmgn-output`、推荐订阅或 gstatic 自动任务。
- 删除旧 gstatic/GMGN/shadow 分支、旧 URL 或历史证据。
- 自动双向切换 GMGN 与 gstatic，或在迁移时重新测速生成新 bundle。

## Requirements

### R1. 代码完成门禁

- C1–C6 的目标单元、组件、workflow contract、完整 `unittest`、JSON/YAML、公开 allowlist 和目标 Linux Mihomo `-t` 必须全部通过。
- V2 自动模式必须为 `off`；只允许显式手动 source SHA 写 `clash-cn-gmgn-v2-shadow`。
- `clash-cn-output`、`clash-cn-gmgn-output`、旧 shadow、文档推荐入口和 gstatic schedule/tag 自动任务在该门禁前后保持不变。
- 记录 GitHub/CNB main SHA、policy/schema/runtime、独立的 `identity_epoch`、独立的 `identity_key_version`、Python/PyYAML/Mihomo 版本/hash，以及三个受保护输出分支的 before refs/bundle hash。
- 未通过代码门禁时不得发起真实 shadow；修复导致任一冻结版本变化时必须重新跑完整门禁。

### R2. 单次真实影子

- 对一个明确且新鲜的 candidate profile SHA 手动触发 V2 shadow；source status、profile、candidate-metadata、manifest、四片和 bundle 必须绑定同一 profile hash。
- 每个 snapshot candidate 恰好 20 次 GMGN 观测，同节点顺序执行，首末采样跨度至少 900 秒；四片出口/canary/controller/target control 满足版本化 `valid_run`。
- 核对亚洲核心/弹性/手动候补/历史保护/非亚洲、真实五地区、80/150/20、多样性、稳定名称、十组和脱敏诊断；公开 history/diagnostics 只能含 HMAC opaque identity，不得含裸 fingerprint 或真实出口 IP。
- staging 与 authoritative remote smoke 都成功，V2 bundle 能按 run ID 回看；旧 gstatic、正式 GMGN 和推荐入口 refs 不变。
- 至少执行一次失败注入，证明缺片、坏 state、Mihomo invalid 或 remote stale cache 会保留 V2 shadow last-good。
- 只有全部通过后，才允许以独立变更将自动模式从 `off` 切到 `shadow`；自动触发仍只能写 V2 shadow。

### R3. 连续三次有效影子

- 三次 accepted run 必须来自三个不同完整 candidate profile SHA，相邻可计数运行至少间隔 21600 秒。
- 三次必须使用完全相同的 candidate/GMGN/history/selection/bundle schema、policy version、`identity_epoch`、`identity_key_version`、Python/PyYAML/Mihomo 版本与 binary hash；epoch 与 key version 分别比较，任一变化将连续计数重置为 0。
- 三次均须 `valid_run=true`、selection accepted、CAS 成功、promotion 后 remote smoke 成功。重复 SHA、基础设施 retry、invalid run、rejected run 和 smoke 失败都不计数、不推进 history。
- 跨三次验证 output name、地区 cache、history transition、恢复晋级、source provenance、bundle/run 关联和 last-5 index 稳定。
- 真实免费节点无需自然完成全部状态轨迹；使用不进入用户订阅的确定性 history canary 或对三次真实 bundle 的受控 replay，证明 `bad1 → bad2 → bad3/remove → recovered`，并证明 invalid/retry 不计数。
- 三次期间 `clash-cn-output`、`clash-cn-gmgn-output` 和推荐入口保持不变；三次通过只生成迁移候选报告，不自动迁移。

### R4. 迁移授权和 exact bundle 提升

- 迁移候选报告必须向用户列出三个 run/source SHA、时间间隔、policy/runtime、节点/地区/层级数量、错误率、历史 canary、远端 smoke、当前订阅 URL 和回滚 refs。
- 必须在该报告之后取得用户单独、明确的迁移批准；未批准时保持 shadow 模式继续运行或停留，不得猜测授权。
- 迁移使用最后一个已经通过三次门禁的 exact V2 bundle，按 bundle hash 提升到 `clash-cn-gmgn-output`；不得重新测量、重新选择或重新渲染另一份内容。
- V2 bundle 必须预先采用 branch-neutral status；正式提升不改任何 bundle payload 字节，不注入 formal branch、URL 或 promotion time。渠道差异仅由 ref 和迁移后文档表达。
- 正式 GMGN 远端回读必须证明 run ID、source SHA、bundle/file hash、节点数、十组、history、node-status 与已验收 bundle 完全一致，且目标 Mihomo 可加载。
- 正式订阅 URL 保持现有 `clash-cn-gmgn-output` 地址，用户不需要新增链接；文档明确区分 GitHub 宽候选、GMGN 正式和冻结 gstatic。

### R5. gstatic 冻结而非删除

- 只有正式 GMGN exact bundle 提升和远端 smoke 成功后，才停止 gstatic 的 schedule/自动 tag 触发；保留受控手动恢复入口。
- `clash-cn-output` 的最后 `clash.yaml` 内容和 URL 保持可读；status/README 标记 `lifecycle=frozen`、`legacy=true`、`frozen_at`、最后 profile/bundle hash、replacement GMGN URL 和恢复步骤。
- 冻结标记发布必须验证最后 profile hash 未改变；不得以空文件或新缩水结果覆盖旧 gstatic。
- 文档不再把 gstatic 作为默认推荐，但明确它是回退对照；未来只有人工确认 GMGN 长期不可用时才恢复自动任务，不做自动切换。

### R6. 证据与远端验证

- 所有 live 下载、before/after refs、validator 输出、运行摘要、bundle/hash、截图或回滚证据写入 `D:\xiangmu\linshi\gmgn-v2-rollout`，不把临时运行产物提交到仓库。
- 每道门禁使用 C5 的 validator；HTTP 读取带 nonce/no-cache，并保存 exact 内容 hash，而不是只看网页显示或 Clash 节点数量。
- before/after refs 必须证明：单次/三次阶段只有 V2 shadow 可变化；迁移阶段正式 GMGN 与文档/触发配置按批准计划变化；gstatic profile 内容保留且状态冻结。

### R7. 回滚

- 单次失败：自动模式保持/切回 `off`，V2 shadow 保留 last-good，旧默认不动。
- 三次期间失败：无效/拒绝运行不计数；policy/schema/runtime 变化重置计数并重新从单次/代码门禁验证，不删除已有诊断。
- 迁移后 smoke 或用户本地确认失败：使用迁移前 refs/bundle hash 以 lease 恢复正式 GMGN/推荐文档；必要时人工恢复 gstatic schedule，旧 URL 和 frozen 历史仍保留。
- 所有回滚使用已记录 refs/hash，不重新抓取历史免费节点，也不删除任一分支。

## Acceptance Criteria

- [ ] 代码门禁完整通过，V2 自动模式仍为 off，三个现有输出分支和推荐入口的 before/after refs 无变化。
- [ ] 一个固定 source SHA 完成一次真实四分片、每候选 20 轮、至少 900 秒观察窗的 valid V2 shadow，并通过 staging/current 防缓存 smoke 与固定 Mihomo。
- [ ] 单次影子输出满足亚洲宽松候补、非亚洲最多 20、80 期望/150 上限、五地区和十组；旧 gstatic/正式 GMGN 未改变。
- [ ] 失败注入证明 rejected run 不覆盖 V2 last-good、不推进 history、不计入 rollout。
- [ ] 自动 shadow 开启后，三个不同 source SHA、间隔至少 21600 秒、相同 policy/runtime 的 accepted run 通过 `series` validator。
- [ ] 确定性 canary/replay 证明 bad1/bad2/bad3 remove/recover、重复 SHA、invalid 和 retry 语义。
- [ ] 三次通过后先提交迁移报告并等待用户新批准；在批准前正式 GMGN、推荐入口和 gstatic 自动任务不变。
- [ ] 获批后正式 GMGN 与最后 accepted V2 bundle 的 run ID、source SHA、bundle hash 和全部文件 hash 完全一致，没有重新测速/重选。
- [ ] 用户刷新正式 GMGN URL 可看到目标十组；文档明确三类订阅用途，不再把旧 `automatic / 84` gstatic 结果描述为 V2。
- [ ] gstatic schedule/自动 tag 已停止，旧 URL 和最后 profile 可读，status/README 含 frozen/legacy、时间、hash、replacement 和手动恢复说明。
- [ ] `migration` validator 和回滚演练证明能用记录的 refs/hash 恢复入口，且不删除分支、不重新抓取历史节点。
