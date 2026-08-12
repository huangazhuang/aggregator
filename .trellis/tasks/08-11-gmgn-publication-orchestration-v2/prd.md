# GMGN 事务发布触发与远端校验

## Goal

将已经通过 C1–C4 契约校验的 GMGN V2 结果，以一个不可分割、可追溯、可回滚的 bundle 发布到独立 `clash-cn-gmgn-v2-shadow` 分支，并让每个新的 GitHub candidate profile SHA 自动且至多触发一次完整 CNB 测试。任何 previous state、构建、Mihomo、竞态、推送、缓存或远端 smoke 异常都不得覆盖 last-good，也不得提交历史差评。

代码完成阶段只建立手动 V2 shadow 能力；自动触发必须等 C7 的单次真实影子验收通过后再开启。本子任务不迁移用户默认入口、不冻结 gstatic。

## Dependencies

- 依赖 `08-11-github-candidate-provenance-v2` 的 `clash.yaml + status.json + candidate-metadata.json` 三件套与 GitHub 发布后 remote smoke；CNB 通过 profile hash 绑定 metadata，不引入 `candidates.jsonl`。
- 依赖 `08-11-gmgn-measurement-validity` 的 manifest、四分片 fragment、`valid_run` 和全局事故门禁。
- 依赖 `08-11-gmgn-history-identity` 的 versioned `history.json`、稳定 identity/name、HMAC diagnostic ID 与“失败运行不推进历史”接口。
- 依赖 `08-11-gmgn-selection-groups-v2` 的最终 profile、十组、node-status 和 selection summary 契约。
- 完成后由 `08-11-gmgn-v2-rollout` 执行真实单次/三次影子及正式迁移；本任务本身不得越过 rollout 门禁。

## In Scope

- 原子构建、验证和发布 V2 shadow bundle。
- previous branch/state 的严格读取、明确首发判定、CAS/force-with-lease 和旧运行拒绝。
- 新 candidate profile SHA 的幂等触发、任务锁、基础设施 retry 语义和 processed-source 记录。
- 推送后的防缓存远端回读、schema/hash/count/group/run 关联和固定 Mihomo 校验。
- workflow 最小权限、私密 fragment 与公开 bundle 隔离、失败诊断和自动化契约测试。

## Out of Scope

- 修改节点采集、20 轮测量、地区/分层/多样性或历史状态机规则。
- 在代码完成时启用新 SHA 自动触发；该开关由 C7 在单次影子通过后修改。
- 覆盖 `clash-cn-gmgn-output`、修改推荐订阅、停止 gstatic 自动更新或删除任一旧分支/URL。
- 拆分仓库或引入多 Worker 仓库。
- 在远端校验失败后把本地构建结果宣告为成功。

## Requirements

### R1. 独立 V2 shadow 与单 bundle

- 新方案只能写 `clash-cn-gmgn-v2-shadow` 及明确的非权威 staging/失败诊断位置；不得写旧 `clash-cn-output`、当前 `clash-cn-gmgn-output` 或旧 `clash-cn-gmgn-shadow`。
- 一个 accepted commit 至少同时包含：`clash.yaml`、`status.json`、`history.json`、`node-status.json`、`runs/index.json`，以及 `runs/<run_id>/diagnostics.json` 的脱敏运行摘要。
- root current 文件、history、node-status 和 run diagnostics 必须共享同一 `run_id`、source profile SHA、main SHA、policy/schema/runtime 版本、独立的 `identity_epoch`、独立的 `identity_key_version` 和 bundle hash。
- 公开 `history.json` 只能用同时绑定 `identity_key_version` 与 `identity_epoch` 的 HMAC `candidate_id`/`exit_id`；裸 fingerprint、真实出口 IP 和私密地区 cache 只能存在于非公开运行态，不得进入 bundle。
- bundle hash 使用非递归逻辑哈希：对除 `bundle.json` 外的 bundle payload 按相对路径排序；JSON 文件在移除顶层 `bundle_hash` 字段后用 canonical JSON 编码，`clash.yaml` 使用精确字节；拼接路径与内容后计算 SHA-256。随后把结果写入各 JSON 的 `bundle_hash`。`bundle.json` 不参与该逻辑哈希，只保存该值及最终 payload 文件的精确 SHA-256，validator 同时重算两层。
- 可被 shadow 与正式分支原样提升的 bundle 文件不得包含 branch/channel、shadow/formal mode、订阅绝对 URL、promotion time 等分支专属字段；这些信息只能存在于工作流证据或分支外文档。正式提升允许 Git commit 元数据不同，但 bundle 树中文件字节和 bundle hash 必须完全相同。
- `runs/index.json` 必须保留最近 5 个 accepted run 的 content-addressed 脱敏摘要；被拒绝运行不得替换 current，可另存为不具权威性的安全失败诊断。
- bundle 先在私密 staging 完整构建；只有字段 allowlist、JSON/YAML 回读、hash、计数、组引用、20 轮/四片、历史关联和固定 Mihomo `-t` 全部通过后才允许远端发布。

### R2. previous 读取和首发

- publisher 必须先读取远端 branch tip、previous bundle 和 history，并验证其 schema、hash、计数、组引用和内部 run 关联。
- 暂时网络错误、404 单文件缺失、坏 JSON/YAML、hash mismatch、未知 schema 或 previous tip 与内容不一致必须失败关闭。
- 只有 `git ls-remote` 明确确认 V2 shadow 分支从未存在时才允许首发；不得把“读取失败”解释为首发。
- 本轮产生的新 history 只有在 `valid_run=true`、selection 成功、bundle 本地校验通过、远端 smoke 成功且 CAS 提升成功后才成为权威状态。

### R3. CAS/lease 和事务顺序

- 读取 previous 时保存 observed tip；最终提升 `clash-cn-gmgn-v2-shadow` 必须使用 `--force-with-lease=<observed_tip>` 或等价 compare-and-swap。
- 先把候选 commit 推到非用户入口的 staging ref，使用防缓存 URL 对该 exact commit 执行 remote smoke，再以 lease 提升 shadow ref；staging 失败不得改变 shadow。
- 若 shadow tip 在运行期间变化、当前远端 source sequence 更新或本轮 run 早于 current，旧运行必须退出，禁止裸 `--force` 覆盖。
- shadow 提升后再次校验 exact tip。若第二次 smoke 失败，任务必须用已保存的 previous commit 和当前 tip 作为 lease 恢复 previous，并保持失败状态；恢复失败必须显式告警，绝不能标记成功。
- push/rollback/diagnostic 阶段的成功不得吞掉较早的构建或 smoke 失败返回码。

### R4. 远端 smoke

- 远端下载必须带每次唯一 nonce 和 `Cache-Control: no-cache`/`Pragma: no-cache`；status 与 profile 等同一 bundle 文件必须按同一 expected commit/hash 交叉验证。
- validator 必须检查：公开 schema 和 allowlist、bundle/file hash、run/source/main/policy 关联、候选/发布/层级/地区计数、精确十组和全部引用、每节点 20 轮与四片摘要、初始至少 900 秒观察窗口、分片出口/canary、history commit、稳定名称、最近运行索引。
- 下载后的 `clash.yaml` 必须由 bundle 记录的固定 Mihomo 版本/hash执行 `-t`；Python、PyYAML、Mihomo 版本/hash需写入 status。
- validator 提供 `run`、`series`、`migration` 三种模式，供本任务单次 smoke 和 C7 三次验收/迁移复用；不能在 workflow YAML 中复制验证算法。

### R5. 新 SHA 幂等触发

- GitHub candidate bundle 只有在自身远端 smoke 成功后，才能以完整 `profile_sha256` 生成 CNB 触发 key/tag；截断 SHA 只能用于显示，不能用于幂等判断。
- 同一 source SHA 已成功、正在运行或已排队时必须 no-op；CNB processed-source registry 再做一次去重，不能只依赖 Git tag。
- 正常自动运行每个新 SHA 至多一次。基础设施失败可显式 retry 同一 SHA，但必须复用逻辑 source identity，标记 retry 关系，并保证 history 只提交一次、bad-run streak 不重复增加。
- workflow lock 必须阻止两个 publisher 同时写相同 V2 shadow；较旧任务即使最后完成也不能覆盖较新 accepted bundle。
- 代码完成时自动模式固定为 `off`，只允许显式手动触发并传入 source SHA；C7 单次影子通过后，才可独立切到 `shadow` 自动模式。

### R6. 权限和秘密隔离

- 收集/探测 job 不持有正式 branch 写 token；最终 publisher 只消费固定 snapshot、validated fragments 和 previous state，不重新抓取不可信订阅。
- C5 作为 `.cnb.yml` owner 必须在每个 GMGN 分片启动前配置并调用 C2 的版本化 network guard：固定已校验公网解析，隔离 Mihomo/探测器并阻断 loopback、link-local、RFC1918、CGNAT、组播、保留地址、Runner/CI 内网和云元数据。隔离原语不可用、规则 self-test 失败或解析固定结果漂移时不得启动分片。
- 私密 selection fragments、完整 proxy、裸 fingerprint、真实出口 IP、私密 cache、原始错误和 Mihomo 日志不得进入 staging ref、shadow、公开 history/诊断或 step summary。
- GitHub/CNB token 通过环境/askpass 注入，不拼接到 URL、不回显；controller 仅绑定 loopback 且每个分片使用独立 secret/端口/目录。
- workflow 维持最小权限、现有同步队列和 CNB 独占锁；`main` 仍只允许正常快进，force/lease 仅用于明确的生成分支。

### R7. 失败诊断

- 失败诊断只含阶段、run/source SHA、安全错误类别、validator 摘要和允许的脱敏 fragment 引用；不含凭据、原始异常、完整代理或 runner IP。
- 缺片、无效运行、history 损坏、Mihomo invalid、CAS 冲突、push 失败、远端旧缓存等失败都必须证明 V2 shadow last-good 不变。
- 失败运行不得推进 processed-success、accepted-run index、history 或三次 rollout 计数。

## Acceptance Criteria

- [ ] 本地构建证明 `clash.yaml + status + history + node-status + last-5 run index` 在同一 bundle 内共享精确 run/source/policy/hash 关联；逻辑 bundle hash 与逐文件 hash 可独立重算且无自引用。
- [ ] status/bundle 不含 branch/channel/mode/绝对订阅 URL/promotion time 等分支专属字段，同一 bundle 可从 V2 shadow 原样提升到正式分支。
- [ ] previous 分支不存在与暂时不可读被严格区分；500、单文件 404、坏 schema/hash/YAML 均失败关闭且不创建可发布 commit。
- [ ] 并发旧 run、外部 tip 变化和 stale source sequence 均触发 lease/CAS 失败，较旧内容不能覆盖较新 tip。
- [ ] staging remote smoke 失败时 shadow tip 不变；提升后 smoke 失败时 previous bundle 通过 lease 恢复，任务仍为失败。
- [ ] push 后 validator 使用防缓存下载并验证 schema、hash、数量、十组、引用、20轮/四片、观察窗、出口/canary、history 和固定 Mihomo。
- [ ] 同一完整 profile SHA 的重复事件、并发事件和基础设施 retry 不会产生第二次 accepted history commit 或重复 bad streak。
- [ ] 代码门禁完成后仅存在手动 V2 shadow 触发；自动新 SHA 触发仍为关闭，旧 gstatic/正式 GMGN/推荐入口 tip 均不变。
- [ ] workflow contract 证明 V2 只能写允许分支，探测阶段没有发布 token，公开文件和日志敏感字段扫描为零命中。
- [ ] workflow/Linux 组件测试证明 network guard 在 Mihomo 前启用，public→private DNS rebinding 和私网/metadata 目标被阻断；guard backend 缺失或 self-test 失败时 shadow/history/processed-source 均不变化。
- [ ] `history.json`/`node-status.json` 公开字段扫描证明只有 HMAC opaque identity，不含裸 fingerprint、真实出口 IP 或私密 cache。
- [ ] 缺片、坏 history、Mihomo invalid、push failure、remote stale cache、CAS conflict 的自动化测试均保留 last-good。
- [ ] `scripts.validate_public_outputs` 的 `run`、`series`、`migration` 模式都有离线 fixture 和错误路径测试，可被 C7 直接调用。
