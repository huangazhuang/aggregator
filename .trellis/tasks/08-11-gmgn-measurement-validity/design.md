# GMGN 测量有效性与并发标定技术设计

## 1. 组件划分

```text
C1 candidate snapshot + C3 identity
  → controlled identity preflight：固定向量/候选 ID/`identity_key_version`/`identity_epoch`
  → prepare：固定三件套、验证双 hash、生成 manifest v3/四片
  → shard-0..3：独立 Mihomo + round barrier + 900s pacing
  → private fragment + redacted fragment + control/canary/egress
  → merge：严格字段/守恒/完整性
  → validate_run：有效或拒绝
  → valid measurement（供 C3/C4/C5）或 redacted failure（不可推进历史）
```

`prepare/probe/merge/validate` 都保持 CLI 薄入口和可复用纯函数。`.cnb.yml` 只由 C5 将这些命令编排成真实 jobs。

## 2. Manifest v3

manifest 使用严格相等字段集合，至少分为：

- source：snapshot ID、profile/metadata SHA、metadata schema/count、main SHA、候选数、identity key version、identity epoch；
- target：URL、expected status、request timeout、qualified delay、20 rounds、900s window；
- runtime：Python/PyYAML/Mihomo version/hash、workers、canary version/hash、validity policy；
- run：run ID、created_at、trigger type；
- shards：index、candidate count、candidate ID hash、private runtime paths、stagger seconds。

候选配置仅写私密 shard input；公开 manifest 不列 proxy/name/server。所有 path 在执行前解析并确认位于 `.cnb-runtime`，拒绝 `.git`、`public-cn*` 和路径逃逸。

## 3. 分片算法

1. 为每个 profile proxy 用 C3 API计算 `candidate_id`，与 C1 metadata 一对一校验。
2. 按 `candidate_id` 排序。
3. 使用 `index % 4` round-robin 分片。
4. 每片记录排序后 candidate IDs 的 hash；merge 重新验证全集、交集和并集。

此算法使输入 YAML 重排不改变归属，并保证片差不超过 1。候选 ID 冲突或 metadata orphan 由 prepare 在任何 Mihomo 启动前拒绝。

prepare 完成后、启动四片前执行 C2-owned probe network guard：重新解析每个域名的全部 A/AAAA，拒绝 non-global、loopback、private、link-local、CGNAT、multicast、reserved、unspecified 和 metadata 目标，并为 Mihomo 固定安全解析。C2 提供版本化 policy/launcher/self-test；C5 在 job 中提供容器或 network namespace 等隔离原语并调用它，阻断上述地址以覆盖 DNS rebinding 的解析后 TOCTOU。任一安全漂移、backend 缺失或 deny self-test 失败都使整轮在 Mihomo 启动前失败；probe jobs 不得注入正式发布 token，controller 通道留在隔离边界内。

HMAC key 只进入 controlled identity preflight/redaction stage。该 stage 只读取固定 snapshot、`tests/fixtures/gmgn_identity_v1.json` 和最小私密 egress-IP handoff，不访问原始来源、不启动 Mihomo、不持发布 token。四个 probe jobs 和最终 publisher 不持 HMAC key；preflight 在启动 Mihomo 前比较 GitHub metadata 中四类固定 public IDs。

## 4. 20 轮 scheduler

每片流程：

1. 按 0/15/30/45 秒固定错峰启动。
2. 启动独立 Mihomo，读取 `/version` 并核对 manifest runtime。
3. round 0 并发提交该片全部候选；每个请求结束后写一个终态 sample。
4. `anchor=max(round0.started_at)`。
5. 对 round 1–19，在该轮提交前等待到 `anchor + round_index * 900/19`；若前一轮自然运行更久则不额外等待。
6. 轮与轮之间有 barrier：上一轮全部 future 已完成、controller 健康已确认后才进入下一轮。
7. round 19 后逐 candidate 验证 20 个唯一 round 和首末 start span ≥900s。

round barrier 保证同一 candidate 不并发；轮内 ThreadPool 充分并行不同 candidate。queue 可按稳定 rotation 改变每轮先后，减少固定队尾偏差，但不得改变 round 归属或产生重复。

## 5. Sample 与统计模型

私密 sample：`candidate_id`、round、started/finished、delay、category、必要的安全内部状态。原始异常只允许在受限日志中短期存在，不进入 fragment 字段。

节点 summary 由 sample 单向归约，不允许 probe 与 publisher 各写一套统计。分位数沿用 nearest-rank；没有响应时为 null。jitter 的定义和单位固定在 schema/policy fixture 中。

聚合验证顺序：sample 数量 → 唯一 round → response/no-result → within/slow → halves/blocks → round trends → shard/global errors。任一不守恒拒绝整个 run。

## 6. 错误分类 owner

错误归一化函数是唯一 owner，输入 Mihomo HTTP status、安全解析的响应和客户端异常类型，输出 R4 枚举。`controller_unhealthy` 只表示 `/version`/进程健康失败；代理请求返回的 controller HTTP 错误归入 `controller_request`，避免把 5xx 全部误报为基础设施死亡。

原始文本不得成为公开分类键，也不得拼进异常。未知异常归 `other`，并在私密日志计数而不是扩散新字符串字段。

## 7. Control、canary 和出口

每片在 round 0 前和 round 19 后执行 egress lookup，私密保存 IP，公开投影 country/region/org，并调用 C3 `exit_id(public_ip)` 生成 HMAC opaque ID。lookup/identity 失败、非 CN、前后变化或跨片 region 不一致均使 valid-run 失败。

每轮 control 是 Runner 直连 GMGN HTTP 200 检查，不经过候选 proxy。canary 是版本化少量稳定代理/端点，四片加载同一集合但不参与候选排名。control/canary 样本与 candidate 样本分开计数，不能污染 candidate 20 轮汇总。

## 8. Validity policy v1

`validate_run()` 是纯函数，返回 `{valid_run, reasons, metrics}`；reasons 使用固定安全枚举。初始门槛：

- 4 shards 完整；所有 candidate 20 次、900s；
- controller unhealthy=0；runtime/hash 完全一致；
- egress country CN、region 一致、同片前后 ID 不变；
- direct control 每片 ≥18/20 且最大连续失败 <3；
- 每个 canary/片 ≥16/20；跨片成功差 ≤4；median 差 ≤max(300ms, faster median×50%)；
- global 403+429 ≤2%；任何单轮 403+429 <10%。

高 candidate timeout 只作为诊断；只有与 control/canary/片偏离组合时才影响有效性。validator 通过后才写 accepted measurement marker；C5 还需在 bundle/Mihomo/远端 smoke 后决定是否提交 history。

## 9. Public/private schema

private selection fragment schema v2 包含 proxy、candidate ID、20-round summary 和运行关联；redacted fragment schema v3 不含 proxy，包含 candidate ID、summary、round trends/error counts、control/canary/egress 聚合。两者共享 run/source/profile/metadata hash、identity key version、identity epoch、shard/policy/runtime 字段并分别使用严格字段常量。

所有私密写入使用 atomic replace 和 `0600`；公开输出从 redacted model 重新构建，禁止“删除若干字段后直接发布私密 dict”。

## 10. 并发 benchmark

新增非发布 benchmark 模式：固定候选子集、policy/runtime/canary，依次执行 8/16/24/32，每档至少两次，证据写 JSON。比较器按 PRD R8 计算 p50、百分点变化与 skew，输出 `keep_16` 或 `eligible_for_policy_change:<workers>`，不自动改配置。

benchmark 失败、valid-run=false 或 cohort/runtime 不一致的样本不参与结论。所有证据写 `D:\xiangmu\linshi\gmgn-measurement-validity\benchmark`。

## 11. 兼容和回滚

schema v3 使用独立版本和默认关闭入口；不让旧 consumer 忽略未知字段。C5 未接入前 current schema v2 不变。回滚只是停止调用 v3 CLI，历史/正式输出不受影响。
