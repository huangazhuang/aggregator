# GMGN 稳定身份、历史与名称技术设计

## 1. 模块边界

建议新增两个单一 owner：

- `scripts/proxy_identity.py`：canonical projection、内部 fingerprint、HMAC candidate/server/endpoint/exit IDs、identity key version、identity epoch 和 migration helpers。
- `scripts/gmgn_history.py`：history schema/loader/validator、event normalization、纯 reducer、stable name allocator 和 staged atomic write。

`scripts/cnb_gmgn_publish.py` 在 C3 只增加默认关闭的 adapter/fixture 接口；C4 后续接入最终 staged tier，C5 后续负责原子提交。C1/C2 通过 import 共享 identity，禁止复制算法。

C3 是纯数据层，不做 DNS/HTTP/Mihomo I/O。`exit_id()` 只解析调用方提供的 IP 字符串并验证为 global；C1/C2 负责 endpoint 解析安全，C5 负责工作流网络层 deny 和发布 Secret 隔离。

固定 `tests/fixtures/gmgn_identity_v1.json` 只含假连接字段和公开 global IP，不含真实凭据。controlled identity stage 用生产 HMAC key 计算四类 public IDs；GitHub metadata 携带这组 preflight IDs，CNB 在测速前重算比较。该 stage 只消费安全固定 snapshot/fixture 或最小 egress-IP handoff，不执行不可信抓取/代理，也不持发布 token。

## 2. Canonical identity

输入必须先经过项目 proxy validator。canonical projection 从完整配置中删除版本化的非连接字段集合，例如：`name`、source/provenance、liveness/chatgpt、GMGN metrics、candidate/output IDs 和内部 `_` 辅助字段；其余已允许字段全部保留。删除集合是显式常量并有反向测试，新增允许连接字段时必须更新 identity fixture。

递归编码规则：mapping key 按 Unicode code point 排序；list 顺序保留；bool/int/string 不互相转换；禁止 NaN/Infinity；UTF-8、`ensure_ascii=False`、紧凑 separators。`sha256(canonical_bytes)` 为内部 fingerprint。

## 3. HMAC IDs

使用 domain-separated message：

```text
candidate: HMAC(key, "candidate\0" + identity_epoch + "\0" + identity_key_version + "\0" + fingerprint_bytes)
server:    HMAC(key, "server\0" + identity_epoch + "\0" + identity_key_version + "\0" + canonical_server_bytes)
endpoint:  HMAC(key, "endpoint\0" + identity_epoch + "\0" + identity_key_version + "\0" + canonical_server_port_bytes)
exit:      HMAC(key, "exit\0" + identity_epoch + "\0" + identity_key_version + "\0" + canonical_public_ip_bytes)
```

公开取前 12 bytes（24 hex），分别加 `c1_`、`srv1_`、`ep1_`、`exit1_`。`canonical_public_ip_bytes` 来自标准 IP parser：IPv4 canonical dotted decimal，IPv6 RFC 5952 compressed lowercase；非 global/无效地址拒绝。完整 digest 仅用于内部 collision 检查；任何 domain 内公开截断碰撞时整次快照/运行失败，不自动延长某一个 ID。

key registry 只接受明确 `identity_key_version -> secret` 映射，canonicalization/domain HMAC 语义由 `identity_epoch` 标识。当前与 previous identity key/epoch 不同必须进入迁移模式：对当前快照中可重算对象同时计算旧/新 candidate/server/endpoint/exit IDs，验证一对一后迁移 history 和 metadata references；快照外 tombstone 按第 8 节保留 legacy identity。缺旧 key、未知 epoch 或无显式迁移路径时 fail-closed。

## 4. History schema v1

顶层严格字段：

```json
{
  "kind": "cnb-gmgn-history",
  "schema_version": 1,
  "identity_key_version": "...",
  "identity_epoch": "...",
  "history_policy_version": "history-v1",
  "selection_policy_version": "...",
  "last_accepted_run_id": "...",
  "last_accepted_source_sha256": "...",
  "last_accepted_at": "...Z",
  "nodes": {}
}
```

node 严格字段包含：candidate ID、节点 ID 的 identity key version/identity epoch、`legacy_identity`、`tombstone_expires_at`、output name、current/previous state、transition reason、bad streak、last counted-bad SHA/time、recent accepted observations、first/last seen/selected、source state、last measurement summary、region-cache 安全容器和 removed tombstone 标记。recent observations 最少保存最近 3 个、V1 固定最多 5 个，每条记录 `counted_bad`；无效/拒绝运行不进入此数组。

region cache 只定义安全 persistence envelope（country/region/HMAC exit/ASN IDs、queried/expires/stale），不得保存原始出口 IP；具体查询和可信度由 C4 owner。

## 5. Reducer 输入契约

每次 stage 接收：

- `run_context`：run/source SHA、run time、valid_run、retry、policy/runtime versions；
- `source_events`：C1 health、confirmed missing；
- `measurements`：C2 response/within/no-result 等完整 summary；
- `decisions`：C4 proposed state/tier 和 reason；
- previous validated history。

stage 前检查 run/source/policy/identity 一致。任何新 `valid_run=true` 且 accepted 的 run 都生成 observation 并推进顶层 last accepted；distinct SHA + 21600 秒只决定 zero-response observation 的 `counted_bad`。responsive accepted observation 立即 reset/recover。已经 accepted 的 source SHA/run ID保持幂等，不生成第二次 transition；C4/C5 拒绝时丢弃 staged result，previous object 和文件保持不变。

## 6. 状态机

| 条件 | 新状态 | streak | reason |
|---|---|---:|---|
| 新亚洲，response≥1，C4 core/flexible/manual | 对应状态 | 0 | `first_responsive_observation` |
| 新亚洲，response=0 | 不创建公开 history/output | - | 仅 C1 候选池 |
| 既有亚洲，accepted response=0，但 spacing/SHA 不可计数 | `history_protected` | 不变 | `zero_response_not_counted` |
| 既有亚洲，可计数 response=0，第1/2次 | `history_protected` | 1/2 | `zero_response_bad_run` |
| 既有亚洲，可计数 response=0，第3次 | `removed_bad_streak` | 3 | `bad_streak_limit` |
| history/removed 后 accepted response≥1（无需 spacing） | C4 proposed manual/core/flexible | 0 | `recovered_response`/`recovered_quality` |
| C1 confirmed missing | `removed_source_missing` | 不变 | `source_confirmed_missing` |
| Mihomo config invalid | `removed_invalid_config` | 不变 | `invalid_config` |
| temporary source failure | 不变 | 不变 | 不增加 bad |
| invalid/rejected/publish failure | 不变 | 不变 | 不提交 history |

非亚洲节点不走 `history_protected`；C4 未选择时可保留 tombstone/名称映射，但不进入发布组。

## 7. Stable name allocator

先加载 previous 全部 name mapping 和 Clash reserved names。既有 candidate 直接复用。新 candidate：

1. 清洗安全 alias，去除控制字符和动态测速后缀，限制版本化长度；
2. 若 base 非空且未占用，使用 base；
3. 否则使用 `<base-or-Node> [<candidate_id last6>]`；
4. 极端碰撞再使用完整公开 ID 的稳定 suffix，仍不得依赖遍历顺序。

先按 candidate ID 排序后批量分配，保证同一批新节点输入重排结果相同。removed tombstone 保留名称占用，恢复时不会被其他节点抢走。

## 8. Bootstrap 与 migration

首次 V2 shadow 必须同时加载并校验 current GMGN profile/status：profile hash/count/组引用正确后，为每个 proxy 计算新 candidate ID，保留合法唯一 name，current state 只按明确旧组做有限 bootstrap 标记，所有 bad streak=0；记录 `bootstrap_legacy_profile`，不声称已有三轮历史。

unknown history schema、profile/status 单边缺失、hash mismatch 或名称重复均 fail-closed。Key/epoch rotation 使用独立 migration command：当前快照内可重算节点迁移到 active ID；快照外 removed tombstone 保留旧 ID/key/epoch、名称和 `legacy_identity=true`。旧 key 在 legacy 数量非零时不得退役；节点重现时用旧 key 匹配后迁移。tombstone 满 90 天后只能执行显式 audited GC，先输出 ID/name/reason/age 证据；legacy=0 或审计 GC 完成后才允许退役旧 key。C5 原子发布前不改权威历史。

## 9. 原子性与公开关联

`write_history_atomic()` 只写 staging 临时文件并 replace；权威性由 C5 bundle commit 决定。公开 node diagnostics 使用 candidate ID，profile status 记录 history SHA 和 run ID；C5 必须保证三者同提交。

异常信息只含固定 reason 和 candidate count，不包含 fingerprint、proxy 或 secret。所有测试 fixture 采用假 secret，并断言序列化结果不包含它。

## 10. 兼容与回滚

adapter 默认关闭，现有 publisher 不读取 history v1。C5 接入 V2 shadow 后，旧正式分支仍是 rollback；任何 schema/key/migration 问题都保留 previous history/profile，不做空状态首发。
