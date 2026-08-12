# GMGN 真实地区选择与分组设计

## 1. 边界与数据流

```text
C1 candidate metadata
  + C2 valid-run node summaries
  + C3 history / stable identity / output name
  → 输入契约校验
  → 出口地区与 ASN cache 解析
  → tier 分类
  → 严格层多样性选择
  → 150 容量裁剪与亚洲候补宽松处理
  → 稳定名称和十个 Clash 组
  → 脱敏 node-status / selection summary
  → C5 publication bundle input
```

选择器必须实现为可离线回放的纯策略层。网络地区查询由窄适配器负责，查询结果先规范化为版本化 cache 记录；排序、分层、容量、多样性、分组和诊断不得直接访问网络或工作流环境变量。

## 2. 输入契约

输入由一个聚合对象组成：

- `run`: `valid_run=true`、run/source/main/policy/schema/runtime 信息；
- `candidates`: C1 的稳定 identity、来源证据、协议、server/endpoint opaque ID 与配置有效状态；
- `measurements`: C2 的 20 轮汇总、前后半程、P90/median/jitter 与 response/no-result；
- `history`: C3 的 HMAC candidate/exit ID、稳定 output name、当前层级和 history-protected/removed 状态；
- `private_region_cache`: 非公开受控状态中的原始出口查询 cache，生成分支只接收其规范化 HMAC `exit_id`、国家/地区、ASN、时间和 stale 标记；
- `region_policy`、`selection_policy`: 固定版本和全部数值常量。

一个 owner 负责严格解码并验证字段集合、版本、identity 集合和 run 关联。选择器内部只消费规范化类型，禁止多个消费者自行读取 raw JSON 字段。

## 3. 地区查询适配器

查询计划先对 identity 去重，并只包含本轮 responder、潜在严格层及历史保护节点。适配器通过该节点代理访问固定 provider，返回：

- `country_code`, `region_code`, `asn`；
- 只写私密 cache 的出口 IP，以及由 C3 identity owner 生成、可进入公开 history 的 opaque `exit_id`；
- `observed_at`, `provider_schema`, `expires_at`, `stale`；
- `confidence=verified|source-specific|unknown|conflict`。

查询失败时优先读取 7 天有效 cache；历史保护节点可读取 30 天 grace cache。真实数据与来源证据冲突时以真实出口为主并记录 conflict；没有真实数据时，只有国家专用、可追溯来源证据可给手动候补资格。

## 4. 分层与选择

先分类，再选择，禁止通过容量循环修改质量线。

1. 计算每个 identity 的 eligibility 和唯一 reason code。
2. 生成亚洲核心、亚洲弹性、亚洲手动候补、历史保护、非亚洲严格候选池。
3. 对严格池应用固定质量排序与 greedy diversity；地区覆盖只是同质量条件下的优先项。
4. 非亚洲先取最多 10 个 `>=16/20`，再从剩余 `>=18/20` 扩展到最多 20。
5. 合并严格层、历史保护和当前候补；若超过 150，按 PRD 的层级顺序裁剪。

每个节点保留结构化 reason，例如 `asia_core`, `asia_flexible`, `asia_manual_slow_only`, `history_bad_1`, `region_unknown`, `diversity_exit_cap`, `capacity_cap`, `non_asia_below_threshold`。显示文案由单一映射生成，避免测试和生产使用不同逻辑。

## 5. 多样性模型

严格层 selection state 维护 `exit_id`、`server_id`、ASN 和 `source_id` 计数。候选按固定排序遍历，达到任一硬上限则跳过并记录原因。五地区尚未覆盖时，可在相同 tier/质量边界内优先未覆盖地区；不得跨阈值或跨 tier 补位。

亚洲候补拥有单独路径：在总数小于等于 150 时不因故障域重复删除，只计算 concentration flags；需要裁剪时将这些 flags 作为质量排序之后的稳定 tie-breaker。这样主力保持独立性，候补仍保留用户本地可能可用的协议/凭据变体。

## 6. 分组渲染

分组成员先以稳定 identity 表示，最后一步才映射到 C3 的 `output_name`。渲染器统一生成十个固定组并调用共享的 Clash 引用过滤/序列化工具，避免悬空引用和 REALITY 字段漂移。

`👆手动优先测速` 只包含经多样性硬限制的亚洲核心、亚洲弹性和非亚洲稳定，作为优先手测集合。`📦全部入选` 才包含全部最终 identity；亚洲候补同时进入 `🌏亚洲候补`，真实出口已验证时也进入对应地区组。`GMGN自动` 明确排除 flexible 与两类候补。

## 7. 公开诊断边界

公开 `node-status` 只输出 opaque diagnostic ID、stable output name、tier/reason、聚合测量、地区置信度、history transition 和 concentration flags。真实出口 IP、服务器、凭据和原始 provider/error payload 只留私密运行目录。

生产 profile、selection summary 和 node-status 必须共享同一个 run ID、source SHA、policy version、`identity_epoch` 和 `identity_key_version`；该关联由 C5 在 bundle 阶段再次校验。epoch 表示 canonicalization/domain 代际，key version 表示密钥轮换，不能互相替代。

## 8. 兼容与回滚

- 旧五组配置不能被增量修改；V2 在独立 shadow 分支一次性生成新十组。
- 未知 selection/history/region schema 一律失败关闭，不从旧组名反推状态。
- 回滚只需让 C5 继续发布上一份已验证 bundle；本任务没有独立远端写操作。
- 地区 provider 异常时保持 cache/unknown 降级，不通过临时放宽主力资格来恢复数量。
