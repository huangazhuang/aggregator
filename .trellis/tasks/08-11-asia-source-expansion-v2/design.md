# 外部亚洲来源受控扩展设计

## 1. 数据流

```text
source registry entry
  → fetch to private runtime
  → parse + untrusted-input validation
  → C3 canonical identity / endpoint IDs
  → marginal-gain comparison with current C1 snapshot
  → freshness / transparency / overlap / capacity gate
  → deterministic per-source/region/endpoint limits
  → merge provenance into C1 candidate model
  → C1 publish guard + remote smoke
```

本任务不直接生成另一份机器代理列表。最终仍由 C1 发布 `clash.yaml`、`status.json` 和 `candidate-metadata.json`，CNB 以 profile hash 绑定配置和 metadata。

## 2. Source registry

每个来源条目至少定义：稳定 source ID、URL 模板或仓库产物定位器、格式、enabled flag、public/private、`publish_derivatives`、目标地区、最大贡献数、最大地区数、最大 endpoint 变体、freshness SLA 和透明度等级。

解析器返回通用 candidate record；身份、endpoint/server opaque ID 由 C3 单一 owner 生成。评估器和生产采集共用同一解析/验证路径，避免“审计通过的内容”和“实际上线的内容”语义分叉。

## 3. 边际增益算法

对来源内候选先做安全校验和 canonical exact dedupe，再与 current snapshot 比较：

- exact fingerprint 新增；
- endpoint 新增；
- 五地区新增；
- 与现池 fingerprint/endpoint 重叠；
- 同 endpoint 变体与协议分布。

通过门禁后，按地区缺口、endpoint 唯一、更新时间、稳定 identity 排序，依次应用 per-endpoint=3、per-region=100、per-source=300。所有裁剪输出 reason，输入重排不改变结果。

## 4. 来源选择

MVP 顺序：

1. `awesome-vpn/awesome-vpn`：小、更新活跃，先验证其实际净增与公开生成/验证证据。
2. Mahdibland：只读取限额亚洲子集，不接入 5k+ 全量。
3. V2Hive：仅 reservoir；透明度和重复风险决定其不能直接 unlimited 发布。

只有首个满足 PRD 数值门禁的来源进入 enabled。其余报告可保留为评估证据，但不默认打开。

## 5. 健康与失败隔离

新来源接入 C1 的 source-health reducer。fetch/429/parse/security failure 只更新观察状态；last-success 仍在 TTL 时继续使用，过期则阻止候选发布。confirmed missing 必须来自 C1 定义的多个健康采集，不由单次源失败决定。

source flag 是采集开关，不是删除事件。关闭后保留 health/provenance 状态，通过明确停用原因区分运营回滚和上游消失。

## 6. 容量模型

评估器读取 C2 版本化 shard/workers/timeout/rounds/900-second window 预算，输出加入前后的候选数、最坏 batches、预计上界和阈值余量。5000 是本版本接入前的硬评估线；达到线即拒绝本轮扩源并要求父任务另行做性能规划。

## 7. 安全与回滚

- fetch/parse job 与 publisher token 隔离；临时上游内容只写 `D:\xiangmu\linshi` 或 CI 私密 runtime。
- 域名候选在实际连接前解析并拒绝内网/元数据地址，不能只检查字面 hostname。
- 回滚是关闭单一 source flag；不删除文件、不清空 source history、不改变 CNB 规则。
