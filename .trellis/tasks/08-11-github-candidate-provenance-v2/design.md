# GitHub 候选池与 provenance V2 技术设计

## 1. 数据流与边界

```text
固定/动态/私有显式允许来源
  → 逐源抓取与 source-health
  → 配置 allowlist 与端点安全校验
  → 独立受控 identity stage 使用 C3 API 计算内部 fingerprint / HMAC IDs
  → 精确配置合并 provenance、地区证据和检查状态
  → GitHub 网络策略（亚洲 bypass，非亚洲沿用严格检查）
  → staging 生成 clash.yaml + status.json + candidate-metadata.json
  → schema/hash/数量/映射/掉量门禁
  → 默认关闭，等待 C5 事务发布与自动触发接入
```

采集器拥有不可信原始输入；publisher 只接受已经校验、可序列化的 staging model。Workflow 只负责传参、权限、阶段和开关，来源健康、合并与门禁放在可单测的 Python 模块中。

## 2. 身份接口与所有权

C3 是唯一身份 owner，提供下列版本化纯函数；C1 不复制实现：

- `canonical_proxy_fingerprint(proxy) -> bytes/hex`：仅内部使用；
- `candidate_id(proxy, identity_key_version, identity_epoch) -> c1_<24hex>`；
- `server_id(proxy, identity_key_version, identity_epoch)` 与 `endpoint_id(proxy, identity_key_version, identity_epoch)`；
- identity key/version/epoch 校验及 canonicalization fixtures。

`name`、采集临时字段、测速值和 provenance 不参与连接身份；协议、server、port、凭据、transport、TLS/REALITY 等连接相关字段全部参与。C1 的 producer 和 CNB validator 必须消费同一实现/fixture。

## 3. 发布产物契约

### 3.1 `clash.yaml`

- 只包含配置有效且通过本任务包含规则的精确唯一 proxy；
- 不写 `candidate_id`、source URL、first/last seen 等辅助字段，避免 Mihomo 兼容风险；
- proxy 名在文件内唯一，但名称不作为 metadata join key；
- 亚洲候选可处于 `bypassed_asia`，非亚洲按既有 GitHub 严格检查进入；
- 用 `dump_clash_yaml()` 或等价共享序列化器，保留 REALITY `short-id` 引号规则。

### 3.2 `candidate-metadata.json` v2

顶层严格字段：

```json
{
  "kind": "github-candidate-metadata",
  "schema_version": 2,
  "snapshot_id": "candidate_<opaque>",
  "profile_sha256": "<64hex>",
  "identity_key_version": "<version>",
  "identity_epoch": "<epoch>",
  "source_policy_version": "candidate-source-v3",
  "candidate_count": 2260,
  "identity_preflight": {
    "fixture_version": "identity-fixture-v1",
    "candidate_id": "c1_<24hex>",
    "server_id": "srv1_<24hex>",
    "endpoint_id": "ep1_<24hex>",
    "exit_id": "exit1_<24hex>"
  },
  "candidates": {
    "c1_<24hex>": {
      "aliases": [],
      "source_ids": [],
      "first_seen_at": "...Z",
      "last_seen_at": "...Z",
      "source_last_success_at": "...Z",
      "region_hints": [],
      "region_evidence": [],
      "protected_asia": true,
      "github_check_state": "bypassed_asia",
      "protocol": "vless",
      "server_id": "srv1_<opaque>",
      "endpoint_id": "ep1_<opaque>"
    }
  },
  "sources": {}
}
```

严格 validator 拒绝未知顶层/候选字段、无效时间、重复 source ID、非 opaque 私有来源标识、裸 fingerprint、完整 proxy、server/port/凭据等敏感字段。`sources` 只保存安全 source ID、公开别名、健康状态、最近成功时间、连续成功缺失计数和安全数量；私有 URL 不进入文件。

### 3.3 `status.json` v2

`status.json` 记录同一 snapshot 的双 hash 与可观察发布门禁。最低字段集合：

- 标识：`kind`、`schema_version`、`snapshot_id`、`run_at`、`main_sha`；
- 关联：`profile_sha256`、`candidate_metadata_sha256`、`profile_url`、`candidate_metadata_url`、`candidate_metadata_schema_version`、`candidate_metadata_count`、`identity_key_version`、`identity_epoch`；
- 数量：`raw_count`、`valid_config_count`、`exact_unique_count`、`unique_endpoint_count`、`candidate_count`；
- 地区：`protected_asia_count` 与 `region_hint_counts.HK/JP/KR/SG/TW/unknown`；
- 来源：configured/healthy/last_good/observing/confirmed_missing/failed；
- GitHub 检查：passed/failed/bypassed_asia；
- 门禁：previous counts、retain ratios、source quorum、`publish_gate.passed/reasons/policy_version`。

profile、metadata 与 status 必须由同一 staging model 一次生成，status 最后写入；禁止分别重跑统计。

## 4. 来源健康与 last-good reducer

来源状态以稳定 source ID 为 key。每轮输入为当前抓取结果、上一版已验证 metadata/profile 和当前时间，输出新状态：

| 当前事件 | 新状态 | 候选处理 |
|---|---|---|
| 抓取/解析成功 | `healthy` | 使用当前内容，更新 last-success |
| HTTP/429/Timeout/解析失败，last-good ≤48h | `using_last_good` | 从上一版 profile+metadata 继承该来源候选 |
| 同上但 last-good >48h | `observing_failure` | 整体来源 quorum/掉量门禁决定 fail-closed，不把候选标为消失 |
| 成功抓取且候选缺失 | 保持健康并增加 success-missing observation | 只有满足 3 次、6h 间隔、48h last-seen 才 confirmed missing |
| 之前失败后成功 | `recovered`/`healthy` | 当前内容重新进入合并，错误 streak 清零 |

同一候选有多个来源时，任一来源仍健康或使用有效 last-good 就不算 source disappeared。confirmed missing 是候选级所有 provenance 的综合结果，不由单个源单方面删除共享候选。

## 5. 去重与 provenance 合并

处理顺序：配置验证 → identity → 按内部 fingerprint 分桶 → 合并字段 → 选择稳定显示别名 → 输出。

合并规则：

- set 字段取排序后的并集；
- `first_seen_at=min`、`last_seen_at=max`；
- `protected_asia=any`；
- `github_check_state` 保留每来源证据并投影为明确枚举，不能让 `failed` 覆盖其他来源的 `bypassed_asia/passed`；
- 显示名只从安全别名中确定，输入重排不改变选择；
- metadata 中不保存内部 fingerprint。

`subscribe/workflow.py::exists` 必须遍历全部任务；proxy 层和任务层去重分别测试，不能依赖最终 proxy 去重掩盖重复执行成本。

## 6. 亚洲提示与 GitHub 检查

地区证据分强弱：显式 `ASIA-KEEP`/国家专用来源/完整国家或机场代码为可靠提示；模糊短词为无效。识别器是单一 owner，TCP 和 reachability 只消费其结果。

最终 metadata 明确区分：

- `passed`：实际执行 GitHub 检查且通过；
- `failed`：实际执行且失败，不进入最终 profile；
- `bypassed_asia`：因亚洲宽池策略没有执行该检查，仍进入 profile。

这避免把候选池误写成“全部活跃节点”。

## 7. 探索配额

`select_airport_domains()` 使用稳定排序和三个桶：known-good 60%、untried 20%、due-retry 20%。192 上限对应初始目标 115/38/39（余数按 due-retry、untried、known-good 的固定顺序分配）；桶不足时才按固定顺序外溢。测试覆盖 0、1、191、192、193 和 known-good 远超上限。

## 8. 发布门禁与失败关闭

门禁比较经过完整验证的 previous v2 snapshot：总量 60%、亚洲 70%、五地区各 50%、previous 非零地区不得归零、来源 quorum 80%。所有比例使用向上取整的整数边界。

previous ref 状态分为：

- `confirmed_absent`：允许首发；
- `present_and_valid`：可比较；
- `temporarily_unreadable` / `malformed` / `hash_mismatch`：失败关闭。

staging 任一步失败都不生成可发布目录。C5 接入后才负责远端 CAS 与 smoke；C1 先提供纯 validator 和默认关闭的 workflow stage。

## 9. 安全设计

- C1 是候选生成时 endpoint 安全校验 owner：先做字符串/IP 校验，域名解析全部 A/AAAA 且均为可接受公网地址，记录检查版本/时间但不公开 IP。一次运行使用共享 resolution session 按 hostname 复用成功结果；目标 `EAI_AGAIN/EAI_FAIL` 有界重试耗尽后，用同一 system resolver 检查三个独立公共 canary（至少两个健康）并再观察一次目标。目标仍失败时只记为候选级 quarantine；canary 不足、普通 resolver 异常或候选级 DNS 异常超过版本化比例上限时整轮失败。canary 只用于决定错误作用域，绝不用于接受目标地址。
- C2 是 probe 启动前重解析 owner；C5 是工作流网络层 deny 和 Secret 隔离 owner。DNS rebinding 存在 TOCTOU，C1/C2 的解析校验不能替代 C5 对 loopback/private/link-local/metadata 的网络阻断。
- 收集/探测 job 使用只读权限，不注入正式分支 token；发布 job 不访问原始订阅。
- 公共 JSON 使用字段 allowlist，异常只输出安全 category/source ID，不输出原始 URL/错误。
- `GMGN_IDENTITY_HMAC_KEY` 只注入受控 identity producer/validator；`GMGN_IDENTITY_KEY_VERSION` 与 `GMGN_IDENTITY_EPOCH` 是必填版本字段，缺失或未知迁移路径时失败关闭。
- identity stage 只读取安全 staging snapshot 与 `tests/fixtures/gmgn_identity_v1.json` 固定非秘密向量，不运行 collection/subscription/Mihomo，也不持有发布 token。publisher 只读取已校验且 hash 固定的三件套，不持有 HMAC key。
- 本机 fixture、下载和生成产物全部落在 `D:\xiangmu\linshi\github-candidate-provenance-v2`。

## 10. 兼容与回滚

V2 由显式开关控制且默认关闭。实现期保留现有 v1 生成路径；只有 C5 完成事务发布与远端 smoke 后才允许改变自动化入口。关闭 V2 不需要删除状态或分支，previous v1 仍是 last-good。
