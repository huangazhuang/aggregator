# Python 与数据契约

## Python 约定

- CI 使用 Python 3.12，并以 `requirements.lock` 安装完整依赖；修改依赖时同步维护 `requirements.txt` 与锁文件。证据：`.github/workflows/tests.yml`、`clash-verge-auto.yml`。
- 新的 `scripts/` 模块沿用 `from __future__ import annotations`、`pathlib.Path`、`dict[str, Any]`/`list[...]` 类型标注和小型可测试函数。参考 `scripts/pipeline_utils.py`、`scripts/cnb_policy_replay.py`。
- 可恢复的可选元数据可以告警并返回空映射，如 `load_optional_json()`；决定是否覆盖旧订阅的输入、manifest、fragment 和旧 profile 必须抛错并失败关闭。
- 文件统一用 UTF-8；JSON 写入使用 `ensure_ascii=False` 并保留结尾换行。涉及同一发布契约的多阶段文件优先使用临时文件替换，参考 `write_json_atomic()` 与 `write_text_atomic()`。

## 聚合配置契约

`subscribe/config/config.default.json` 定义四个顶层域：

- `domains`：订阅或机场任务；至少保持 `name`、`sub`/`domain`、`enable`、`push_to`、过滤与 liveness 字段的语义。
- `crawl`：爬虫开关、公共过滤、持久化键及 Telegram/GitHub/搜索/页面/脚本源。
- `groups`：输出分组及 `targets` 到 storage item 的映射。
- `storage`：后端 `engine`、公共参数和 `items`。

`subscribe/process.py::load_configs()` 会合并多份配置并构造 `ProcessConfig`；`subscribe/workflow.py::TaskConfig` 是运行时任务边界。新增字段必须同时检查配置解析、任务构造、README 示例和实际消费者，不能只更新默认 JSON。

## Clash YAML 契约

- 源文档必须是 YAML mapping，`proxies` 必须是非空的 mapping 列表；发布前过滤非 mapping 项。参考 `scripts.cnb_mihomo_filter.load_profile()`。
- 节点最小身份字段是 `name`、`type`、`server`、`port`；GMGN 私密 fragment 会逐项校验这些字段。
- 会原地规范化节点的共享校验器必须保持幂等：同一合法节点连续校验两次仍应通过。`subscribe.clash.verify()` 可能把 REALITY `short-id` 包装成 `QuotedStr` 以保证 YAML 引号，因此类型判断必须接受 `str` 子类，同时继续执行十六进制、偶数长度和最多 16 位检查。回归测试至少覆盖一次校验后的二次校验，以及奇数、非十六进制和超长值仍被拒绝。
- 代理名在运行配置中必须唯一；分组引用只能指向已选节点、其他组或 `DIRECT`/`REJECT` 等内建目标。使用 `unique_proxy_names()` 与 `filtered_profile()`，不要手写易残留悬空引用的过滤。
- REALITY `reality-opts.short-id` 必须是偶数长度、最多 16 位的十六进制字符串，并通过 `dump_clash_yaml()` 强制带引号；无效节点在启动 Mihomo 前拒绝。证据：`scripts/pipeline_utils.py`、`tests/test_pipeline_utils.py`。
- 生成后至少用 `yaml.safe_load` 回读；GMGN 正式发布还在 `.cnb.yml` 中执行 `clash-linux-amd -t`。

## Scenario: Clash 字符串子类与序列化失败脱敏

### 1. Scope / Trigger

- 任何经 `subscribe.clash.verify()` 后再进入 `dump_clash_yaml()` 的 GitHub/CNB profile 都适用。
- `verify()` 会把数字外观的认证字段和 REALITY `short-id` 包装成 `str` 子类；模块既可能以 `clash` 也可能以 `subscribe.clash` 导入，不能依赖某一个具体类对象。

### 2. Signatures

- `dump_clash_yaml(profile: dict[str, Any]) -> tuple[str, list[str]]`
- 失败统一抛出固定、无私密值的 `ClashYamlSerializationError`；Candidate CLI 再转换为本领域固定错误和退出码 `1`。

### 3. Contracts

- 内建 `str` 继续使用 `yaml.SafeDumper` 的默认标量样式。
- 任意 `str` 子类必须通过 `ClashSafeDumper.add_multi_representer(str, ...)` 显式双引号输出。
- 数字外观认证值（如 `08`、`521314`）和 REALITY `short-id` 回读后必须仍为 `str`，值保持不变。
- serializer 异常不得把原对象、proxy credential 或底层 `RepresenterError` 链写入 stderr/Actions/CNB 日志。

### 4. Validation & Error Matrix

| 条件 | 结果 |
| --- | --- |
| 内建普通字符串 | 保持默认 YAML 风格 |
| `QuotedString`、任意 collector `QuotedStr` 或其他 `str` 子类 | 显式双引号并可安全回读 |
| REALITY `short-id` 非偶数十六进制或超过 16 位 | 在 Mihomo 启动前拒绝节点 |
| PyYAML 无法表示任意对象 | 固定 `ClashYamlSerializationError`，`__cause__`/`__context__` 不含原异常 |
| Candidate sanitizer/snapshot 序列化失败 | 固定领域错误、CLI 返回 `1`、不创建输出文件 |

### 5. Good/Base/Bad Cases

- Good：HTTP `username="08"`、`password="521314"` 经 `verify → dump → safe_load` 后仍是同值字符串。
- Base：普通节点名、server 和规则字符串按原有默认样式输出。
- Bad：只为某个 `QuotedStr` 精确注册 representer；另一模块名产生的同义子类会落入 PyYAML `represent_undefined`。

### 6. Tests Required

- 共享 serializer：内建 `str`、项目 `QuotedString`、collector `QuotedStr`、任意 foreign `str` 子类。
- 全链路：sanitizer 与 snapshot 分别覆盖数字 HTTP 认证字段和 REALITY `short-id`。
- 失败链：注入带假 secret 的 `RepresenterError`，断言固定消息、空 cause/context、stderr 无 secret、输出目录不存在。
- 继续运行 YAML 回读、完整 `unittest` 和 `git diff --check`。

### 7. Wrong vs Correct

#### Wrong

```python
ClashSafeDumper.add_representer(SomeImportedQuotedStr, quoted_scalar)
```

这只识别完全相同的类对象；`clash.QuotedStr` 与 `subscribe.clash.QuotedStr` 可以是两个类。

#### Correct

```python
ClashSafeDumper.add_multi_representer(str, quoted_scalar)
```

PyYAML 会先匹配内建 `str` 的精确 representer，再让所有字符串子类走显式引号路径。

## 状态与快照

- GitHub `clash-verge-output/status.json` 由 `scripts/prepare_github_publish.py` 生成，`profile_sha256` 必须对应发布的确切 `clash.yaml` 字节，并记录 `run_at`、`proxy_count`、`main_sha` 等来源信息。
- CNB 下载 source status 与 profile 时必须加防缓存标识，检查时间窗口并核对 SHA 后再固定到本轮目录；不要分别读取后直接假定属于同一轮。
- 上一版状态是发布保护输入。读取失败、计数不一致或 profile SHA 不一致时，正式 GMGN 发布拒绝覆盖，参考 `load_previous_profile()` 和 `tests/test_cnb_gmgn_publish.py`。

## Scenario: GitHub Candidate V1 亚洲基线迁移

### 1. Scope / Trigger

- 从没有 metadata 的 `clash-verge-output` V1 profile/status 首次迁移到 Candidate V2 时适用。
- V1 的 `protected_asia_count` 使用 `is_preferred_asian_proxy()` 逐节点计算；HK/JP/KR/SG/TW 提示使用 `preferred_asia_region_hints()`，两者不是同一个集合。

### 2. Signatures

- `validate_legacy_candidate_baseline(profile_bytes, status) -> baseline`
- `_validate_legacy_candidate_baseline_summary(value) -> normalized baseline`

### 3. Contracts

- profile SHA、`proxy_count` 与 status 必须严格绑定；显式 status `protected_asia_count` 必须等于绑定 profile 的独立重算值。
- `sum(HK, JP, KR, SG, TW) <= protected_asia_count <= candidate_count`。
- `protected_asia_count - sum(HK, JP, KR, SG, TW) <= unknown`；差额表示受 `ASIA-KEEP`、旗帜等保护但不能安全归入具体地区的节点。
- 差额继续计入 70% 亚洲总量基线，但不得计入任一地区的 50%/不得归零基线。
- 该兼容关系只属于 `legacy_v1`；V2 仍从 metadata 逐项重算并严格绑定 status。

### 4. Validation & Error Matrix

| 条件 | 结果 |
| --- | --- |
| 具体五区合计小于 protected，差额可由 unknown 容纳 | 接受 legacy baseline |
| 具体五区合计大于 protected | `legacy candidate baseline Asia counts are inconsistent` |
| protected 与绑定 profile 独立重算不符 | `legacy candidate protected Asia count is invalid` |
| profile/status SHA、count 或 baseline binding 被篡改 | 失败关闭 |

### 5. Good/Base/Bad Cases

- Good：`JP` + `ASIA-KEEP generic` + global，protected=2、JP=1，未知桶包含 generic 和 global。
- Base：所有 protected 节点都有具体地区提示，五区合计等于 protected。
- Bad：为消除差额而把 unknown 硬归到 KR/JP，或把 protected 降为五区合计；两者都会削弱对应掉量保护。

### 6. Tests Required

- marker-only 和带亚洲旗帜的状态文本可以迁移，但仍位于 unknown。
- 亚洲 70% 总量与具体地区 50%/不得归零门禁在差额存在时仍执行。
- 五区和大于 protected、status/profile protected 不一致、SHA/count/baseline binding 篡改均拒绝。

### 7. Wrong vs Correct

#### Wrong

```python
sum(region_counts[region] for region in REGION_ORDER) == protected_asia_count
```

#### Correct

```python
hinted <= protected_asia_count
protected_asia_count - hinted <= region_counts["unknown"]
```

## GMGN schema 契约

- 下列 schema 2/随机诊断 ID 是当前 V1 现状。实施 GMGN V2 时必须改用 [GMGN V2 跨层契约](./gmgn-v2-contract.md) 的 snapshot v2、manifest v3、HMAC identity 和原子 bundle；不得把 V1 现状误当成禁止升级的永久约束。
- 正式 manifest：`kind=cnb-gmgn-shadow-manifest`、schema 2、恰好 4 个 shard、20 轮、3000 ms 请求上限、1000 ms 达标线、HTTP 200 的 `https://gmgn.ai/`。
- 每个 fragment 必须与 manifest 的 `run_id`、`main_sha`、`source_sha256`、目标参数、shard index、profile SHA、节点数完全一致；四片缺一、重复节点名或统计和不守恒均拒绝合并。
- schema 的字段集合是严格相等校验。新增/删除字段时必须同步 producer、字段常量、validator、publisher、schema version（若不兼容）及测试，不能依赖消费者忽略未知字段。
- 计数必须守恒：`response + no_result = attempts`，`within_limit + slow = response`，前后半轮和四个五轮窗口必须与总达标数一致。参考 `normalize_summary()`、`validate_shadow_result()`。

## 公开与私密数据

- 私密 selection fragment 含完整 `proxy`，只能位于含 `.cnb-runtime` 的私密根下，不能位于 `.git` 或 `public-cn*`；写入模式为 `0o600`，CNB 阶段使用 `umask 077`。
- V1 公开 shadow/diagnostic 逐节点数据只允许随机 `node_id`、`preferred_asia` 与聚合次数/延迟指标。V2 改为带版本/epoch 的 HMAC stable ID，但仍禁止 server、port、UUID、password、原始错误、逐轮样本、裸 fingerprint、原始出口 IP 和 runner 公网 IP。
- 启动失败信息不得回显 Mihomo 私密日志尾部；`scripts.cnb_gmgn_shadow.wait_for_shadow_mihomo()` 使用内容抑制消息，测试会检查凭据不出现在异常中。
- `failure.json` 保持小型摘要，并以安全的同级 basename 引用 `redacted-probe-results.json`；回放加载器要核对 run ID、SHA、结果数和 policy 完全一致。

## 反模式

- 用 `yaml.dump` 直接发布含 REALITY 节点的配置。
- 为兼容坏输入静默补齐 GMGN 缺失字段或不完整轮次。
- 把“80 个期望容量”误作无条件发布下限，或为了凑数降低质量线。
- 把原始节点或凭据写入诊断、公开 status、README、异常文本或 CI summary。
- 更改 schema 但不更新契约测试，或只更新生产选择器而不更新离线回放器。
