# GMGN 稳定身份、历史与名称实施计划

## 1. 执行顺序

1. **建立 identity 测试向量和共享模块**
   - 冻结 canonical projection/encoding、非连接字段集合、candidate/server/endpoint/exit domain-separated HMAC、公开前缀、identity key version、identity epoch 与 ID 格式。
   - 提供 C1/C2 可消费的纯函数，不接入远端工作流。
   - 新增 `tests/fixtures/gmgn_identity_v1.json`，实现跨 GitHub/CNB preflight helper 和 stage Secret 边界测试。
2. **定义 history v1 schema 与严格 loader**
   - 建立完整/损坏/未知版本/旧 key fixtures。
   - 实现安全 region-cache envelope、per-node key/epoch、legacy tombstone/90天 retention 和 public field allowlist。
3. **实现 stable name allocator**
   - 处理清洗、reserved names、同名冲突、removed tombstone 和输入重排。
4. **实现纯 history reducer**
   - 归一化 C1 source、C2 measurement、C4 staged decision；每个 accepted valid run 推进 last accepted/observation，distinct SHA + 21600 秒只限制 zero-response `bad_streak += 1`。
   - 实现亚洲 bad1/bad2/bad3/remove、`<21600s` 快速响应恢复、duplicate accepted SHA 幂等和直接 source/invalid 移除。
5. **实现 bootstrap 与 key migration**
   - 从已验证旧 profile/status 保留名称并记录有限 bootstrap。
   - 当前快照节点 old/new key/epoch 一对一迁移；快照外 tombstone 保留 legacy ID，支持重现迁移与90天 audited GC；缺 legacy key/冲突失败关闭。
6. **最小 publisher adapter**
   - 在默认关闭路径中让 `scripts/cnb_gmgn_publish.py` 可读取/生成 staged history，但不改变当前 selector、组或发布行为。
   - 为 C4 冻结 proposed decision 输入，为 C5 冻结 staged/accepted 原子边界。
7. **验证与交接**
   - 运行 identity、history 五运行、stable-name、现有 publisher 和完整测试。
   - 向 C1/C2/C4/C5 交付 API、fixtures、schema/reason enums 和 migration 操作说明。

## 2. 文件范围与所有权

允许修改：

- 新增 `scripts/proxy_identity.py`、`scripts/gmgn_history.py`，分别作为唯一 identity 和 history owner
- `scripts/cnb_gmgn_publish.py` 的默认关闭 history adapter，不修改最终选择/分组
- `tests/test_cnb_gmgn_publish.py`
- 新增 `tests/test_proxy_identity.py`、`tests/test_gmgn_history.py`、`tests/test_gmgn_stable_names.py`

禁止修改：

- C1 source/candidate workflow、C2 measurement、C4 region/selection/groups。
- `.cnb.yml`、GitHub workflows、publish CAS/trigger/远端 smoke（C5）。
- 文档默认入口与 gstatic lifecycle（C7）。

若 C1/C2 同时开发，先提交/冻结 identity API；其他 worker 只 import，不回退彼此修改。

## 3. 最低测试矩阵

- Identity：固定向量、key order/name/provenance invariance、连接字段 sensitivity、四类 domain separation、exit IPv4/IPv6 canonicalization/非公网拒绝、collision 模拟、无 secret/fingerprint/IP 泄露。
- History schema：strict fields、时间/ID/SHA、recent accepted observations 3/5 与 counted_bad、坏 JSON、unknown version、region envelope、legacy retention。
- State sequence：core → bad1 → bad2 → bad3/remove → recovered；manual/flexible/core recovery。
- Accepted/counting：新 SHA `<21600s` 仍推进 last accepted 但 zero-response 不增 streak；bad1 后快速 response 立即 reset/recover；duplicate accepted SHA/retry 幂等；invalid/rejected/publish failure 才保持 previous 字节不变。
- Immediate removal：confirmed missing、invalid config；与 temporary failure 区分。
- New candidate：response=0 不创建公开节点；response≥1 创建并清零 streak。
- Names：source rename、input reorder、ranking/tier、collision、reserved/empty、removed/recovery、legacy name preservation。
- Migration：legacy bootstrap、active 节点 old/new key/epoch、快照外 tombstone 轮换/重现迁移/90天 audited GC、missing legacy key、partial map、collision、unknown schema fail-closed。

## 4. 验证命令

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-history-identity'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_proxy_identity -v
python -m unittest tests.test_gmgn_history -v
python -m unittest tests.test_gmgn_stable_names -v
python -m unittest tests.test_cnb_gmgn_publish -v
python -m unittest discover -s tests -v
git diff --check -- scripts tests
```

所有 migration/bootstrap fixture、before/after JSON 和敏感字段扫描证据写入 `$TaskTemp`；测试不得将 key、history 或 proxy fixture 写到仓库根目录。

## 5. 完成门禁

- C1/C2 实际消费共享 identity API，仓库搜索不存在第二个 fingerprint/HMAC 算法。
- history reducer/allocator 为纯函数，拒绝/失败路径不改变 previous；staged history 只有 C5 可提交。
- 五运行状态机、非计数插入、source/invalid、稳定名称和 key/schema migration 全部有自动测试。
- adapter 默认关闭，当前 GMGN 输出/分组/工作流无行为变化。

## 6. 回滚点

- **identity/history 模块阶段**：尚无 consumer 时可仅回退新模块。
- **默认关闭 adapter 阶段**：关闭 adapter 即回到 current publisher；保留 migration evidence，不删除 previous。
- **未来 V2 shadow 接入后**：identity/schema/key 任一异常都拒绝新 bundle并保留上一版 history/profile；不得以空 history 或新 key 全量重置作为回退。
