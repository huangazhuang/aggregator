# GMGN 测量有效性与并发标定实施计划

## 1. 执行顺序

1. **冻结 schema/fixture**
   - 建立 manifest v3、private selection v2、redacted fragment v3、sample/summary/control/canary/egress 和 validity result fixture；显式绑定 identity key version 与 identity epoch。
   - 接入 C1 双 hash 与 C3 candidate ID fixture，不复制 identity 算法。
   - 实现 controlled identity preflight，比较固定 fixture 四类 public IDs，并冻结 key 只存在于该 stage 的 workflow contract。
2. **重构统计与错误分类单一 owner**
   - 从 `scripts/cnb_gmgn_shadow.py` 抽取 sample reducer、严格守恒 validator 和 R4 error enum。
   - 将真实 controller health 与 per-proxy controller request 分开。
3. **实现 900 秒 scheduler**
   - 注入 clock/sleeper；实现 round-0 anchor、19 个 pacing slot、round barrier 和每 candidate 20 次/span 校验。
   - 保留轮内并发和稳定 rotation，不实现 early stop。
4. **扩展 prepare/partition/runtime**
   - 固定 status/profile/metadata 三件套，验证双 hash/映射。
   - 按 candidate ID 稳定四分片，manifest 记录 runtime hash、stagger、policy/canary；在任何 Mihomo 启动前执行全部 shard endpoint 重解析安全门禁。
   - 实现可复用的 network-guard policy/launcher/self-test：固定安全解析，阻断私网/link-local/CGNAT/Runner 内网/metadata，并在 backend 不可用或自检失败时 fail-closed；C5 只负责 `.cnb.yml` 隔离原语和调用顺序。
5. **实现 per-shard control/canary/egress**
   - 前后出口、每轮 control/canary、Mihomo `/version` 健康写入独立结构；公开出口标识只调用 C3 `exit_id` API。
   - 原始 IP/日志只留私密目录。
6. **实现 `validate_run`**
   - 按 policy v1 精确门槛判断完整性、观察窗、出口、control/canary、403/429 和跨片可比性。
   - 无效运行只输出安全 reasons，不写 accepted measurement。
7. **并发 benchmark**
   - 添加 8/16/24/32 非发布模式、证据 schema 和比较器；默认保持 16。
8. **验证与 C5 交接**
   - 运行 fake-clock、四片组件、network guard、隐私、完整测试。
   - 交付 C5 所需 guard backend/policy/self-test、CLI 参数、accepted/rejected 文件清单和 workflow contract；不编辑 `.cnb.yml`。

## 2. 文件范围与所有权

允许修改：

- `scripts/cnb_gmgn_shadow.py`
- `scripts/cnb_mihomo_filter.py` 中可复用且不改变 gstatic 语义的 runner/controller helper；跨链路改动必须有双方回归测试
- 可新增 `scripts/gmgn_measurement.py`、`scripts/gmgn_validity.py`、`scripts/probe_network_guard.py` 或等价纯模块
- `tests/test_cnb_gmgn_shadow.py`、`tests/test_gmgn_measurement_*.py`、四片组件/benchmark 测试

禁止修改：

- `.cnb.yml` 与任何输出分支/trigger（C5 owner）。
- C1 candidate producer、C3 identity/history、C4 selector 和文档默认入口。
- `scripts/cnb_gmgn_publish.py` 的最终选择/发布逻辑；C2 只冻结其输入契约。

## 3. 最低测试矩阵

- U-20：完整 20 API calls、Timeout 后恢复、1000/1001、HTTP/category、无早退。
- U-WINDOW：fake clock、900 秒边界、round barrier、跨 candidate 并发、stagger 不替代观察窗。
- U-SHARD：N=4/5/2260/5000、输入重排、ID collision、片 hash/数量。
- C-4SHARD：prepare → 4 fake probe → merge → validate；缺/重片、source/main/policy/runtime mismatch。
- C-CONTROL：18/20、连续 3、16/20、成功差 4/5、median 容差、egress CN/非CN/region/前后变化。
- C-INCIDENT：global 2%、round 10%、controller death、candidate 高 timeout 但 control 正常。
- C-PRIVACY：路径逃逸、0600、startup failure、public exact allowlist、假 secret 扫描。
- C-NETWORK：public→private DNS rebinding、IPv4/IPv6 私网/metadata deny、controller 隔离、guard backend 缺失/self-test 失败、probe job 无发布 token。
- C-BENCH：cohort/runtime 不一致拒绝、两次/档、量化比较、不会自动改 workers。

## 4. 验证命令

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-measurement-validity'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_cnb_gmgn_shadow -v
python -m unittest discover -s tests -p 'test_gmgn_measurement_*.py' -v
python -m unittest discover -s tests -p 'test_gmgn_component_pipeline.py' -v
python -m unittest discover -s tests -v
git diff --check -- scripts tests
```

真实 CNB benchmark 由 C5/C7 在独立影子门禁执行，证据目录必须显式指定到 `D:\xiangmu\linshi\gmgn-measurement-validity\benchmark` 或受保护的 CNB 运行目录；本地单元测试不得访问真实 GMGN、IP provider 或 Mihomo 网络。

## 5. 完成门禁

- 所有 manifest/fragment/sample 字段由单一 owner 定义，producer/validator fixture 严格相等。
- 每 candidate 20 次和 900 秒由 fake clock 与组件链同时证明。
- valid-run reasons 可解释且完全脱敏；无效运行不会产生 accepted measurement。
- network guard 在任何 Mihomo 之前完成并可由 C5 工作流调用；解析漂移、backend 缺失或 deny self-test 失败均不产生 accepted/history 输入。
- benchmark 工具可重复解析证据，16 workers 未被无证据修改。
- 未修改 `.cnb.yml`、触发器或远端分支。

## 6. 回滚点

- **schema/scheduler 阶段**：v3 未集成，回退新模块即可，v2 路径不变。
- **C5 未来影子接入后**：关闭 v3 shadow 调用，保留最后一个 V2 last-good；失败/重试不提交 history。
- **workers 调整候选**：比较器只给建议，回滚为 policy v1 的 16 workers，不需要改历史数据。
