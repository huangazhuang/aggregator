# GMGN 真实地区选择与分组实施计划

## 1. 实施顺序

1. **冻结依赖接口**
   - 读取并固定 C1 candidate metadata、C2 valid-run summary、C3 history/identity fixtures。
   - 定义 region cache、selection result、reason code 和 node-status schema；未知版本失败关闭。
2. **实现地区适配器与 cache**
   - 复用 `subscribe/location.py` 的 per-proxy 监听思路，抽出可 mock 的 provider adapter。
   - 实现 7 天 TTL、历史节点 30 天 grace、conflict/unknown/stale 状态和 opaque exit ID。
3. **实现纯分层选择器**
   - 建议新增 `scripts/gmgn_region.py`、`scripts/gmgn_selection.py`。
   - 实现 14/10/16/18 边界、半程要求、至少一次响应候补和历史保护消费。
   - 保持排名和 reason code 的单一 owner。
4. **实现容量与多样性**
   - 严格层应用 exit/server/ASN/source 上限和地区覆盖 tie-break。
   - 亚洲候补在 150 以下仅标记集中度，超过 150 才按固定顺序裁剪。
5. **接入稳定名称、分组和诊断**
   - 修改 `scripts/cnb_gmgn_publish.py` 使其消费 C3 API 和选择器结果，不再从旧组名推断历史。
   - 生成十个固定组、`node-status` 与选择汇总；手动优先只含 core/flexible/non-Asia strict，全部组承载候补，并复用共享 YAML/引用校验。
6. **补齐测试和回放**
   - 更新旧五组断言为 V2 十组契约。
   - 新增地区、缓存、多样性、容量、稳定排序、脱敏和组件回放测试。

## 2. 文件所有权

- 本任务 owner：`scripts/cnb_gmgn_publish.py` 的选择/渲染路径、建议新增的 `scripts/gmgn_region.py` 与 `scripts/gmgn_selection.py`、对应测试。
- `subscribe/asia.py` 的标签识别由 C1 owner；本任务只消费其冻结证据，不复制识别表。
- `.cnb.yml`、GitHub workflow 和发布脚本由 C5 owner；本任务不得并行修改。
- identity/history/name 逻辑由 C3 owner；若接口变化，以冻结 schema 协调，不回退其他代理修改。

## 3. 目标测试

建议新增或扩展：

- `tests/test_gmgn_region.py`
- `tests/test_gmgn_selection.py`
- `tests/test_cnb_gmgn_publish.py`
- `tests/test_gmgn_component_pipeline.py`
- `tests/test_pipeline_utils.py`

最低 fixture：五地区、非亚洲、unknown/conflict、cache fresh/stale/expired；14/13/10/9、16/18 边界；一次慢响应候补；历史 bad1/bad2/bad3；150 容量；同 exit/server/ASN/source 集中；输入重排和稳定名称；公开诊断敏感字段扫描。

## 4. 验证命令

所有测试临时文件使用 `D:\xiangmu\linshi\gmgn-selection-groups-v2`：

```powershell
$TaskTemp = 'D:\xiangmu\linshi\gmgn-selection-groups-v2'
New-Item -ItemType Directory -Force -Path $TaskTemp | Out-Null
$env:AGGREGATOR_TEST_TMPDIR = $TaskTemp
$env:TEMP = $TaskTemp
$env:TMP = $TaskTemp
$env:PYTHONPYCACHEPREFIX = Join-Path $TaskTemp 'pycache'
$env:PYTHONPATH = (Get-Location).Path

python -m unittest tests.test_gmgn_region -v
python -m unittest tests.test_gmgn_selection -v
python -m unittest tests.test_cnb_gmgn_publish -v
python -m unittest discover -s tests -p 'test_gmgn_component_pipeline.py' -v
python -m unittest tests.test_pipeline_utils -v
python -m unittest discover -s tests -v
git diff --check -- scripts subscribe tests
```

Linux/CNB 集成门禁由 C5 执行固定 Mihomo：

```bash
clash/clash-linux-amd -t -d "$RUNNER_TEMP/gmgn-v2-selection" -f "$RUNNER_TEMP/gmgn-v2-build/clash.yaml"
```

## 5. Review Gate

- [ ] C1/C2/C3 fixtures 与本任务 decoder 对同一字段集合和版本有双向测试。
- [ ] 亚洲候补宽松例外没有泄漏到手动优先、核心、非亚洲或自动组。
- [ ] 80/150/20 与所有质量边界是整数精确测试，不依赖比例近似。
- [ ] 分组成员、顺序、空组和 Mihomo 内建目标行为均有测试。
- [ ] node-status allowlist 不含代理或来源凭据、真实 IP、原始错误。
- [ ] 本任务未修改 `.cnb.yml` 或触发/发布分支。

## 6. 回滚点

- 地区适配器失败：回到 cache/unknown 降级实现，不修改质量门槛。
- 选择器回归：C5 不接入新的 selection schema，继续保留上一份 V2 shadow last-good。
- 新分组 Mihomo 校验失败：停止在本地 staging，不生成可发布 bundle。
- 与 C1/C2/C3 schema 冲突：回到接口冻结步骤，通过版本升级同步 producer/consumer，禁止兼容性猜测。
