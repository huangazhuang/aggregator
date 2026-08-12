# 测试规范

## 测试框架与入口

本仓库的权威测试入口是标准库 `unittest`：

```powershell
$env:AGGREGATOR_TEST_TMPDIR = 'D:\xiangmu\linshi'
python -m unittest discover -s tests -v
```

GitHub Actions 在 Python 3.12 上执行同一 discovery 命令。不要引入只在本地 IDE 或另一测试框架下才运行的测试。

## 编写方式

- 文件命名 `tests/test_<feature>.py`，类继承 `unittest.TestCase`，测试名描述可观察行为和边界，例如 `test_1000ms_is_qualified_but_1001ms_is_slow`。
- 用小型 fixture builder 构造完整契约数据，参考 `probe_summary()`、`candidate()`、`formal_manifest()`；避免在每个测试中复制长 JSON。
- 网络、时间、随机外部响应、Mihomo 进程和文件下载使用 `unittest.mock.patch` 隔离。单元测试不得依赖真实 GitHub、CNB、GMGN、IP 定位服务或已启动的 Mihomo。
- 需要文件系统时使用 `tempfile.TemporaryDirectory(dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None)`。Windows 本机所有测试/临时产物必须落在 `D:\xiangmu\linshi`，不得在仓库或其他目录留下临时文件。
- 既断言成功输出，也断言失败关闭：异常类型/消息、输出文件未创建、旧产物未被覆盖、敏感字符串未出现。

## 改动对应的最低覆盖

| 改动 | 必须覆盖 |
| --- | --- |
| 发布门槛/排序 | 精确边界、区域上限、容量不足、上一版保留比例；参考 `test_asia_retention.py`、`test_cnb_gmgn_publish.py` |
| YAML/分组 | REALITY 引号、无效节点拒绝、嵌套组无悬空引用；参考 `test_pipeline_utils.py` |
| FC 探针 | TCP/UDP 协议分流与 socket 错误分类；参考 `test_probe_classification.py` |
| 诊断/回放 | 脱敏字段白名单、跨文件 SHA/run ID/policy 一致、CLI 回放；参考 `test_cnb_policy_replay.py` |
| GMGN schema | 20 轮、四分片、字段精确集合、计数守恒、私密路径/权限、完整合并；参考 `test_cnb_gmgn_shadow.py` |
| workflow | 权限、锁、并发、分支、触发器、私密/公开目录隔离；现有 `ShadowWorkflowTests` 直接解析 `.cnb.yml` 和 GitHub workflow |
| 订阅解析安全 | 恶意输入不得执行表达式，异常输入的既有 fail-open/fail-closed 语义保持；参考 `test_crawl_security.py` |

策略规则应以整数边界测试，不只测比例中间值：现有套件固定了 14/20 对 13/20、1000 ms 对 1001 ms、四片齐全、完整 20 轮等生产契约。

## 验证顺序

1. 开发中运行目标模块，例如 `python -m unittest tests.test_pipeline_utils -v`。
2. 修改跨层契约后运行相关生产/回放/工作流测试组合。
3. 交付前运行完整 discovery。
4. 若生成 JSON/YAML，再用 `python -m json.tool` 或 `yaml.safe_load` 做格式验证；涉及正式 Clash 输出时保留 Mihomo `-t` 验证。

## 反模式

- 通过放宽断言来接受缺片、缺字段、未完成轮次或泄露字段。
- 用真实网络“碰运气”验证选择策略。
- 只测试最终数量，不测试分组、排序、状态元数据和旧版保护。
- 在测试中使用真实订阅凭据；fixture 应使用明显的假 secret，并断言它不会出现在公开序列化结果中。
- 将临时报告、profile 或运行日志写入仓库根目录。
