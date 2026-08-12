# Aggregator 开发规范

本目录适用于仓库根包 `aggregator`：`subscribe/`、`scripts/`、`probe/`、`tests/`、`.github/workflows/` 与 `.cnb.yml`。`manager/` 是独立子模块，使用 `.trellis/spec/manager/`，不要把其约定带入根包。

Trellis 可注入的层入口是 [pipeline/index.md](./pipeline/index.md)；本页同时保留根包的完整导航。

## 导航

| 规范 | 何时阅读 |
| --- | --- |
| [架构与目录导航](./architecture-and-navigation.md) | 判断改动应落在哪一层，或追踪 GitHub/CNB 数据流时 |
| [Python 与数据契约](./python-and-data-contracts.md) | 修改 Python、Clash YAML、状态 JSON、GMGN 分片或诊断格式时 |
| [测试规范](./testing-guidelines.md) | 新增行为、修复边界条件或调整流水线契约时 |
| [CI 与发布安全](./ci-and-release-safety.md) | 修改 GitHub Actions、`.cnb.yml`、密钥、触发器或输出分支时 |
| [GMGN V2 跨层契约](./gmgn-v2-contract.md) | 实现 candidate snapshot v2、HMAC identity、20 轮有效性、history 或 V2 事务发布时 |

## 代码入口速查

- 聚合核心：`subscribe/process.py`、`subscribe/collect.py`、`subscribe/crawl.py`、`subscribe/workflow.py`。
- 发布编排：`scripts/build_*`、`scripts/merge_clash_profiles.py`、`scripts/filter_reachability.py`、`scripts/cnb_*`。
- 公共契约工具：`scripts/pipeline_utils.py`、`scripts/cnb_diagnostics.py`。
- 国内 TCP 探针：`probe/aliyun_fc_probe.py` 与 `scripts/apply_tcp_probe.py`。
- 自动化入口：`.github/workflows/clash-verge-auto.yml`、`.github/workflows/tests.yml`、`.github/workflows/sync-cnb.yml`、`.cnb.yml`。

## 开发前检查

- [ ] 确认改动属于传统聚合、GitHub 发布、CNB gstatic、CNB GMGN 或 FC 探针中的哪条链路。
- [ ] 阅读对应实现和现有测试；README 只作说明，源码与测试契约优先。
- [ ] 若改变 JSON/YAML 字段，同时列出生产者、消费者、校验器、schema 版本和回归测试。
- [ ] 若接触发布，确认旧版产物在失败时仍会被保留，私密节点数据不会进入公开目录或日志。
- [ ] 使用 CI 的 Python 3.12 与 `requirements.lock` 作为可复现环境基线。

## 质量检查

- [ ] 运行 `python -m unittest discover -s tests -v`；本机临时目录规则见测试规范。
- [ ] 对修改的 JSON/YAML 做真实解析；生成 Clash 配置的发布链路还要保留 Mihomo 配置校验。
- [ ] 检查公开状态、诊断、README 和日志中没有节点名称、server、port、UUID、password、订阅 token 或原始错误内容。
- [ ] 检查 GitHub/CNB 权限、并发锁、分支目标与触发条件没有被放宽。
- [ ] 确认只修改根包相关文件；不要顺手修改 `manager/` 子模块或生成分支产物。
