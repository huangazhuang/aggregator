# 架构与目录导航

## 根包边界

| 路径 | 职责 | 代表证据 |
| --- | --- | --- |
| `subscribe/` | 订阅发现、注册、解析、过滤、转换与存储；保留可直接按文件运行的历史入口 | `subscribe/process.py`、`subscribe/collect.py`、`subscribe/workflow.py` |
| `scripts/` | 面向自动化的薄入口、筛选策略、状态生成、诊断与发布契约 | `scripts/pipeline_utils.py`、`scripts/cnb_mihomo_filter.py`、`scripts/cnb_gmgn_shadow.py` |
| `probe/` | 可选的中国大陆 TCP 可达性服务端；不替代 Mihomo 协议级检测 | `probe/aliyun_fc_probe.py`、`probe/README.md` |
| `tests/` | Python `unittest` 行为与流水线结构契约 | `tests/test_pipeline_utils.py`、`tests/test_cnb_gmgn_shadow.py` |
| `.github/workflows/` | GitHub 聚合、测试、镜像和手动入口 | `clash-verge-auto.yml`、`tests.yml`、`sync-cnb.yml` |
| `.cnb.yml` | CNB 定时/手动探测、锁、私密运行态及隔离发布分支 | `.cnb.yml` |
| `clash/`、`subconverter/` | 随仓库分发的运行时二进制、规则和模板 | `clash/clash-linux-amd`、`subconverter/base/` |

`manager/` 不参与当前聚合或测速流程；`CNB_SETUP.md` 明确要求 CNB 默认不更新该子模块。

## 主要执行流

### 传统聚合

1. `subscribe/process.py` 通过 `load_configs()` 将 `domains`、`crawl`、`groups`、`storage`、`update` 合入 `ProcessConfig`。
2. `subscribe/workflow.py` 用 `TaskConfig` 驱动机场订阅获取与解析。
3. `subscribe/clash.py` 验证、去重并生成 Clash 配置，`subconverter` 负责其他目标格式。
4. `subscribe/push.py` 按 `storage.items` 将分组结果写入目标后端。

`subscribe/collect.py` 是简化入口：收集机场、维护 `data/domain-health.json` 等跨轮状态、生成配置并可推送 Gist。

### GitHub `clash-verge-output`

`.github/workflows/clash-verge-auto.yml` 的顺序是：恢复上一轮状态 → 构建手工或爬虫配置 → 运行 `collect.py`/`process.py` → 合并 → 可选 FC TCP 预筛 → 三目标严格筛选 → 生成 `status.json` → 重建输出分支。发布逻辑应留在 `scripts/`，工作流只负责传参、权限和阶段编排。

### CNB 两条隔离链路

下列内容描述当前 V1。GMGN V2 的 candidate snapshot、HMAC identity、完整影子订阅和事务提升遵循 [GMGN V2 跨层契约](./gmgn-v2-contract.md)，在用户批准迁移前不改变这两条线上链路。

- gstatic：固定 GitHub `clash.yaml` 与 `status.json` 快照并核对时效/SHA → `scripts.cnb_mihomo_filter` 完整 20 轮 → 成功发布 `clash-cn-output`，失败仅发布脱敏 `clash-cn-diagnostics`。
- GMGN：`prepare` 固定快照并拆成四片 → 四个 `probe` 作业并行 → `merge` 只合并脱敏报告 → 私密 selection fragments 交给 `scripts.cnb_gmgn_publish` → 分别发布 `clash-cn-gmgn-shadow` 与 `clash-cn-gmgn-output`。

V1 GMGN 影子报告不是订阅；gstatic 与 GMGN 输出不得互相覆盖。V2 允许在独立 `clash-cn-gmgn-v2-shadow` 发布可导入的完整 bundle，但不得覆盖 V1/正式/gstatic 分支。证据：`.cnb.yml`、`CNB_SETUP.md`、`tests/test_cnb_gmgn_shadow.py`。

## 放置规则

- 订阅域、爬虫、机场注册或通用代理解析逻辑放在 `subscribe/`。
- 只服务 CI/CNB 的参数解析、状态生成、策略回放与发布逻辑放在 `scripts/`；跨发布链路复用优先放入 `scripts/pipeline_utils.py` 或 `scripts/cnb_diagnostics.py`。
- 外部探针协议的服务端实现放在 `probe/`，调用端适配放在 `scripts/`。
- 新自动化脚本应支持 `python -m scripts.<module>`，并保持 `main() -> int` 与 `raise SystemExit(main())`；现有 `subscribe/*.py` 依赖按文件运行和同目录导入，不能只改一半导入方式。
- 生成数据写到运行目录或输出分支，不在 `main` 提交 `data/`、`.cnb-runtime/`、`public-cn*` 产物。

## 反模式

- 在 workflow YAML 中复制大段选拔算法，导致本地回放和生产策略分叉。
- 让 `scripts/` 直接绕过 `pipeline_utils` 自行序列化 REALITY `short-id`。
- 把公开脱敏 fragment 与包含完整 proxy 的 selection fragment 放在同一目录或发布步骤。
- 为“统一风格”单独改写 `subscribe/` 的导入路径，却不同时验证按文件执行入口。
- 把输出分支的强推策略用于 `main`，或让 `manager/` 子模块成为根包流水线依赖。
