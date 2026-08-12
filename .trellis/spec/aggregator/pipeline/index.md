# Aggregator Pipeline 规范入口

本层覆盖根包的 Python 聚合与 GitHub/CNB 发布流水线。开始修改前按需读取：

- [架构与目录导航](../architecture-and-navigation.md)
- [Python 与数据契约](../python-and-data-contracts.md)
- [测试规范](../testing-guidelines.md)
- [CI 与发布安全](../ci-and-release-safety.md)
- [GMGN V2 跨层契约](../gmgn-v2-contract.md)

## Pre-Development Checklist

- [ ] 确认目标链路：传统聚合、GitHub 输出、CNB gstatic、CNB GMGN 或 FC 探针。
- [ ] 阅读对应实现与测试，列清受影响的 producer、validator、consumer 和输出分支。
- [ ] 涉及发布时先确认私密/公开目录边界、失败关闭门槛、锁与权限。
- [ ] 本机测试临时目录使用 `D:\xiangmu\linshi`。

## Quality Check

- [ ] `python -m unittest discover -s tests -v` 通过。
- [ ] JSON/YAML 可被真实解析，Clash 发布改动保留 Mihomo 配置校验。
- [ ] 公开文件和日志不含节点凭据、订阅 token、原始错误或私密运行路径内容。
- [ ] `main` 仍只快进，force push 仍仅指向明确的生成分支。
