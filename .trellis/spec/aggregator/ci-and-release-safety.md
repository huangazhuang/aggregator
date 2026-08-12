# CI 与发布安全

## 流水线与权限边界

| 流水线 | 权限/并发 | 允许写入 |
| --- | --- | --- |
| `.github/workflows/tests.yml` | `contents: read`，同 ref 新运行取消旧运行 | 不发布 |
| `clash-verge-auto.yml` | `contents: write`，单一 `clash-verge-auto` 并发组 | 仅重建 `clash-verge-output` |
| `sync-cnb.yml` | `contents: read`，同步任务排队且不互相取消 | CNB `main` 快进；可推唯一触发 tag |
| `.cnb.yml` gstatic | 独占锁 `aggregator-mainland-probe` | `clash-cn-output`；失败时仅 `clash-cn-diagnostics` |
| `.cnb.yml` GMGN | 独占锁 `aggregator-gmgn-shadow` | `clash-cn-gmgn-shadow` 与 `clash-cn-gmgn-output` |
| `.cnb.yml` GMGN V2 rollout | 独立 source-SHA 锁与 CAS/lease | 迁移前仅 `clash-cn-gmgn-v2-shadow`，以及非订阅的 `clash-cn-gmgn-v2-processed/<source_sha>` 单文件状态 ref；用户批准后提升同一 bundle 到 `clash-cn-gmgn-output` |

修改 workflow 时保持最小权限。需要删除历史 Actions 的第三方 action 必须像 `.github/workflows/delete.yaml` 一样固定到 commit，不能跟随可变的 `main` 标签。

## 密钥与认证

- 订阅 URL、token、账号配置只放 GitHub/CNB Secret，不放 repository variable、提交文件、step summary 或命令回显。证据：`CLASH_VERGE_AUTO.md`、`CNB_SETUP.md`。
- GitHub 到 CNB 使用 `scripts/cnb_git_askpass.sh`、`GIT_ASKPASS` 与 `GIT_TERMINAL_PROMPT=0`；不要把 token 拼到 remote URL。
- `checkin.yml` 仅把 `CHECKIN_CONFIG_JSON` 写入运行时配置，未配置时跳过；不得把生成的 `.github/actions/checkin/config.json` 作为发布产物。
- 手工订阅模式禁止发布 `subscribes.txt`，因为 URL 可能含私密 token；`clash-verge-auto.yml` 已有显式跳过逻辑。

## 分支与触发器

- `main` 只允许正常快进。GitHub 手动同步必须从 `refs/heads/main` 运行；CNB/GitHub 镜像分叉时失败，不得用 `--force` 掩盖。
- `git push --force` 仅用于从临时 git 仓库或 orphan worktree 重建生成分支；绝不能复用于 `main`。
- CNB 手动探测通过唯一的 `cnb-probe-*` 或 `cnb-gmgn-shadow-*` tag 触发；tag 只推往 CNB，不回写 GitHub。
- GMGN V2 processed ref 只允许脱敏 `state.json`，使用 observed tip 的 force-with-lease；不得把它当订阅或用 tag-only 状态替代 CAS registry。accepted 只由 authoritative V2 bundle/history 宣告。
- 不要移除同步队列或 CNB 独占锁。它们防止定时与手动任务并发强推同一输出分支。

## 发布前保护

- 测试必须先于聚合/发布执行；`clash-verge-auto.yml` 在生成 profile 前运行完整 `unittest`。
- 隔离的发布/远端 smoke job 若只安装最小 Python 依赖，必须覆盖其可信入口的完整传递顶层 import closure；主测试 job 安装完整 `requirements.lock` 并不能证明隔离 job 可运行。入口或其顶层导入变化时，同步更新该 job 的固定版本依赖和 workflow 契约测试；至少实际执行一次入口（如 `python -m scripts.validate_public_outputs ...`），不能把 `setup-python` 或单独安装 `PyYAML` 当成运行时验证。
- 来源必须固定：状态时间在允许窗口内，`profile_sha256` 与实际 profile 完全一致。检查失败时等待新快照或终止，不能继续使用上一轮输入冒充新结果。
- 发布必须失败关闭：节点数低于绝对/保留比例门槛、轮次不完整、Mihomo 退出、分片缺失、旧 profile/status 不一致或目标检查异常时，不覆盖最后一版可用订阅。
- GitHub 严格筛选要求普通节点同时通过 GMGN、Google、YouTube；目标整体不可用时应失败，而不是把所有节点当失败后发布空/极小配置。
- GMGN 正式 profile 在发布前通过 YAML 回读和 `clash-linux-amd -t`。V1 公开 shadow 报告与可导入 profile 保持分支隔离；V2 按 [GMGN V2 跨层契约](./gmgn-v2-contract.md) 在独立 V2 shadow 分支发布同构的原子 bundle，rejected diagnostics 仍必须与 current bundle 隔离。

## 失败诊断

- gstatic 正常发布阶段失败后，`failStages` 只能复制 `failure.json` 与 `redacted-probe-results.json` 到诊断分支。
- 诊断发布失败不得吞掉原始失败；`.cnb.yml` 先保存 `push_rc`，只打印 warning，最终任务仍保持失败语义。
- 不得将 `mihomo-runtime.yaml`、私密 selection fragments、节点凭据、原始错误或 runner IP 复制到诊断/影子分支。
- `.cnb-runtime/`、`public-cn/`、`public-cn-shadow/`、`public-cn-gmgn/` 必须保持在 `.gitignore`，新增私密运行目录也应具备等价保护。

## 发布改动检查表

- [ ] 权限是否仍为完成任务所需的最小集合？
- [ ] `main` 是否仍只快进，force push 是否只指向明确的生成分支？
- [ ] Secret 是否通过环境/askpass 注入且不会出现在日志和公开文件？
- [ ] 并发组、CNB lock、timeout 与触发分支是否仍能阻止冲突发布？
- [ ] 新状态字段是否与 profile SHA、source SHA、main SHA 和 schema 测试同步？
- [ ] 每个隔离 Python job 是否安装了其实际入口的完整 import closure，并由 workflow/入口 smoke 测试锁定？
- [ ] 所有失败路径是否保留旧订阅，并且诊断仍完全脱敏？

## 反模式

- 为了“保证更新”在 main 同步或正式发布输入校验失败时强推。
- 将 GitHub Secret 改为 Variable，或在 shell 中打印完整环境变量。
- 在四片未全部完成时发布半份 GMGN 结果。
- 让诊断阶段成功覆盖前面失败状态。
- 将 gstatic、V1 GMGN 和 V2 rollout 混写到同一分支；或在 V2 内把 rejected run 诊断覆盖到 current bundle。
