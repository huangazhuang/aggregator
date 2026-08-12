# 现有代码与线上产出综合审计摘要

日期：2026-08-11

依据：

- `research/history-decisions.md`
- `research/collection-audit.md`
- `research/gmgn-pipeline-audit.md`
- `research/tests-ops-audit.md`
- 2026-08-11 对 GitHub/CNB 公开 `status.json` 和配置的防缓存只读核验

## 已经正确工作的部分

1. GitHub 对名称识别为 HK/JP/KR/SG/TW 的节点实施宽松保护：绕过普通 liveness、中国 TCP 探针和 GMGN/Google/YouTube 单轮严格过滤。
2. CNB GMGN 流水线会固定 GitHub 来源 SHA，将全部 2260 个来源候选稳定分为四片，并让每个候选执行恰好 20 轮。
3. 单轮只有 `<=1000 ms` 记为合格；慢响应与无结果分别计数，20 轮分片完整性、总数、半程和五轮块统计都有校验。
4. 当前四片各 565 个候选，耗时约 1388–1452 秒，证明 4×16 workers 在当前规模下能于约 24 分钟完成 45200 次尝试。
5. GMGN 正式输出与旧 gstatic 输出分支隔离；正式配置在推送前经过 YAML/hash/引用检查和 Mihomo 校验，上一版 GMGN profile 读取失败时基本为 fail-closed。
6. 当前策略不会为了凑满 80 自动降低主力阈值；150 是硬上限，80 只是期望容量。

## 与目标不一致的关键问题

### GitHub 候选池

- 当前线上 2260 个配置、1163 个名称亚洲候选，但只记录总量与亚洲总量，最终 profile 已失去 source/sub provenance。
- 精确配置重复为 0，但只有 1752 个唯一 `server:port`，存在 508 个同入口别名/凭据变体；配置数量不等于独立故障域数量。
- GitHub 的发布地板只检查总 `proxy_count`。某个固定亚洲源一轮失败、某地区归零时，只要剩余总量仍过线，就会覆盖上一版。
- fixed raw 亚洲源没有逐源 last-good；机场轮转优先 known-good，达到 192 个后，新来源可能长期没有探索配额。
- 亚洲名称识别缺少 `TPE/KHH/NRT/KIX/ICN/SIN` 等常见机场代码，并存在短标签误判风险。
- 当前 GMGN 输入是 GitHub 最终候选 profile，不是最原始爬取全集；这是可接受边界，但必须明确命名和统计。

### CNB 20 轮与选拔

- 当前 1163 个名称亚洲候选中，74 个至少得到一次 GMGN 响应，37 个至少一次 `<=1000 ms`，17 个达到 `>=10/20`；正式发布为 26 个（亚洲 17、非亚洲 9）。
- `ASIA-KEEP KR 012` 之类节点低于 10/20 时仍会立即消失。现有“观察保留”只对上一版 stable 且本轮 12–13/20 生效一次，主要改变标签/优先级，不是真正 2–3 次跨运行保护。
- shadow node ID 每轮随机，公开分支每次强推单一快照；没有稳定私有身份、连续失败 streak、迁移原因或 last-N 运行历史。
- `Asia` 仍由用户可控名称判断。错误标签可能得到亚洲宽松阈值，真实亚洲但名称未识别的节点会走非亚洲严格路径。
- runner 本次确实显示中国广东，但配置只保证 AMD64；没有中国/广东 fail-closed，也没有四个 probe job 的出口一致性校验。
- 发布器看不到 shadow 的全局轮次趋势和错误类型。本次 45200 次尝试有 38809 次无结果，但发布器无法区分候选整体差与 GMGN/runner/DNS/TLS 的系统事故。
- 没有出口 IP、server、ASN、来源、协议和地区多样性政策。当前 26 个结果只有 20 个唯一端点，个别端点贡献 4 个节点。
- 当前 `GMGN自动` 包含 10–13/20 的 flexible/observation 节点，不符合用户以手动复测为主、候补仅供观察的路径。

### 发布、历史和测试

- GMGN profile 的 last-good 保护较强，但 shadow 先强推、profile 后构建；若 profile B 被拒绝，shadow A 已被 B 覆盖，旧 profile A 无法再找到对应诊断。
- GitHub restore 和旧 gstatic previous-status 读取存在 fail-open：暂时失败可退化为冷启动/较低绝对地板。
- 所有公开输出分支均为 orphan 单提交强推，没有 compare-and-swap/force-with-lease，也没有发布后重新下载远端产物的自动 smoke。
- 现有 113 个单元测试已通过，强项是单轮算术、20 轮/四分片形式契约、脱敏、fragment 校验和 GMGN previous-profile 失败保护；缺少多运行历史、真实地区、稳定节点名、多样性、系统事故门禁、端到端四进程、远端发布 smoke 和 rollback canary。
- Trellis 当前默认包错误指向 `manager` 子模块，根目录 Python/CI 没有项目规范，不能直接进入 implement/check 分派。

## 外部亚洲来源结论

- `awesome-vpn/awesome-vpn`：小而更新活跃，可优先作为受控补充。
- `mahdibland/V2RayAggregator`：JP/KR 边际价值较高，但与现池重叠明显，应只引入受控亚洲子集。
- `cybersecplayground/V2Hive`：五地区 reservoir 很大，但生成/验证透明度不足且入口重复高，只适合限额发现源。
- `Epodonios/v2ray-configs`、`ALIILAPRO/v2rayNG-Config`：更新活跃但地区标签弱、重复或亚洲边际增益低，不应优先直接接入。
- 当前 CNB 最坏耗时保护在约 5000 候选附近开始紧张；新源必须先做 fingerprint、唯一入口、与现池重叠、地区和新鲜度评估。

## 规划结论

最小可行方向不是降低现有严格主力门槛，而是增加一个有容量上限、可跨运行保护、仅供手动复测的亚洲候补层；同时补齐 provenance、真实出口、多样性、系统性异常门禁和发布后校验。GitHub 继续承担宽池与来源健康，CNB 承担固定快照的 GMGN 20 轮测量和分层输出。

在确定亚洲候补的准入/移除边界后，再收敛真实出口查询范围、自动运行频率和旧 gstatic 订阅生命周期。
