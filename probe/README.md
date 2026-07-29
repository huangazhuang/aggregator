# 阿里云函数计算(FC)探针部署 — 5 分钟搞定

这个探针让 GitHub Actions 能从**国内机房视角**批量判断节点入口是否被墙,
在云端就剔除连不通的节点,不需要你本地跑任何东西。部署一次,永久生效。

## 一、创建函数

1. 打开阿里云函数计算控制台 https://fcnext.console.aliyun.com/ ,
   右上角地域选**国内**任意区域(推荐「华东1(杭州)」或「华北2(北京)」)。
2. 左侧「函数」→「创建函数」→ 选「**从零开始**」。
3. 配置:
   - 函数名称: 随意,例如 `cn-probe`
   - 运行环境: **Python 3.10**(或 3.9/3.12 均可)
   - 请求处理程序类型: **处理 HTTP 请求**(即 WSGI/HTTP 函数)
   - 处理程序: `aliyun_fc_probe.handler`
   - 内存: 512 MB   超时: 120 秒
4. 创建后进入函数详情。

## 二、上传代码

「代码」标签页,把本仓库 `probe/aliyun_fc_probe.py` 的内容整段粘贴进
编辑器里的 `index.py`(或新建 `aliyun_fc_probe.py` 并把处理程序改成
`aliyun_fc_probe.handler`;直接粘进默认文件最省事,记得处理程序对应文件名),
然后「部署代码」。

## 三、设置鉴权口令

「配置」→「环境变量」,新增一条:
- Key: `PROBE_TOKEN`
- Value: 自己定一个随机串(例如 `openssl rand -hex 16` 生成的),记下来。

保存。

## 四、开启 HTTP 触发器,拿到 URL

1. 「触发器」→「创建触发器」→ 类型「HTTP」。
2. 认证方式选「**anonymous(无需签名)**」(我们用上面的 PROBE_TOKEN 头做鉴权,
   足够防滥用;也可选签名认证但集成更麻烦)。
3. 请求方式勾上 `POST`。
4. 创建后会给你一个**公网访问 URL**(形如
   `https://cn-probe-xxxx.cn-hangzhou.fcapp.run` 或带路径的地址),复制它。

## 五、把 URL 和口令填进 GitHub

到 huangazhuang/aggregator 仓库 →「Settings」→「Secrets and variables」→
「Actions」→「New repository secret」,新增两条:
- `PROBE_URL`  = 第四步拿到的公网 URL
- `PROBE_TOKEN` = 第三步设的口令(和 FC 环境变量里的**完全一致**)

## 六、验证

仓库「Actions」→「Clash Verge Auto」→「Run workflow」手动跑一次。
跑完在这次运行的 Summary 里应看到:
`cn-check(FC): N endpoints, ... ` 且 `dropped X GFW-blocked, kept Y/Z`。
看到 `(FC)` 字样就说明 GitHub 已启用你的自建探针。未配置 `PROBE_URL`
时会直接跳过中国侧预筛选，不会调用 Globalping。

这是可选的 TCP 入口预筛选，和 CNB 的 Mihomo 协议级实测互为补充：

- SS、SSR、Snell、HTTP、SOCKS5、VMess、VLESS、Trojan、AnyTLS 等 TCP 入口都会测试。
- TUIC、Hysteria、Hysteria2 依赖 UDP，不参与 TCP 探测，也不会因此被删除。
- TCP 成功连接、明确拒绝或连接重置，都能证明请求已到达入口，按可达处理。
- 超时、DNS 失败、网络/主机无路由以及未知 `OSError` 按不可达处理；响应中的 `classifications` 会汇总分类结果。

## 成本

FC 每月有免费额度(约 100 万次调用 + 一定 CU 资源),本探针每天最多几次、
每次几秒,**基本落在免费额度内,月账单几乎为 0**。担心的话可在 FC 控制台
设「预留实例=0」(纯按量)并给函数设并发上限。

## 排错

- Summary 显示 `FC probe failed (...)`: 检查 PROBE_URL 是否可公网访问、
  PROBE_TOKEN 两边是否一致、触发器是否允许 POST。失败会自动回退到不剔除
  (fail-open),订阅不会被清空。
- 想临时停用自建探针: 删掉仓库的 `PROBE_URL` secret，GitHub 会跳过中国侧
  预筛选，后续 GMGN、Google、YouTube 三站点严格筛选仍会照常执行。

## 测试

探针错误分类和协议跳过列表由仓库单元测试覆盖：

```bash
python -m unittest tests.test_probe_classification -v
```
