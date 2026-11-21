# TinyLane

轻量的 OpenWrt 透明代理：一个 Go 二进制（内嵌精简版 sing-box 1.14 内核 + 守护进程 + Web 面板），面向 128–256 MB 内存的小路由器（开发机：小米 AX3000T / OpenWrt 25.12，aarch64）。

> 状态：早期版本，作者自用并持续更新。接口和配置格式可能还会变。

## 特点

- **一个进程树**：procd → `tinylane daemon`（面板、看门狗、订阅、规则集、流量统计）→ 子进程 `tinylane run`（sing-box 内核）。内核崩溃不会带走面板；2 分钟内崩 3 次自动撤掉透明代理、局域网临时直连，内核稳定后自动恢复。
- **透明代理**：nftables tproxy（TCP+UDP），只接管 LAN 口进来的流量；路由器本机流量、WireGuard 等运维链路永远直连（可在编译时写死，配置删不掉）。
- **规则分流**：自定义规则（拖动排序、固定规则）、远程规则集（.srs / sing-box 源格式 .json，按计划更新）、geosite/geoip-cn；规则模式下国内 IP 直接在 nft 层绕过内核。
- **组成员规则 + 断网保护**：每个组 = 手选节点 +「只用名称含」+「排除名称含」，订阅更新后自动重算；开「断网保护」的组在成员全部不可用时宁可断开也不回落直连或其他线路（适合某些网站只允许走特定出口）。
- **看门狗**：故障切换组按优先级自动切换（延迟 + 吞吐双探测），上游整体断网时不乱切。
- **国内直连优化**：WAN 口 cake + [cake-autorate](https://github.com/lynxthecat/cake-autorate)（按延迟自动调速），直连超时可调。
- **设备**：按设备指定模式、访客（只直连）、拉黑、踢下线、Wi‑Fi 信号、24 小时连接历史、按设备今日流量（独立 nft 计数表，含直连流量）、新设备默认访客。
- **访客 Wi‑Fi**：独立 SSID + 独立网桥/防火墙区，只能上网、与 LAN 隔离；应用后自检主 Wi‑Fi 和运维链路，失败自动撤回。
- **导入 / 高级模式**：Clash YAML、sing-box JSON、分享链接 / Base64、Clash 规则行、域名列表、整份配置——先预览后应用；原始 JSON 编辑带完整校验和 90 秒未确认自动回滚。
- **面板**：Apple 风格（iOS 设置式分组列表、大标题、毛玻璃导航/标签栏、iOS 开关和分段控件、弹簧动效、浅色/深色/跟随系统），单文件 gzip 后约 36 KB 内嵌进二进制；与 LuCI 单点登录（root 密码 / LuCI 会话）。

## 目录

| 路径 | 内容 |
|---|---|
| `src/cmd/tinylane/` | 主程序（放进 sing-box v1.14.4 源码树的 `cmd/tinylane` 编译） |
| `src/include/` | 精简的协议注册表（只注册用到的入站/出站/DNS） |
| `web/` | 面板源码：`app.tpl.html` + `_proto.css` + `app.extra.css` + `apple.css` + `app.js` + `app.m6.js`，`assemble.py` 拼成 `app.html` |
| `files/` | 装到路由器的文件：init 脚本、nft / 整形 / 访客 Wi‑Fi 脚本、死人开关 `tinylane-safe-apply`、LuCI 菜单、示例配置 |
| `test/` | 沙盒测试（API、截图交互） |

## 编译

```sh
# 需要 Go 1.27+ 和 sing-box v1.14.4 源码（build.sh 里的 SB= 路径）
OUT=out/tinylane-linux-arm64 GOARCH=arm64 sh build.sh
# 可选：把运维链路写死进二进制（逗号分隔），放在不进仓库的 secret/build.env：
#   TL_BUILTIN_BYPASS=203.0.113.10/32,10.0.0.0/24
```

必须的编译标签：`with_quic,with_clash_api,with_gvisor,with_utls`（VLESS reality / client-fingerprint 需要 utls）。

## 安装（概要）

1. 依赖：`kmod-nft-tproxy`、`dnsmasq-full`（或 dnsmasq）、`curl`、`ca-bundle`；可选 `kmod-sched-cake kmod-ifb tc-tiny fping`（智能限速）。
2. 二进制放 `/usr/bin/tinylane`，`files/` 按原路径放好，配置参考 `files/etc/tinylane/tinylane.json.example`。
3. 首次启动用死人开关：`tinylane-safe-apply 5`（5 分钟内不 `tinylane-safe-apply confirm` 就自动回到普通路由）。
4. 面板：`http://<路由器 LAN IP>:9999`，或 LuCI「服务 → TinyLane」。

## 常用命令

```sh
tinylane check -c /var/run/tinylane/config.json   # 校验内核配置
tinylane gen -i /etc/tinylane/tinylane.json -o sb.json --nft t.nft
tinylane conns '主线路'                           # 某组的当前连接
tinylane mode rule|global|direct
tinylane config-set guest_wifi.check_ping 10.0.0.1
```

## 致谢与许可

- [sing-box](https://github.com/SagerNet/sing-box)（GPL-3.0-or-later）：内核。TinyLane 与其静态链接，因此整体按 **GPL-3.0-or-later** 发布（见 LICENSE）。
- [cake-autorate](https://github.com/lynxthecat/cake-autorate)（GPL-2.0，`files/usr/share/cake-autorate/LICENCE.md`）。
- 面板外观参考 [gotired/apple-design-skills](https://github.com/gotired/apple-design-skills) 的 HIG→Web 映射和系统色值（只借鉴规则和数值，未复制其代码）。与 Apple Inc. 无关。
- TinyLane 是独立项目，与 sing-box 官方无关，也未获其认可。

## 发布前待办

- [x] LICENSE：GPL-3.0-or-later（11-21 定）。
- [x] 示例配置、注释和面板文案已换成通用说法。
- [ ] CI：GitHub Actions 交叉编译 arm64 / armv7 / mipsle，并预编译 .srs。
- [ ] 截图用演示数据重新生成（不要用真实设备/节点名）。
