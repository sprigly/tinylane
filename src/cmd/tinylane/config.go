package main

// TinyLane 自有配置（/etc/tinylane/tinylane.json）。
// 设计原则：字段尽量少、全部有默认值；节点直接内嵌 sing-box 出站 JSON（不重复造协议字段），
// 这样任何 sing-box 支持的协议参数都能用，校验交给 sing-box 自己。

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type Config struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`         // rule | global | direct（初始值；运行中可经 clash_api 切换）
	GlobalGroup string `json:"global_group"` // 全局代理模式走哪个组，默认 main_group
	MainGroup   string `json:"main_group"`   // 规则模式 final 组
	LogLevel    string `json:"log_level"`

	LAN struct {
		Iface string   `json:"iface"` // br-lan
		CIDR  []string `json:"cidr"`  // 192.168.1.0/24
	} `json:"lan"`

	TProxyPort  int    `json:"tproxy_port"`  // 7893
	MixedListen string `json:"mixed_listen"` // 127.0.0.1:7890，"" = 不开
	DNSPort     int    `json:"dns_port"`     // 1053（dnsmasq 上游）
	FwMark      int    `json:"fwmark"`       // 0x7a
	RouteTable  int    `json:"route_table"`  // 100

	ClashAPI struct {
		Listen string `json:"listen"` // 只允许 127.0.0.1:9090
		Secret string `json:"secret"`
	} `json:"clash_api"`

	// 永远直连、永远不进 tproxy 的目标（WireGuard 远程链路等）。gen 会强制补上内置三项。
	AlwaysBypass struct {
		CIDR     []string `json:"cidr"`
		UDPPorts []int    `json:"udp_ports"`
	} `json:"always_bypass"`

	Guest struct {
		DirectOnly bool     `json:"direct_only"`
		IPs        []string `json:"ips"`
		MACs       []string `json:"macs"`
		// NewDefault：新出现的设备（MAC 不在 device_info / device_names 里）自动标记为访客（M6）
		NewDefault bool `json:"new_device_default,omitempty"`
	} `json:"guest"`

	// GuestWifi：独立访客 SSID（M6）。只直连、与 LAN 隔离；由 tinylane-guest.sh 写 uci 并重载一次。
	GuestWifi GuestWifi `json:"guest_wifi"`
	// CustomRuleSets：远程规则集（.srs / sing-box 源格式 .json），按计划下载到 rulesets.dir/custom（M6）
	CustomRuleSets []CustomRuleSet `json:"rule_sets,omitempty"`

	Blacklist struct {
		MACs []string `json:"macs"`
	} `json:"blacklist"`

	Devices []Device `json:"devices"`
	Nodes   []Node   `json:"nodes"`
	Groups  []Group  `json:"groups"`
	Rules   []Rule   `json:"rules"`

	DNS struct {
		CN       []string `json:"cn"`      // 223.5.5.5
		Foreign  []string `json:"foreign"` // https://1.1.1.1/dns-query（经 foreign_detour）
		Detour   string   `json:"foreign_detour"`
		Fallback []string `json:"fallback"` // tinylane 停止后 dnsmasq 改回的上游
	} `json:"dns"`

	RuleSets struct {
		Dir        string   `json:"dir"`
		GeositeCN  []string `json:"geosite_cn_urls"`
		GeoipCN    []string `json:"geoip_cn_urls"`
		UpdateDays int      `json:"update_days"`
	} `json:"rulesets"`

	HY2MTUFix struct {
		InitialPacketSize int  `json:"initial_packet_size"` // 1200
		DisablePMTUD      bool `json:"disable_path_mtu_discovery"`
	} `json:"hy2_mtu_fix"`

	FindNeighbor bool `json:"find_neighbor"`
	// KernelCNBypass：规则模式下国内 IP 在 nft 里直接绕过 tproxy（缺省 = 开）。全局代理模式 / 设备=全局时不绕过。
	KernelCNBypass *bool `json:"kernel_cn_bypass,omitempty"`
	// KernelConnLog（M6d）：记录内核直连的连接（读 conntrack，缺省 = 开）。只影响面板显示，不进 gen。
	KernelConnLog *bool `json:"kernel_conn_log,omitempty"`
	// CoreMemLimitMB（M9）：代理内核 Go 内存软上限（MB），缺省 40；0 = 关（96 MB 兜底）。不进 gen，改了不重启内核。
	CoreMemLimitMB *int `json:"core_mem_limit_mb,omitempty"`
	// DirectTimeoutS：直连出站 TCP 拨号超时（秒），缺省 15（sing-box 默认 5 s 在上游丢包时太短）
	DirectTimeoutS int `json:"direct_connect_timeout_s,omitempty"`
	// SQM：WAN 口 cake 整形 + cake-autorate（缺省关；单位 Mbit）
	SQM       SQMConfig `json:"sqm"`
	CacheFile string    `json:"cache_file"` // tmpfs，记住手动选择的节点

	// M2/M3
	ProbeListen string             `json:"probe_listen"` // 看门狗吞吐探测专用 mixed 入站（127.0.0.1:7891），固定走隐藏组 tl-probe
	Panel       PanelConf          `json:"panel"`
	Watchdog    WatchdogConf       `json:"watchdog"`
	Update      UpdateConf         `json:"update"` // M11 自动更新
	Subs        []Sub              `json:"subscriptions,omitempty"`
	DeviceNames map[string]string  `json:"device_names,omitempty"` // MAC(小写) → 备注名
	DeviceInfo  map[string]DevInfo `json:"device_info,omitempty"`  // MAC(小写) → 类型/首次出现（M4，含从旧设备管理插件迁移的数据）

	// M7
	ConfigVersion int     `json:"config_version,omitempty"`
	ImportExclude *string `json:"import_exclude,omitempty"` // 订阅导入时过滤的信息条目（名称关键词）；nil = 默认值
	EgressProbe   *bool   `json:"egress_probe,omitempty"`   // 新节点自动检测出口 IP（缺省开）

	eff map[string][]string // 组 → 实际成员（loadConfig 时算好）
}

func (c *Config) egressAuto() bool { return c.EgressProbe == nil || *c.EgressProbe }

type GuestWifi struct {
	Enabled bool   `json:"enabled"`
	SSID    string `json:"ssid,omitempty"`
	Key     string `json:"key,omitempty"`     // WPA2/3 密码（8–63 位）；空 = 开放网络（不推荐）
	Band    string `json:"band,omitempty"`    // both | 2g | 5g（缺省 both）
	Subnet  string `json:"subnet,omitempty"`  // 缺省 192.168.77.1/24
	Applied string `json:"applied,omitempty"` // 上次实际生效时间
	// CheckPing：应用后自检要能 ping 通的地址（远程运维链路，如 WireGuard 对端）；空 = 不查
	CheckPing string `json:"check_ping,omitempty"`
}

type CustomRuleSet struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Format    string `json:"format,omitempty"` // binary(.srs) | source(.json)；空 = 按扩展名
	Outbound  string `json:"outbound"`
	Update    string `json:"update,omitempty"` // daily | weekly | off（缺省 weekly）
	Disabled  bool   `json:"disabled,omitempty"`
	Updated   string `json:"updated,omitempty"`
	Count     int    `json:"count,omitempty"`      // 规则条数（下载时统计）
	HasDomain bool   `json:"has_domain,omitempty"` // 含域名类规则（决定要不要加 DNS 分流规则）
	HasIP     bool   `json:"has_ip,omitempty"`
	LastErr   string `json:"last_error,omitempty"`
}

type DevInfo struct {
	Type      string   `json:"type,omitempty"`       // phone | computer | tablet | tv | other
	FirstSeen int64    `json:"first_seen,omitempty"` // unix 秒
	LastSeen  int64    `json:"last_seen,omitempty"`  // 迁移时的最后出现时间（不随运行更新）
	Hostname  string   `json:"hostname,omitempty"`
	Conn      string   `json:"conn,omitempty"` // 如「Wi‑Fi · 5 GHz」
	IPs       []string `json:"ips,omitempty"`
	Note      string   `json:"note,omitempty"`
}

type PanelConf struct {
	Listen       []string `json:"listen"`        // 空 = LAN 接口第一个 IPv4:9999
	PasswordHash string   `json:"password_hash"` // pbkdf2-sha256$iter$salt$hash（tinylane passwd 生成）
	SessionHours int      `json:"session_hours"` // 默认 168
	Disabled     bool     `json:"disabled,omitempty"`
}

type WatchdogConf struct {
	Disabled      bool   `json:"disabled,omitempty"`
	Interval      int    `json:"interval_s"`       // 轻量检测间隔，默认 60
	HeavyInterval int    `json:"heavy_interval_s"` // 吞吐检测间隔，默认 900
	Fail          int    `json:"fail"`             // 连续失败几次才切走，默认 3
	Recover       int    `json:"recover"`          // 高优先级连续正常几次才切回，默认 3
	URL           string `json:"url"`              // 默认 https://www.gstatic.com/generate_204
	TimeoutMS     int    `json:"timeout_ms"`       // 默认 5000
	SpeedHost     string `json:"speed_host"`       // 默认 speed.cloudflare.com
	DownBytes     int    `json:"down_bytes"`       // 默认 262144
	UpBytes       int    `json:"up_bytes"`         // 默认 262144
	MinDownKBps   int    `json:"min_down_kbps"`    // 默认 64
	MinUpKBps     int    `json:"min_up_kbps"`      // 默认 32
	HoldMinutes   int    `json:"hold_minutes"`     // 面板手动选择后暂停自动切换，默认 60
	// M10 快速切换（见 m10.go）。指针 = 缺省开 / 0 有意义的项
	FastSwitch    *bool `json:"fast_switch,omitempty"`     // 当前节点一次探测失败 → 快速复测，缺省开
	FastRetestS   int   `json:"fast_retest_s,omitempty"`   // 复测间隔秒，缺省 15（5–60）
	FastWindowS   int   `json:"fast_window_s,omitempty"`   // 判定窗口秒，缺省 30（15–180）
	CoreErrKick   *bool `json:"core_err_kick,omitempty"`   // 内核超时报错成批出现 → 触发快速复测，缺省开
	CoreErrCount  int   `json:"core_err_count,omitempty"`  // 20 秒内几条算成批，缺省 5（3–50）
	ProbeBackup   *bool `json:"probe_backup,omitempty"`    // 每轮也测各组下一个备用节点，缺省开
	SwitchBackMin *int  `json:"switch_back_min,omitempty"` // 快速切走后多少分钟内不切回，缺省 5（0–60）
}

type Sub struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Exit    string `json:"exit,omitempty"`    // M7 起不再使用（兼容读入，迁移时删除）
	UA      string `json:"ua,omitempty"`      // 自定义 User-Agent（空 = 先 clash.meta，没节点再 v2rayN/6.0）
	Auto    string `json:"auto,omitempty"`    // weekly | daily | off（默认 weekly：周一 08:00 上海时间）
	Updated string `json:"updated,omitempty"` // 上次成功时间
	Count   int    `json:"count,omitempty"`
	LastErr string `json:"last_error,omitempty"`
}

type SQMConfig struct {
	Enabled bool   `json:"enabled"`
	Iface   string `json:"iface,omitempty"` // 缺省 wan
	DLMin   int    `json:"dl_min"`
	DLBase  int    `json:"dl_base"`
	DLMax   int    `json:"dl_max"`
	ULMin   int    `json:"ul_min"`
	ULBase  int    `json:"ul_base"`
	ULMax   int    `json:"ul_max"`
}

type Device struct {
	Name  string `json:"name"`
	IP    string `json:"ip"`
	MAC   string `json:"mac,omitempty"`
	Mode  string `json:"mode"`            // rule | global | direct | intl（国内直连、国外走 group）
	Group string `json:"group,omitempty"` // global 时走哪个组/节点，默认 global_group
}

type Node struct {
	Name   string `json:"name"`
	Exit   string `json:"exit,omitempty"`    // M7 起不再使用：旧配置兼容读入、不影响分组（迁移时删除）；出口改为自动检测（egress.json）
	CertFP string `json:"cert_fp,omitempty"` // 订阅给的证书 SHA256 指纹（Clash fingerprint）；导入时换成 tls.certificate_public_key_sha256
	Source string `json:"source,omitempty"`  // clash | manual
	MTUFix *bool  `json:"mtu_fix,omitempty"` // 仅 hysteria2；缺省 = 开
	// sing-box 出站原样 JSON（不含 tag）
	Outbound map[string]any `json:"outbound"`
}

func (n Node) mtuFix() bool { return n.MTUFix == nil || *n.MTUFix }

func (n Node) Type() string { s, _ := n.Outbound["type"].(string); return s }

type Group struct {
	Name    string   `json:"name"`
	Label   string   `json:"label,omitempty"` // 面板显示名（只影响显示；name 是内核里的组 tag，规则/设备都按 name 引用）
	Type    string   `json:"type"`            // select（手动）| failover（看门狗按顺序故障切换）
	Members []string `json:"members"`         // 手选成员，有序：第一个 = 默认
	// M7 通用成员规则：Filter = 名称含这些关键词的节点自动加入（| 分隔，或 /正则/）；Exclude = 名称含这些的一律排除（对手选也生效）
	Filter  string `json:"filter,omitempty"`
	Exclude string `json:"exclude,omitempty"`
	// Strict：断网保护——组里没有可用节点时不回落直连
	Strict bool `json:"strict,omitempty"`
	// Forbid：M6 及以前的「禁止 exit:<出口>」，M7 起不再生效（兼容读入，迁移时转成 strict 并删除）
	Forbid []string `json:"forbid,omitempty"`
}

type Rule struct {
	Name          string   `json:"name,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	Port          []int    `json:"port,omitempty"`
	Network       string   `json:"network,omitempty"` // tcp | udp
	SourceIP      []string `json:"source_ip,omitempty"`
	Outbound      string   `json:"outbound"` // 组名 / 节点名 / direct / block
	Disabled      bool     `json:"disabled,omitempty"`
	// Pin：在「全局代理」模式和「设备=全局代理」时也生效（用于某些网站必须走指定出口的场景）。
	// 「全局直连」模式和「设备=直连」仍优先。
	Pin bool `json:"pin,omitempty"`
}

func (r Rule) hasDomain() bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.DomainRegex) > 0
}

// 内置永久绕过（WireGuard 远程运维链路，任何配置都删不掉）
// 编译时注入（build.sh 从 secret/build.env 读 TL_BUILTIN_BYPASS，逗号分隔），开源版默认为空：
//
//	go build -ldflags "-X main.builtinBypass=203.0.113.10/32,10.0.0.0/24"
//
// 运行时也可以在配置 always_bypass.cidr 里写；这里写死的部分任何配置都删不掉（远程运维链路保险）。
var builtinBypass = ""
var builtinBypassCIDR = splitList(builtinBypass)

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

var builtinBypassUDP = []int{51820}

var privateCIDR4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"255.255.255.255/32",
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	// 默认值：先给，再被 JSON 覆盖
	c.Enabled = true
	c.HY2MTUFix.DisablePMTUD = true
	c.FindNeighbor = true
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	c.applyDefaults()
	return c, c.validate()
}

func (c *Config) applyDefaults() {
	if c.DirectTimeoutS <= 0 {
		c.DirectTimeoutS = 15
	}
	if c.SQM.Iface == "" {
		c.SQM.Iface = "wan"
	}
	for _, x := range []struct {
		p *int
		v int
	}{{&c.SQM.DLMin, 20}, {&c.SQM.DLBase, 50}, {&c.SQM.DLMax, 90}, {&c.SQM.ULMin, 5}, {&c.SQM.ULBase, 20}, {&c.SQM.ULMax, 40}} {
		if *x.p <= 0 {
			*x.p = x.v
		}
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	defi := func(s *int, v int) {
		if *s == 0 {
			*s = v
		}
	}
	def(&c.Mode, "rule")
	def(&c.LogLevel, "warn")
	def(&c.LAN.Iface, "br-lan")
	if len(c.LAN.CIDR) == 0 {
		c.LAN.CIDR = []string{"192.168.1.0/24"}
	}
	defi(&c.TProxyPort, 7893)
	defi(&c.DNSPort, 1053)
	defi(&c.FwMark, 0x7a)
	defi(&c.RouteTable, 100)
	def(&c.ClashAPI.Listen, "127.0.0.1:9090")
	if len(c.DNS.CN) == 0 {
		c.DNS.CN = []string{"223.5.5.5"}
	}
	if len(c.DNS.Foreign) == 0 {
		c.DNS.Foreign = []string{"https://1.1.1.1/dns-query"}
	}
	if len(c.DNS.Fallback) == 0 {
		c.DNS.Fallback = []string{"223.5.5.5", "119.29.29.29"}
	}
	def(&c.RuleSets.Dir, "/etc/tinylane/ruleset")
	if len(c.RuleSets.GeositeCN) == 0 {
		c.RuleSets.GeositeCN = []string{
			"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
			"https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
		}
	}
	if len(c.RuleSets.GeoipCN) == 0 {
		c.RuleSets.GeoipCN = []string{
			"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
			"https://testingcf.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-cn.srs",
		}
	}
	defi(&c.RuleSets.UpdateDays, 7)
	defi(&c.HY2MTUFix.InitialPacketSize, 1200)
	def(&c.CacheFile, "/tmp/tinylane/cache.db")
	def(&c.ProbeListen, "127.0.0.1:7891")
	defi(&c.Panel.SessionHours, 168)
	w := &c.Watchdog
	defi(&w.Interval, 60)
	defi(&w.HeavyInterval, 900)
	defi(&w.Fail, 3)
	defi(&w.Recover, 3)
	def(&w.URL, "https://www.gstatic.com/generate_204")
	defi(&w.TimeoutMS, 5000)
	def(&w.SpeedHost, "speed.cloudflare.com")
	defi(&w.DownBytes, 262144)
	defi(&w.UpBytes, 262144)
	defi(&w.MinDownKBps, 64)
	defi(&w.MinUpKBps, 32)
	defi(&w.HoldMinutes, 60)
	m10Defaults(w)
	for i := range c.Subs {
		def(&c.Subs[i].Auto, "weekly")
	}
	for i := range c.CustomRuleSets {
		r := &c.CustomRuleSets[i]
		def(&r.Update, "weekly")
		if r.Format == "" {
			if strings.HasSuffix(strings.ToLower(strings.SplitN(r.URL, "?", 2)[0]), ".json") {
				r.Format = "source"
			} else {
				r.Format = "binary"
			}
		}
	}
	def(&c.GuestWifi.Band, "both")
	def(&c.GuestWifi.Subnet, "192.168.77.1/24")
	if c.MainGroup == "" && len(c.Groups) > 0 {
		c.MainGroup = c.Groups[0].Name
	}
	def(&c.GlobalGroup, c.MainGroup)
	def(&c.DNS.Detour, c.MainGroup)
	for i := range c.Groups {
		def(&c.Groups[i].Type, "select")
	}
	// 内置绕过永远存在
	c.AlwaysBypass.CIDR = uniq(append(c.AlwaysBypass.CIDR, builtinBypassCIDR...))
	ports := map[int]bool{}
	for _, p := range append(c.AlwaysBypass.UDPPorts, builtinBypassUDP...) {
		ports[p] = true
	}
	c.AlwaysBypass.UDPPorts = nil
	for p := range ports {
		c.AlwaysBypass.UDPPorts = append(c.AlwaysBypass.UDPPorts, p)
	}
	sortInts(c.AlwaysBypass.UDPPorts)
}

func (c *Config) validate() error {
	if c.DirectTimeoutS > 120 {
		return fmt.Errorf("直连超时只能是 1–120 秒")
	}
	q := c.SQM
	if q.DLMin > q.DLBase || q.DLBase > q.DLMax || q.ULMin > q.ULBase || q.ULBase > q.ULMax || q.DLMax > 10000 || q.ULMax > 10000 {
		return fmt.Errorf("整形速率要满足 最低 ≤ 常用 ≤ 最高（1–10000 Mbit）")
	}
	if !validIface(q.Iface) {
		return fmt.Errorf("整形接口名无效")
	}
	switch c.Mode {
	case "rule", "global", "direct":
	default:
		return fmt.Errorf("mode 只能是 rule/global/direct，现在是 %q", c.Mode)
	}
	host, _, ok := strings.Cut(c.ClashAPI.Listen, ":")
	if !ok || (host != "127.0.0.1" && host != "localhost") {
		return fmt.Errorf("clash_api.listen 只允许 127.0.0.1:<port>（现在 %q）", c.ClashAPI.Listen)
	}
	for _, l := range []string{c.MixedListen, c.ProbeListen} {
		if l == "" {
			continue
		}
		h, _, _ := strings.Cut(l, ":")
		if h != "127.0.0.1" {
			return fmt.Errorf("mixed_listen / probe_listen 只允许 127.0.0.1（现在 %q）", l)
		}
	}
	if c.ProbeListen == c.MixedListen && c.MixedListen != "" {
		return fmt.Errorf("probe_listen 不能和 mixed_listen 相同")
	}
	for _, l := range c.Panel.Listen {
		ap, err := netip.ParseAddrPort(l)
		if err != nil {
			return fmt.Errorf("panel.listen %q 无效（要写成 IP:端口）", l)
		}
		if ap.Addr().IsUnspecified() {
			return fmt.Errorf("panel.listen 不允许 0.0.0.0 / ::（避免暴露到 WAN），请写 LAN IP")
		}
	}
	for _, s := range c.Subs {
		if s.Name == "" || !(strings.HasPrefix(s.URL, "https://") || strings.HasPrefix(s.URL, "http://")) {
			return fmt.Errorf("订阅 %q 的 URL 无效", s.Name)
		}
		switch s.Auto {
		case "weekly", "daily", "off":
		default:
			return fmt.Errorf("订阅 %q 的 auto 只能是 weekly/daily/off", s.Name)
		}
	}
	names := map[string]string{"direct": "builtin", "block": "builtin", probeTag: "builtin"}
	for _, n := range c.Nodes {
		if n.Name == "" || n.Outbound == nil || n.Type() == "" {
			return fmt.Errorf("节点 %q 缺少 name/outbound.type", n.Name)
		}
		if _, dup := names[n.Name]; dup {
			return fmt.Errorf("名称重复：%q", n.Name)
		}
		names[n.Name] = "node"
	}
	for _, g := range c.Groups {
		if _, dup := names[g.Name]; dup {
			return fmt.Errorf("名称重复：%q", g.Name)
		}
		names[g.Name] = "group"
		if g.Type != "select" && g.Type != "failover" {
			return fmt.Errorf("组 %q：type 只能是 select / failover", g.Name)
		}
		if g.Name == "" || len(g.Name) > 64 {
			return fmt.Errorf("组名称无效：%q", g.Name)
		}
		if _, err := compileMatcher(g.Filter); err != nil {
			return fmt.Errorf("组 %q 的「只用含」规则：%v", g.Name, err)
		}
		if _, err := compileMatcher(g.Exclude); err != nil {
			return fmt.Errorf("组 %q 的「排除含」规则：%v", g.Name, err)
		}
		if len(g.Members) == 0 && strings.TrimSpace(g.Filter) == "" {
			return fmt.Errorf("组 %q 没有成员（手选节点，或填写「只用名称含」自动筛选）", g.Name)
		}
	}
	if c.ImportExclude != nil {
		if _, err := compileMatcher(*c.ImportExclude); err != nil {
			return fmt.Errorf("订阅过滤关键词：%v", err)
		}
	}
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if _, ok := names[m]; !ok {
				return fmt.Errorf("组 %q 的成员 %q 不存在", g.Name, m)
			}
			if m == g.Name {
				return fmt.Errorf("组 %q 不能包含自己", g.Name)
			}
		}
	}
	c.computeEff()
	if c.MainGroup == "" {
		return fmt.Errorf("没有 main_group（也没有任何组）")
	}
	for _, ref := range []string{c.MainGroup, c.GlobalGroup, c.DNS.Detour} {
		if _, ok := names[ref]; !ok {
			return fmt.Errorf("引用的出站 %q 不存在", ref)
		}
	}
	for i, r := range c.Rules {
		if _, ok := names[r.Outbound]; !ok {
			return fmt.Errorf("规则 #%d(%s) 的去向 %q 不存在", i+1, r.Name, r.Outbound)
		}
		for _, s := range append(append([]string{}, r.IPCIDR...), r.SourceIP...) {
			if _, err := parsePrefix(s); err != nil {
				return fmt.Errorf("规则 #%d：%v", i+1, err)
			}
		}
	}
	rsNames := map[string]bool{}
	for _, r := range c.CustomRuleSets {
		if r.Name == "" || len(r.Name) > 40 || strings.ContainsAny(r.Name, "/\\\"") {
			return fmt.Errorf("规则集名称无效：%q", r.Name)
		}
		if rsNames[r.Name] {
			return fmt.Errorf("规则集名称重复：%q", r.Name)
		}
		rsNames[r.Name] = true
		if !(strings.HasPrefix(r.URL, "https://") || strings.HasPrefix(r.URL, "http://")) {
			return fmt.Errorf("规则集 %q 的 URL 无效", r.Name)
		}
		if _, ok := names[r.Outbound]; !ok {
			return fmt.Errorf("规则集 %q 的去向 %q 不存在", r.Name, r.Outbound)
		}
		if r.Format != "binary" && r.Format != "source" {
			return fmt.Errorf("规则集 %q 的格式只能是 binary(.srs) / source(.json)", r.Name)
		}
		switch r.Update {
		case "daily", "weekly", "off":
		default:
			return fmt.Errorf("规则集 %q 的更新计划只能是 daily/weekly/off", r.Name)
		}
	}
	if err := c.GuestWifi.check(); err != nil {
		return err
	}
	for _, d := range c.Devices {
		if _, err := netip.ParseAddr(d.IP); err != nil {
			return fmt.Errorf("设备 %q IP 无效", d.Name)
		}
		switch d.Mode {
		case "rule", "global", "direct", "intl":
		default:
			return fmt.Errorf("设备 %q mode 无效", d.Name)
		}
		if d.Group != "" {
			if _, ok := names[d.Group]; !ok {
				return fmt.Errorf("设备 %q 的组 %q 不存在", d.Name, d.Group)
			}
		}
	}
	for _, s := range append(append(append([]string{}, c.Guest.IPs...), c.AlwaysBypass.CIDR...), c.LAN.CIDR...) {
		if _, err := parsePrefix(s); err != nil {
			return err
		}
	}
	for _, m := range append(append([]string{}, c.Guest.MACs...), c.Blacklist.MACs...) {
		if !isMAC(m) {
			return fmt.Errorf("MAC 无效：%q", m)
		}
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("地址无效：%q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func isMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 || strings.Trim(strings.ToLower(p), "0123456789abcdef") != "" {
			return false
		}
	}
	return true
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
