package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type M = map[string]any

const (
	tagTProxy = "tproxy-in"
	tagMixed  = "mixed-in"
	tagDNSIn  = "dns-in"
	tagDNSCN  = "dns-cn"
	tagDNSRem = "dns-remote"
	rsSite    = "geosite-cn"
	rsIP      = "geoip-cn"
	tagProbe  = "probe-in"
	probeTag  = "tl-probe" // 隐藏 selector：包含全部节点，只给看门狗吞吐探测用
)

// buildSingBox 把 TinyLane 配置翻译成 sing-box 1.14 配置。
func buildSingBox(c *Config) (M, error) {
	// ---------- 出站 ----------
	outbounds := []any{
		// 国内直连拨号超时 5 s → 15 s：上游满载丢包时 SYN 重传（1 s/3 s）还能连上，不再 5 s 硬失败
		M{"type": "direct", "tag": "direct", "connect_timeout": fmt.Sprintf("%ds", c.DirectTimeoutS)},
		M{"type": "block", "tag": "block"},
	}
	for _, n := range c.Nodes {
		ob := M{}
		for k, v := range n.Outbound {
			ob[k] = v
		}
		ob["tag"] = n.Name
		if n.Type() == "hysteria2" && n.mtuFix() {
			// QUICOptions 在 sing-box 1.14.4 中内嵌（flatten）在 hysteria2 出站顶层：
			// option/hysteria2.go Hysteria2OutboundOptions{ ... QUICOptions ... }
			ob["initial_packet_size"] = c.HY2MTUFix.InitialPacketSize
			ob["disable_path_mtu_discovery"] = c.HY2MTUFix.DisablePMTUD
		}
		// 节点域名一律用国内 DNS 直连解析，不依赖 dnsmasq（避免环路）
		if _, ok := ob["domain_resolver"]; !ok {
			ob["domain_resolver"] = tagDNSCN
		}
		outbounds = append(outbounds, ob)
	}
	for _, g := range c.Groups {
		obs, def := selectorOutbounds(c, g) // M7：手选 + 名称筛选 − 排除；空组 → block（断网保护）/ direct
		outbounds = append(outbounds, M{
			"type":                        "selector",
			"tag":                         g.Name,
			"outbounds":                   obs,
			"default":                     def,
			"interrupt_exist_connections": true,
		})
	}

	if c.ProbeListen != "" && len(c.Nodes) > 0 {
		var all []string
		for _, n := range c.Nodes {
			all = append(all, n.Name)
		}
		outbounds = append(outbounds, M{"type": "selector", "tag": probeTag, "outbounds": all, "default": all[0]})
	}

	// ---------- 入站 ----------
	inbounds := []any{
		// 不写 network = 同时 TCP+UDP
		M{"type": "tproxy", "tag": tagTProxy, "listen": "::", "listen_port": c.TProxyPort},
		M{"type": "direct", "tag": tagDNSIn, "listen": "127.0.0.1", "listen_port": c.DNSPort},
	}
	if c.MixedListen != "" {
		h, p, _ := strings.Cut(c.MixedListen, ":")
		port, _ := strconv.Atoi(p)
		inbounds = append(inbounds, M{"type": "mixed", "tag": tagMixed, "listen": h, "listen_port": port})
	}
	if c.ProbeListen != "" && len(c.Nodes) > 0 {
		h, p, _ := strings.Cut(c.ProbeListen, ":")
		port, _ := strconv.Atoi(p)
		inbounds = append(inbounds, M{"type": "mixed", "tag": tagProbe, "listen": h, "listen_port": port})
	}

	// ---------- 规则集（本地 .srs，update-rules 负责下载）----------
	ruleSets := []any{
		M{"type": "local", "tag": rsSite, "format": "binary", "path": filepath.Join(c.RuleSets.Dir, "geosite-cn.srs")},
		M{"type": "local", "tag": rsIP, "format": "binary", "path": filepath.Join(c.RuleSets.Dir, "geoip-cn.srs")},
	}

	// 自定义远程规则集（M6）：只引用已下载、通过校验的文件；没下载好的不进配置（避免内核起不来）
	var customRS []CustomRuleSet
	for _, r := range c.CustomRuleSets {
		if r.Disabled || !fileExists(customRSPath(c, r)) {
			continue
		}
		customRS = append(customRS, r)
		ruleSets = append(ruleSets, M{"type": "local", "tag": customRSTag(r), "format": r.Format, "path": customRSPath(c, r)})
	}

	// ---------- 路由规则 ----------
	var rules []any
	add := func(r M) { rules = append(rules, r) }
	add(M{"action": "sniff"})
	add(M{"protocol": "dns", "action": "hijack-dns"})
	add(M{"inbound": []string{tagDNSIn}, "action": "hijack-dns"})
	// 看门狗探测入站：与运行模式无关，永远走 tl-probe（由看门狗选节点）
	if c.ProbeListen != "" && len(c.Nodes) > 0 {
		add(M{"inbound": []string{tagProbe}, "outbound": probeTag})
	}
	// 1. 私有/局域网/永久绕过 → 直连
	add(M{"ip_is_private": true, "outbound": "direct"})
	add(M{"ip_cidr": append(append([]string{}, c.AlwaysBypass.CIDR...), c.LAN.CIDR...), "outbound": "direct"})
	add(M{"domain_suffix": []string{"lan", "local", "localhost"}, "outbound": "direct"})
	// 2. 访客 → 直连（nft 层也已绕过，这里是双保险）
	if c.Guest.DirectOnly && (len(c.Guest.IPs) > 0 || len(c.Guest.MACs) > 0) {
		if len(c.Guest.IPs) > 0 {
			add(M{"source_ip_cidr": c.Guest.IPs, "outbound": "direct"})
		}
		if len(c.Guest.MACs) > 0 {
			add(M{"source_mac_address": lower(c.Guest.MACs), "outbound": "direct"})
		}
	}
	// 3. 按设备覆盖（直连）+ 全局直连模式
	var devDirect []string
	devGlobal := map[string][]string{}
	devIntl := map[string][]string{} // 设备=国外走某组：国内照常直连，其余走指定组
	for _, d := range c.Devices {
		switch d.Mode {
		case "intl":
			g := d.Group
			if g == "" {
				g = c.MainGroup
			}
			devIntl[g] = append(devIntl[g], d.IP)
		case "direct":
			devDirect = append(devDirect, d.IP)
		case "global":
			g := d.Group
			if g == "" {
				g = c.GlobalGroup
			}
			devGlobal[g] = append(devGlobal[g], d.IP)
		}
	}
	if len(devDirect) > 0 {
		add(M{"source_ip_cidr": devDirect, "outbound": "direct"})
	}
	add(M{"clash_mode": "direct", "outbound": "direct"})
	// 4. 固定规则（pin）：全局代理 / 设备全局时也生效，例如某些网站只走指定出口
	for _, r := range c.Rules {
		if !r.Disabled && r.Pin {
			add(ruleToSB(r))
		}
	}
	// 5. 设备=全局代理 + 全局代理模式（clash_api 可热切换模式）
	for _, g := range sortedKeys(devGlobal) {
		add(M{"source_ip_cidr": devGlobal[g], "outbound": g})
	}
	add(M{"clash_mode": "global", "outbound": c.GlobalGroup})
	// 6. 其余自定义规则
	for _, r := range c.Rules {
		if !r.Disabled && !r.Pin {
			add(ruleToSB(r))
		}
	}
	// 6b. 自定义远程规则集（顺序 = 面板列表顺序；在自定义规则之后、国内直连之前）
	for _, r := range customRS {
		add(M{"rule_set": []string{customRSTag(r)}, "outbound": r.Outbound})
	}
	// 7. 国内域名 / 国内 IP → 直连
	add(M{"domain_suffix": []string{"cn"}, "outbound": "direct"})
	add(M{"rule_set": []string{rsSite}, "outbound": "direct"})
	// mixed 入站（测试用）目标是域名：按 DNS 规则解析一次（国内结果才直连，被污染的国外结果回落 DoH），供 geoip 判断；tproxy 目标本来就是 IP
	if c.MixedListen != "" {
		add(M{"inbound": []string{tagMixed}, "action": "resolve", "strategy": "ipv4_only"})
	}
	add(M{"rule_set": []string{rsIP}, "outbound": "direct"})
	// 8. 设备=国外走某组：排在国内直连之后、默认出口之前（nft 层不进 nobypass_src，国内 IP 照常内核直连）
	for _, g := range sortedKeys(devIntl) {
		add(M{"source_ip_cidr": devIntl[g], "outbound": g})
	}

	route := M{
		"rules":                   rules,
		"rule_set":                ruleSets,
		"final":                   c.MainGroup,
		"default_domain_resolver": M{"server": tagDNSCN, "strategy": "ipv4_only"},
	}
	if c.FindNeighbor {
		route["find_neighbor"] = true
	}

	// ---------- DNS ----------
	dnsServers := []any{dnsServer(tagDNSCN, c.DNS.CN[0], "")}
	dnsServers = append(dnsServers, dnsServer(tagDNSRem, c.DNS.Foreign[0], c.DNS.Detour))
	var dnsRules []any
	// IPv6 第一版不处理：AAAA 直接回空
	dnsRules = append(dnsRules, M{"query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"})
	dnsRules = append(dnsRules, M{"domain_suffix": []string{"lan", "local", "localhost"}, "action": "route", "server": tagDNSCN})
	// 自定义规则里的域名：去向是直连 → 国内 DNS；否则 → 国外 DNS（经代理）
	var dDirect, dProxy []M
	for _, r := range c.Rules {
		if r.Disabled || !r.hasDomain() {
			continue
		}
		m := domainPart(r)
		if r.Outbound == "direct" {
			dDirect = append(dDirect, m)
		} else if r.Outbound != "block" {
			dProxy = append(dProxy, m)
		}
	}
	for _, m := range dDirect {
		m["action"], m["server"] = "route", tagDNSCN
		dnsRules = append(dnsRules, m)
	}
	for _, m := range dProxy {
		m["action"], m["server"] = "route", tagDNSRem
		dnsRules = append(dnsRules, m)
	}
	for _, r := range customRS {
		if r.Outbound == "block" || !r.HasDomain {
			continue
		}
		srv := tagDNSRem
		if r.Outbound == "direct" {
			srv = tagDNSCN
		}
		dnsRules = append(dnsRules, M{"rule_set": []string{customRSTag(r)}, "action": "route", "server": srv})
	}
	dnsRules = append(dnsRules,
		M{"domain_suffix": []string{"cn"}, "action": "route", "server": tagDNSCN},
		M{"rule_set": []string{rsSite}, "action": "route", "server": tagDNSCN},
		// 列表外域名：先问国内 DNS，结果是国内 IP 就用它（→ 之后路由按 geoip-cn 直连）
		M{"action": "evaluate", "server": tagDNSCN},
		M{"match_response": true, "rule_set": []string{rsIP}, "action": "respond"},
	)
	dns := M{
		"servers":  dnsServers,
		"rules":    dnsRules,
		"final":    tagDNSRem,
		"strategy": "ipv4_only",
	}

	clash := M{
		"external_controller": c.ClashAPI.Listen,
		"secret":              c.ClashAPI.Secret,
		"default_mode":        modeName(c.Mode),
	}
	exp := M{"clash_api": clash}
	if c.CacheFile != "" {
		exp["cache_file"] = M{"enabled": true, "path": c.CacheFile, "store_rdrc": false}
	}

	return M{
		"log":          M{"level": c.LogLevel, "timestamp": true},
		"dns":          dns,
		"inbounds":     inbounds,
		"outbounds":    outbounds,
		"route":        route,
		"experimental": exp,
	}, nil
}

func modeName(m string) string {
	switch m {
	case "global":
		return "global"
	case "direct":
		return "direct"
	}
	return "rule"
}

// dnsServer 把 "223.5.5.5" / "udp://x" / "tcp://x" / "tls://x" / "https://x/dns-query" 转成 1.12+ 新格式。
func dnsServer(tag, s, detour string) M {
	m := M{"tag": tag}
	if !strings.Contains(s, "://") {
		s = "udp://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		m["type"], m["server"] = "udp", s
		return m
	}
	m["type"] = u.Scheme
	m["server"] = u.Hostname()
	if p := u.Port(); p != "" {
		m["server_port"], _ = strconv.Atoi(p)
	}
	if u.Scheme == "https" && u.Path != "" && u.Path != "/dns-query" {
		m["path"] = u.Path
	}
	if detour != "" {
		m["detour"] = detour
	}
	return m
}

func domainPart(r Rule) M {
	m := M{}
	if len(r.Domain) > 0 {
		m["domain"] = r.Domain
	}
	if len(r.DomainSuffix) > 0 {
		m["domain_suffix"] = r.DomainSuffix
	}
	if len(r.DomainKeyword) > 0 {
		m["domain_keyword"] = r.DomainKeyword
	}
	if len(r.DomainRegex) > 0 {
		m["domain_regex"] = r.DomainRegex
	}
	return m
}

func ruleToSB(r Rule) M {
	m := domainPart(r)
	if len(r.IPCIDR) > 0 {
		m["ip_cidr"] = r.IPCIDR
	}
	if len(r.Port) > 0 {
		m["port"] = r.Port
	}
	if r.Network != "" {
		m["network"] = []string{r.Network}
	}
	if len(r.SourceIP) > 0 {
		m["source_ip_cidr"] = r.SourceIP
	}
	if r.Outbound == "block" {
		m["action"] = "reject"
	} else {
		m["outbound"] = r.Outbound
	}
	return m
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// ---------- nftables ----------

// cnBypassCIDRs：只在规则模式且开关打开（缺省开）时返回国内 IPv4 网段；全局代理 / 全局直连模式返回 nil。
func cnBypassCIDRs(c *Config) []string {
	if c.Mode != "rule" || (c.KernelCNBypass != nil && !*c.KernelCNBypass) {
		return nil
	}
	return loadCN4(c.RuleSets.Dir)
}

func buildNft(c *Config) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	mark := fmt.Sprintf("0x%x", c.FwMark)
	w("# 由 tinylane gen 生成，勿手改。只挂 prerouting（LAN 进来的流量），路由器本机流量不经过这里。\n")
	w("table inet tinylane\ndelete table inet tinylane\n\n")
	w("table inet tinylane {\n")
	w("\tset bypass4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}\n",
		strings.Join(collapse(append(append(append([]string{}, privateCIDR4...), c.AlwaysBypass.CIDR...), c.LAN.CIDR...)), ", "))
	w("\tset bypass_udp_port {\n\t\ttype inet_service\n%s\t}\n", elems(intsToStr(c.AlwaysBypass.UDPPorts)))
	guestIP, guestMAC := []string{}, []string{}
	if c.Guest.DirectOnly {
		guestIP, guestMAC = c.Guest.IPs, lower(c.Guest.MACs)
	}
	w("\tset guest_ip {\n\t\ttype ipv4_addr\n\t\tflags interval\n%s\t}\n", elems(collapse(guestIP)))
	w("\tset guest_mac {\n\t\ttype ether_addr\n%s\t}\n", elems(guestMAC))
	w("\tset black_mac {\n\t\ttype ether_addr\n%s\t}\n", elems(lower(c.Blacklist.MACs)))
	if cn := cnBypassCIDRs(c); len(cn) > 0 {
		var srcIP, srcMAC, dst []string
		for _, d := range c.Devices {
			if d.Mode == "global" {
				srcIP = append(srcIP, d.IP)
				if d.MAC != "" {
					srcMAC = append(srcMAC, strings.ToLower(d.MAC))
				}
			}
		}
		for _, r := range c.Rules {
			if r.Disabled || r.Outbound == "direct" {
				continue
			}
			for _, x := range r.IPCIDR {
				if p, err := parsePrefix(x); err == nil && p.Addr().Is4() {
					dst = append(dst, p.Masked().String())
				}
			}
		}
		w("\tset nobypass_src {\n\t\ttype ipv4_addr\n\t\tflags interval\n%s\t}\n", elems(collapse(srcIP)))
		w("\tset nobypass_mac {\n\t\ttype ether_addr\n%s\t}\n", elems(uniq(srcMAC)))
		w("\tset nobypass4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n%s\t}\n", elems(collapse(dst)))
		w("\tset cn4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { %s }\n\t}\n", strings.Join(cn, ", "))
	}
	w("\n\tchain prerouting {\n")
	w("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	w("\t\tiifname != %q return\n", c.LAN.Iface)
	w("\t\tether saddr @black_mac counter drop\n")
	w("\t\tmeta nfproto ipv6 return\n")
	w("\t\tmeta l4proto != { tcp, udp } return\n")
	w("\t\tfib daddr type { local, broadcast, multicast } return\n")
	w("\t\tip daddr @bypass4 return\n")
	w("\t\tudp dport @bypass_udp_port return\n")
	w("\t\tudp sport @bypass_udp_port return\n")
	w("\t\tether saddr @guest_mac return\n")
	w("\t\tip saddr @guest_ip return\n")
	if cn := cnBypassCIDRs(c); len(cn) > 0 {
		// 规则模式：DNS 照常劫持；设备=全局代理、自定义规则里指向代理的 IP 段不绕过；其余国内 IP 直接 return（内核转发）
		w("\t\tth dport 53 goto tp\n")
		w("\t\tip saddr @nobypass_src goto tp\n")
		w("\t\tether saddr @nobypass_mac goto tp\n")
		w("\t\tip daddr @nobypass4 goto tp\n")
		w("\t\tip daddr @cn4 counter return\n")
	}
	w("\t\tgoto tp\n")
	w("\t}\n")
	w("\n\tchain tp {\n")
	w("\t\tmeta l4proto tcp meta mark set %s tproxy ip to 127.0.0.1:%d counter accept\n", mark, c.TProxyPort)
	w("\t\tmeta l4proto udp meta mark set %s tproxy ip to 127.0.0.1:%d counter accept\n", mark, c.TProxyPort)
	w("\t}\n}\n")
	return b.String()
}

func elems(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return "\t\telements = { " + strings.Join(v, ", ") + " }\n"
}

func intsToStr(a []int) []string {
	out := []string{}
	for _, i := range a {
		out = append(out, strconv.Itoa(i))
	}
	return out
}

func buildEnv(c *Config) string {
	b := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	return fmt.Sprintf("ENABLED=%d\nLAN_IFACE=%q\nTPROXY_PORT=%d\nDNS_PORT=%d\nFWMARK=0x%x\nROUTE_TABLE=%d\nFALLBACK_DNS=%q\nRULESET_DIR=%q\n",
		b(c.Enabled), c.LAN.Iface, c.TProxyPort, c.DNSPort, c.FwMark, c.RouteTable, strings.Join(c.DNS.Fallback, " "), c.RuleSets.Dir)
}

func buildSQMEnv(c *Config) string {
	b := 0
	if c.SQM.Enabled {
		b = 1
	}
	q := c.SQM
	return fmt.Sprintf("ENABLED=%d\nIFACE=%q\nDL_MIN=%d\nDL_BASE=%d\nDL_MAX=%d\nUL_MIN=%d\nUL_BASE=%d\nUL_MAX=%d\n",
		b, q.Iface, q.DLMin, q.DLBase, q.DLMax, q.ULMin, q.ULBase, q.ULMax)
}

func randomSecret() string {
	var b [12]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func marshal(v any) []byte {
	out, _ := json.MarshalIndent(v, "", "  ")
	return append(out, '\n')
}

// collapse 去掉被其他网段包含的网段（nft interval 集合里重叠元素会报错）
func collapse(in []string) []string {
	var ps []netip.Prefix
	for _, s := range uniq(in) {
		if p, err := parsePrefix(s); err == nil {
			ps = append(ps, p.Masked())
		}
	}
	var out []string
	for i, p := range ps {
		covered := false
		for j, q := range ps {
			if i != j && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q.Bits() < p.Bits() || j < i) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p.String())
		}
	}
	return out
}
