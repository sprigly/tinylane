package main

// import-clash：把 Clash / mihomo YAML 的 proxies 列表转成 TinyLane 节点（内嵌 sing-box 出站）。
// 支持：hysteria2、vless（tcp/ws/grpc/http/httpupgrade + tls/reality）、ss（obfs / v2ray-plugin）、trojan、vmess、tuic、anytls（M7）。
// 内核不支持的类型（hysteria v1、wireguard、ssr、snell、socks/http 等）汇总成「跳过 N 个 xxx」。
// 不打印任何密码 / uuid。

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

func importClash(path string) ([]Node, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return importClashData(data)
}

func importClashData(data []byte) ([]Node, []string, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
		Groups  []any            `yaml:"proxy-groups"`
		Rules   []any            `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// 也允许文件本身就是一个 proxies 列表
		var list []map[string]any
		if err2 := yaml.Unmarshal(data, &list); err2 != nil {
			return nil, nil, fmt.Errorf("YAML 解析失败: %w", err)
		}
		doc.Proxies = list
	}
	var nodes []Node
	var warns []string
	skip := skipCounter{}
	for _, p := range doc.Proxies {
		name := str(p, "name")
		if t := strings.ToLower(str(p, "type")); !supportedTypes[t] {
			skip[firstNonEmpty(t, "未知类型")]++
			continue
		}
		ob, _, err := clashToSB(p)
		if err != nil {
			warns = append(warns, fmt.Sprintf("跳过 %q：%v", name, err))
			continue
		}
		nodes = append(nodes, Node{Name: name, Source: "clash", CertFP: certFP(p), Outbound: ob})
	}
	warns = append(skip.warns(), warns...)
	if len(doc.Groups) > 0 || len(doc.Rules) > 0 {
		warns = append(warns, fmt.Sprintf("订阅里的 %d 个代理组、%d 条规则没有导入（只导入节点；组在「节点」页自己建，可按名称自动筛选）", len(doc.Groups), len(doc.Rules)))
	}
	return dedupeNames(nodes), warns, nil
}

// certFP：Clash 的 fingerprint（证书 SHA256）；跳过证书校验时没意义
func certFP(p map[string]any) string {
	if boolean(p, "skip-cert-verify") {
		return ""
	}
	if fp := normFP(str(p, "fingerprint")); len(fp) == 64 {
		return fp
	}
	return ""
}

func clashToSB(p map[string]any) (M, string, error) {
	typ := str(p, "type")
	server := str(p, "server")
	port := num(p, "port")
	if server == "" || port == 0 {
		return nil, "", fmt.Errorf("缺少 server/port")
	}
	ob := M{"server": server, "server_port": port}
	if u := str(p, "uuid"); (typ == "vless" || typ == "vmess" || typ == "tuic") && !validUUID(u) {
		return nil, "", fmt.Errorf("uuid 格式无效")
	}
	sni := firstNonEmpty(str(p, "sni"), str(p, "servername"))
	tlsOn := boolean(p, "tls")
	switch typ {
	case "hysteria2", "hy2":
		ob["type"] = "hysteria2"
		ob["password"] = firstNonEmpty(str(p, "password"), str(p, "auth"))
		if o := str(p, "obfs"); o != "" {
			ob["obfs"] = M{"type": o, "password": str(p, "obfs-password")}
		}
		if ports := str(p, "ports"); ports != "" {
			var sp []string
			for _, r := range strings.Split(ports, ",") {
				sp = append(sp, strings.ReplaceAll(strings.TrimSpace(r), "-", ":"))
			}
			ob["server_ports"] = sp
			if hi := num(p, "hop-interval"); hi > 0 {
				ob["hop_interval"] = fmt.Sprintf("%ds", hi)
			}
		}
		if up := mbps(p["up"]); up > 0 {
			ob["up_mbps"] = up
		}
		if down := mbps(p["down"]); down > 0 {
			ob["down_mbps"] = down
		}
		tlsOn = true
	case "vless":
		ob["type"] = "vless"
		ob["uuid"] = str(p, "uuid")
		if f := str(p, "flow"); f != "" {
			ob["flow"] = f
		}
		if pe := str(p, "packet-encoding"); pe != "" {
			ob["packet_encoding"] = pe
		}
	case "vmess":
		ob["type"] = "vmess"
		ob["uuid"] = str(p, "uuid")
		ob["alter_id"] = num(p, "alterId")
		ob["security"] = firstNonEmpty(str(p, "cipher"), "auto")
	case "trojan":
		ob["type"] = "trojan"
		ob["password"] = str(p, "password")
		tlsOn = true
	case "ss", "shadowsocks":
		ob["type"] = "shadowsocks"
		ob["method"] = str(p, "cipher")
		ob["password"] = str(p, "password")
		if pl := str(p, "plugin"); pl != "" {
			opts, _ := p["plugin-opts"].(map[string]any)
			switch pl {
			case "obfs":
				ob["plugin"] = "obfs-local"
				ob["plugin_opts"] = fmt.Sprintf("obfs=%s;obfs-host=%s", str(opts, "mode"), str(opts, "host"))
			case "v2ray-plugin":
				ob["plugin"] = "v2ray-plugin"
				s := "mode=" + firstNonEmpty(str(opts, "mode"), "websocket")
				if boolean(opts, "tls") {
					s += ";tls"
				}
				if h := str(opts, "host"); h != "" {
					s += ";host=" + h
				}
				if pa := str(opts, "path"); pa != "" {
					s += ";path=" + pa
				}
				ob["plugin_opts"] = s
			default:
				return nil, "", fmt.Errorf("不支持的 ss 插件 %q", pl)
			}
		}
		if boolean(p, "udp-over-tcp") {
			ob["udp_over_tcp"] = true
		}
		return ob, "", nil
	case "tuic":
		ob["type"] = "tuic"
		ob["uuid"] = str(p, "uuid")
		ob["password"] = str(p, "password")
		if cc := str(p, "congestion-controller"); cc != "" {
			ob["congestion_control"] = cc
		}
		if m := str(p, "udp-relay-mode"); m != "" {
			ob["udp_relay_mode"] = m
		}
		if boolean(p, "reduce-rtt") {
			ob["zero_rtt_handshake"] = true
		}
		if hb := num(p, "heartbeat-interval"); hb > 0 {
			ob["heartbeat"] = fmt.Sprintf("%dms", hb)
		}
		tlsOn = true
	case "anytls":
		ob["type"] = "anytls"
		ob["password"] = str(p, "password")
		if v := num(p, "idle-session-check-interval"); v > 0 {
			ob["idle_session_check_interval"] = fmt.Sprintf("%ds", v)
		}
		if v := num(p, "idle-session-timeout"); v > 0 {
			ob["idle_session_timeout"] = fmt.Sprintf("%ds", v)
		}
		if v := num(p, "min-idle-session"); v > 0 {
			ob["min_idle_session"] = v
		}
		tlsOn = true
	default:
		return nil, "", fmt.Errorf("不支持的类型 %q", typ)
	}

	// 传输层（vless / vmess / trojan）
	if typ == "vless" || typ == "vmess" || typ == "trojan" {
		switch net := firstNonEmpty(str(p, "network"), "tcp"); net {
		case "tcp":
		case "ws":
			opts, _ := p["ws-opts"].(map[string]any)
			if opts == nil { // 老式写法 ws-path / ws-headers
				opts = map[string]any{"path": p["ws-path"], "headers": p["ws-headers"]}
				if p["ws-path"] == nil {
					delete(opts, "path")
				}
			}
			t := M{"type": "ws"}
			path := str(opts, "path")
			// ?ed=2048 早期数据写法
			if u, err := url.Parse(path); err == nil && u.Query().Get("ed") != "" {
				ed, _ := strconv.Atoi(u.Query().Get("ed"))
				q := u.Query()
				q.Del("ed")
				u.RawQuery = q.Encode()
				path = u.String()
				t["max_early_data"] = ed
				t["early_data_header_name"] = "Sec-WebSocket-Protocol"
			}
			if path != "" {
				t["path"] = path
			}
			if med := num(opts, "max-early-data"); med > 0 {
				t["max_early_data"] = med
				t["early_data_header_name"] = firstNonEmpty(str(opts, "early-data-header-name"), "Sec-WebSocket-Protocol")
			}
			if hdr, ok := opts["headers"].(map[string]any); ok {
				h := M{}
				for k, v := range hdr {
					h[k] = fmt.Sprint(v)
				}
				if len(h) > 0 {
					t["headers"] = h
				}
			}
			ob["transport"] = t
		case "grpc":
			opts, _ := p["grpc-opts"].(map[string]any)
			ob["transport"] = M{"type": "grpc", "service_name": str(opts, "grpc-service-name")}
		case "http", "h2":
			opts, _ := p["h2-opts"].(map[string]any)
			if opts == nil {
				opts, _ = p["http-opts"].(map[string]any)
			}
			t := M{"type": "http"}
			if hosts := strList(opts["host"]); len(hosts) > 0 {
				t["host"] = hosts
			}
			if pa := strList(opts["path"]); len(pa) > 0 {
				t["path"] = pa[0]
			}
			ob["transport"] = t
		case "httpupgrade":
			opts, _ := p["http-upgrade-opts"].(map[string]any)
			ob["transport"] = M{"type": "httpupgrade", "path": str(opts, "path"), "host": str(opts, "host")}
		default:
			return nil, "", fmt.Errorf("不支持的传输 %q", net)
		}
	}

	if tlsOn {
		t := M{"enabled": true}
		if sni != "" {
			t["server_name"] = sni
		}
		if boolean(p, "skip-cert-verify") {
			t["insecure"] = true
		}
		if alpn := strList(p["alpn"]); len(alpn) > 0 {
			t["alpn"] = alpn
		}
		fp := str(p, "client-fingerprint")
		if ro, ok := p["reality-opts"].(map[string]any); ok {
			t["reality"] = M{"enabled": true, "public_key": str(ro, "public-key"), "short_id": str(ro, "short-id")}
			if fp == "" {
				fp = "chrome" // reality 必须 uTLS
			}
		}
		// hysteria2/tuic 是 QUIC，不走 uTLS
		if fp != "" && fp != "none" && typ != "hysteria2" && typ != "hy2" && typ != "tuic" {
			t["utls"] = M{"enabled": true, "fingerprint": fp}
		}
		ob["tls"] = t
	}
	return ob, sni, nil
}

// 合并：替换 source=clash 的旧节点，保留手动节点；同名节点保留用户设过的 mtu_fix。
func mergeNodes(old []Node, imported []Node) []Node {
	prev := map[string]Node{}
	for _, n := range old {
		prev[n.Name] = n
	}
	seen := map[string]bool{}
	var out []Node
	for _, n := range imported {
		if p, ok := prev[n.Name]; ok {
			n.MTUFix = p.MTUFix
		}
		seen[n.Name] = true
		out = append(out, n)
	}
	for _, n := range old {
		if n.Source != "clash" && !seen[n.Name] {
			out = append(out, n)
		}
	}
	return out
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	switch v := m[k].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func num(m map[string]any, k string) int {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(v))
		return i
	}
	return 0
}

func boolean(m map[string]any, k string) bool {
	if m == nil {
		return false
	}
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func mbps(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		f := strings.Fields(x)
		if len(f) > 0 {
			i, _ := strconv.Atoi(f[0])
			return i
		}
	}
	return 0
}

func strList(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []any:
		var out []string
		for _, i := range x {
			out = append(out, fmt.Sprint(i))
		}
		return out
	}
	return nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
