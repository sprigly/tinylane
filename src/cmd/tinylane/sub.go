package main

// 订阅：面板订阅地址（Clash YAML / Base64 分享链接 / 明文分享链接 / sing-box JSON）→ 节点。
// 规则：订阅只替换「自己导入的节点」（source = sub:<名称>；第一个订阅也接管 M1 的 source=clash），手动节点永久保留；
// 同名节点保留用户设过的 mtu_fix；更新后组里不存在的手选成员自动移除（组被删空且没有名称筛选则拒绝应用）；
// M7：名称像「官网 / 客服 / 剩余流量」的信息条目按 import_exclude 过滤；内核不支持的类型汇总成「跳过 N 个 xxx」。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

func parseSubscription(data []byte) ([]Node, []string, string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if s == "" {
		return nil, nil, "", fmt.Errorf("订阅内容为空")
	}
	if strings.Contains(s, "proxies:") {
		n, w, err := importClashData([]byte(s))
		return n, w, "Clash YAML", err
	}
	if strings.HasPrefix(s, "{") {
		n, w, err := importSingBoxJSON([]byte(s))
		return n, w, "sing-box JSON", err
	}
	format := "分享链接"
	if !strings.Contains(s, "://") {
		dec, err := b64any(s)
		if err != nil {
			return nil, nil, "", fmt.Errorf("无法识别订阅格式（不是 Clash YAML / sing-box JSON / Base64）")
		}
		s = string(dec)
		format = "Base64 分享链接"
	}
	var nodes []Node
	var warns []string
	skip := skipCounter{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		n, err := linkToNode(line)
		if err != nil {
			if us, ok := err.(unsupportedScheme); ok {
				skip[string(us)]++
				continue
			}
			warns = append(warns, err.Error())
			continue
		}
		nodes = append(nodes, n)
	}
	warns = append(skip.warns(), warns...)
	if len(nodes) == 0 {
		return nil, warns, format, fmt.Errorf("没有解析出任何节点")
	}
	return dedupeNames(nodes), warns, format, nil
}

func dedupeNames(nodes []Node) []Node {
	seen := map[string]int{}
	for i := range nodes {
		n := nodes[i].Name
		if seen[n] > 0 {
			nodes[i].Name = fmt.Sprintf("%s %d", n, seen[n]+1)
		}
		seen[n]++
	}
	return nodes
}

func b64any(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 解码失败")
}

func importSingBoxJSON(data []byte) ([]Node, []string, error) {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	var out []Node
	var warns []string
	skip := skipCounter{}
	for _, ob := range doc.Outbounds {
		t, _ := ob["type"].(string)
		switch t {
		case "hysteria2", "vless", "vmess", "trojan", "shadowsocks", "tuic", "anytls":
		case "direct", "block", "dns", "selector", "urltest":
			continue
		default:
			skip[t]++
			continue
		}
		name, _ := ob["tag"].(string)
		delete(ob, "tag")
		delete(ob, "detour")
		if name == "" {
			warns = append(warns, "跳过没有 tag 的出站")
			continue
		}
		out = append(out, Node{Name: name, Outbound: ob})
	}
	return dedupeNames(out), append(skip.warns(), warns...), nil
}

type unsupportedScheme string

func (u unsupportedScheme) Error() string { return "不支持的链接类型 " + string(u) + "://" }

// linkToNode：分享链接 → Clash 风格 map → clashToSB（复用同一套转换，行为和 import-clash 一致）
func linkToNode(link string) (Node, error) {
	p, err := linkToClash(link)
	if err != nil {
		return Node{}, err
	}
	ob, _, err := clashToSB(p)
	if err != nil {
		return Node{}, fmt.Errorf("%s：%v", p["name"], err)
	}
	return Node{Name: str(p, "name"), CertFP: certFP(p), Outbound: ob}, nil
}

func linkToClash(link string) (map[string]any, error) {
	scheme, _, _ := strings.Cut(link, "://")
	scheme = strings.ToLower(scheme)
	if scheme == "vmess" {
		return vmessToClash(link)
	}
	if scheme == "ss" {
		return ssToClash(link)
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("链接无效：%v", err)
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	name := u.Fragment
	if name == "" {
		name = u.Host
	}
	p := map[string]any{"name": name, "server": u.Hostname(), "port": port}
	pass := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		pass += ":" + pw
	}
	if v := q.Get("sni"); v != "" {
		p["sni"] = v
	} else if v := q.Get("peer"); v != "" {
		p["sni"] = v
	}
	if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("allow_insecure") == "1" {
		p["skip-cert-verify"] = true
	}
	if a := q.Get("alpn"); a != "" {
		var l []any
		for _, x := range strings.Split(a, ",") {
			l = append(l, x)
		}
		p["alpn"] = l
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if v := firstNonEmpty(q.Get("pinSHA256"), q.Get("fingerprint")); len(normFP(v)) == 64 {
		p["fingerprint"] = v // 证书 SHA256 指纹 → 导入时换成公钥固定
	}
	transport := func() {
		switch q.Get("type") {
		case "ws":
			p["network"] = "ws"
			wo := map[string]any{"path": firstNonEmpty(q.Get("path"), "/")}
			if h := q.Get("host"); h != "" {
				wo["headers"] = map[string]any{"Host": h}
			}
			p["ws-opts"] = wo
		case "grpc":
			p["network"] = "grpc"
			p["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
		case "httpupgrade":
			p["network"] = "httpupgrade"
			p["http-upgrade-opts"] = map[string]any{"path": q.Get("path"), "host": q.Get("host")}
		case "h2", "http":
			p["network"] = "h2"
			ho := map[string]any{}
			if h := q.Get("host"); h != "" {
				ho["host"] = []any{h}
			}
			if pa := q.Get("path"); pa != "" {
				ho["path"] = []any{pa}
			}
			p["h2-opts"] = ho
		case "", "tcp", "raw":
		default:
			p["network"] = q.Get("type")
		}
		switch q.Get("security") {
		case "tls":
			p["tls"] = true
		case "reality":
			p["tls"] = true
			p["reality-opts"] = map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
		}
	}
	switch scheme {
	case "hysteria2", "hy2":
		p["type"] = "hysteria2"
		p["password"] = pass
		if o := q.Get("obfs"); o != "" {
			p["obfs"] = o
			p["obfs-password"] = q.Get("obfs-password")
		}
		if mp := q.Get("mport"); mp != "" {
			p["ports"] = mp
		}
	case "vless":
		p["type"] = "vless"
		p["uuid"] = pass
		if f := q.Get("flow"); f != "" {
			p["flow"] = f
		}
		transport()
	case "trojan":
		p["type"] = "trojan"
		p["password"] = pass
		transport()
	case "anytls":
		p["type"] = "anytls"
		p["password"] = pass
		for _, k := range []string{"idle-session-check-interval", "idle-session-timeout", "min-idle-session"} {
			if v := q.Get(k); v != "" {
				p[k] = v
			}
		}
	case "tuic":
		p["type"] = "tuic"
		p["uuid"] = u.User.Username()
		p["password"], _ = u.User.Password()
		if cc := q.Get("congestion_control"); cc != "" {
			p["congestion-controller"] = cc
		}
		if m := q.Get("udp_relay_mode"); m != "" {
			p["udp-relay-mode"] = m
		}
	default:
		return nil, unsupportedScheme(scheme)
	}
	return p, nil
}

func vmessToClash(link string) (map[string]any, error) {
	b, err := b64any(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return nil, fmt.Errorf("vmess 链接 base64 无效")
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("vmess 链接 JSON 无效")
	}
	p := map[string]any{"type": "vmess", "name": str(v, "ps"), "server": str(v, "add"), "port": num(v, "port"),
		"uuid": str(v, "id"), "alterId": num(v, "aid"), "cipher": firstNonEmpty(str(v, "scy"), "auto")}
	if p["name"] == "" {
		p["name"] = str(v, "add")
	}
	if str(v, "tls") == "tls" {
		p["tls"] = true
		if s := firstNonEmpty(str(v, "sni"), str(v, "host")); s != "" {
			p["sni"] = s
		}
	}
	switch str(v, "net") {
	case "ws":
		p["network"] = "ws"
		wo := map[string]any{"path": firstNonEmpty(str(v, "path"), "/")}
		if h := str(v, "host"); h != "" {
			wo["headers"] = map[string]any{"Host": h}
		}
		p["ws-opts"] = wo
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": str(v, "path")}
	case "", "tcp":
	default:
		return nil, fmt.Errorf("vmess %s：不支持的传输 %s", p["name"], str(v, "net"))
	}
	return p, nil
}

func ssToClash(link string) (map[string]any, error) {
	rest := strings.TrimPrefix(link, "ss://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	var plugin string
	if i := strings.Index(rest, "?"); i >= 0 {
		q, _ := url.ParseQuery(rest[i+1:])
		plugin = q.Get("plugin")
		rest = strings.TrimSuffix(rest[:i], "/")
	}
	var userinfo, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hostport = rest[:at], rest[at+1:]
		if dec, err := b64any(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else {
			userinfo, _ = url.PathUnescape(userinfo)
		}
	} else {
		dec, err := b64any(rest)
		if err != nil {
			return nil, fmt.Errorf("ss 链接无效")
		}
		at := strings.LastIndex(string(dec), "@")
		if at < 0 {
			return nil, fmt.Errorf("ss 链接无效")
		}
		userinfo, hostport = string(dec[:at]), string(dec[at+1:])
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	h, pt, err := splitHostPort(hostport)
	if !ok || err != nil {
		return nil, fmt.Errorf("ss 链接无效")
	}
	if name == "" {
		name = hostport
	}
	p := map[string]any{"type": "ss", "name": name, "server": h, "port": pt, "cipher": method, "password": pass}
	if plugin != "" { // SIP003：obfs-local;obfs=http;obfs-host=x / v2ray-plugin;tls;host=x;path=/p
		parts := strings.Split(plugin, ";")
		opts := map[string]any{}
		for _, kv := range parts[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				opts[k] = true
				continue
			}
			opts[k] = v
		}
		switch parts[0] {
		case "obfs-local", "simple-obfs":
			p["plugin"] = "obfs"
			p["plugin-opts"] = map[string]any{"mode": opts["obfs"], "host": opts["obfs-host"]}
		case "v2ray-plugin":
			p["plugin"] = "v2ray-plugin"
			o := map[string]any{"mode": firstNonEmpty(fmt.Sprint(opts["mode"]), "websocket"), "tls": opts["tls"] == true}
			if opts["mode"] == nil {
				o["mode"] = "websocket"
			}
			if h, ok := opts["host"].(string); ok {
				o["host"] = h
			}
			if pa, ok := opts["path"].(string); ok {
				o["path"] = pa
			}
			p["plugin-opts"] = o
		default:
			return nil, fmt.Errorf("ss %s：不支持的插件 %s", name, parts[0])
		}
	}
	return p, nil
}

func splitHostPort(s string) (string, int, error) {
	u, err := url.Parse("x://" + s)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(u.Port())
	return u.Hostname(), p, err
}

// ---------------- 订阅管理 ----------------

type SubDiff struct {
	Format  string   `json:"format"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
	Kept    []string `json:"kept"`    // 手动/其他订阅节点，保留
	Pruned   []string `json:"pruned"`   // 将从组里移除的手选成员（组/节点）
	Filtered []string `json:"filtered"` // M7：按名称过滤掉的信息条目（官网 / 客服 / 剩余流量…）
	Warns    []string `json:"warns"`
	Total   int      `json:"total"`
}

type pendingSub struct {
	nodes []Node
	at    time.Time
}

type SubManager struct {
	d       *Daemon
	mu      sync.Mutex
	pending map[string]pendingSub
	lastTry map[string]time.Time
}

func newSubManager(d *Daemon) *SubManager {
	return &SubManager{d: d, pending: map[string]pendingSub{}, lastTry: map[string]time.Time{}}
}

func subOwner(idx int, name string) func(Node) bool {
	return func(n Node) bool {
		return n.Source == "sub:"+name || (idx == 0 && n.Source == "clash")
	}
}

func (s *SubManager) fetch(sub Sub, ua string) ([]byte, error) {
	c := s.d.conf()
	dns := c.DNS.CN[0]
	try := func(hc *http.Client) ([]byte, error) {
		req, _ := http.NewRequest("GET", sub.URL, nil)
		req.Header.Set("User-Agent", ua)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	}
	data, err := try(httpClientDirect(dns))
	if err == nil {
		return data, nil
	}
	if c.MixedListen != "" { // 直连失败 → 经代理再试
		px, _ := url.Parse("http://" + c.MixedListen)
		hc := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(px)}}
		if d2, err2 := try(hc); err2 == nil {
			return d2, nil
		}
	}
	return nil, err
}

// Preview：下载 + 解析 + 计算差异，结果暂存，Apply 时使用。
func (s *SubManager) Preview(idx int) (*SubDiff, error) {
	c := s.d.conf()
	if idx < 0 || idx >= len(c.Subs) {
		return nil, fmt.Errorf("订阅不存在")
	}
	sub := c.Subs[idx]
	// 先按 Clash 客户端请求；有的面板（如 Marzneshin）对 clash.meta 只回一个空模板 → 再按通用客户端要分享链接
	uas := []string{"clash.meta", "v2rayN/6.0"}
	if sub.UA != "" {
		uas = []string{sub.UA}
	}
	var nodes []Node
	var warns []string
	var format string
	var err error
	for i, ua := range uas {
		var data []byte
		data, err = s.fetch(sub, ua)
		if err != nil {
			err = fmt.Errorf("下载订阅失败：%v", err)
			continue
		}
		nodes, warns, format, err = parseSubscription(data)
		if err == nil && len(nodes) > 0 {
			if i > 0 {
				warns = append(warns, "「"+uas[0]+"」请求没有返回节点，已改用「"+ua+"」（分享链接格式）")
			}
			break
		}
		if err == nil {
			err = fmt.Errorf("订阅里没有节点")
		}
	}
	if err != nil {
		return nil, err
	}
	nodes, filtered := filterInfoNodes(nodes, c.importExclude())
	if len(nodes) == 0 {
		return nil, fmt.Errorf("订阅里只有信息条目，没有可用节点")
	}
	for i := range nodes {
		nodes[i].Source = "sub:" + sub.Name
	}
	warns = append(warns, resolvePins(nodes, c.Nodes, c.DNS.CN[0])...)
	diff, merged := diffSub(c, idx, nodes)
	if warns == nil {
		warns = []string{}
	}
	if filtered == nil {
		filtered = []string{}
	}
	diff.Format, diff.Warns, diff.Filtered = format, warns, filtered
	_ = merged
	s.mu.Lock()
	s.pending[sub.Name] = pendingSub{nodes: nodes, at: time.Now()}
	s.mu.Unlock()
	return diff, nil
}

func diffSub(c *Config, idx int, imported []Node) (*SubDiff, []Node) {
	sub := c.Subs[idx]
	own := subOwner(idx, sub.Name)
	old := map[string]Node{}
	for _, n := range c.Nodes {
		if own(n) {
			old[n.Name] = n
		}
	}
	d := &SubDiff{Added: []string{}, Removed: []string{}, Changed: []string{}, Kept: []string{}, Pruned: []string{}, Filtered: []string{}}
	merged := mergeSub(c.Nodes, imported, own, sub.Name)
	newNames := map[string]bool{}
	for _, n := range merged {
		newNames[n.Name] = true
	}
	for _, n := range imported {
		o, ok := old[n.Name]
		if !ok {
			d.Added = append(d.Added, n.Name)
		} else if !reflect.DeepEqual(normJSON(o.Outbound), normJSON(n.Outbound)) {
			d.Changed = append(d.Changed, n.Name)
		}
	}
	for name := range old {
		if !newNames[name] {
			d.Removed = append(d.Removed, name)
		}
	}
	for _, n := range c.Nodes {
		if !own(n) {
			d.Kept = append(d.Kept, n.Name)
		}
	}
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if _, isGroup := groupNames(c)[m]; !newNames[m] && !isGroup && m != "direct" && m != "block" {
				d.Pruned = append(d.Pruned, g.Name+" / "+m)
			}
		}
	}
	d.Total = len(imported)
	return d, merged
}

func groupNames(c *Config) map[string]bool {
	m := map[string]bool{}
	for _, g := range c.Groups {
		m[g.Name] = true
	}
	return m
}

func normJSON(v any) any {
	b, _ := json.Marshal(v)
	var o any
	json.Unmarshal(b, &o)
	return o
}

func mergeSub(old []Node, imported []Node, own func(Node) bool, subName string) []Node {
	prev := map[string]Node{}
	others := map[string]bool{}
	for _, n := range old {
		if own(n) {
			prev[n.Name] = n
		} else {
			others[n.Name] = true
		}
	}
	var out []Node
	for _, n := range imported {
		if others[n.Name] { // 和手动节点重名：改名，绝不覆盖手动节点
			n.Name = n.Name + " · " + subName
		}
		if p, ok := prev[n.Name]; ok {
			n.MTUFix = p.MTUFix
		}
		out = append(out, n)
	}
	// 保持原来非订阅节点的位置在后面
	for _, n := range old {
		if !own(n) {
			out = append(out, n)
		}
	}
	return out
}

// Apply：把 Preview 暂存的节点合并进配置并热重载。
func (s *SubManager) Apply(idx int, auto bool) (*SubDiff, error) {
	c := s.d.conf()
	if idx < 0 || idx >= len(c.Subs) {
		return nil, fmt.Errorf("订阅不存在")
	}
	sub := c.Subs[idx]
	s.mu.Lock()
	p, ok := s.pending[sub.Name]
	s.mu.Unlock()
	if !ok || time.Since(p.at) > 30*time.Minute {
		return nil, fmt.Errorf("请先点「立即更新」获取订阅（预览已过期）")
	}
	diff, _ := diffSub(c, idx, p.nodes)
	desc := fmt.Sprintf("订阅「%s」已更新：+%d −%d ~%d（共 %d 节点）", sub.Name, len(diff.Added), len(diff.Removed), len(diff.Changed), diff.Total)
	if auto {
		desc = "（自动）" + desc
	}
	err := s.d.applyEdit(applyOpts{desc: desc}, func(m map[string]any) error {
		var cur Config
		b, _ := json.Marshal(m)
		json.Unmarshal(b, &cur)
		// 找回 idx 对应订阅（按名称）
		si := -1
		for i, x := range cur.Subs {
			if x.Name == sub.Name {
				si = i
			}
		}
		if si < 0 {
			return fmt.Errorf("订阅已被删除")
		}
		merged := mergeSub(cur.Nodes, p.nodes, subOwner(si, sub.Name), sub.Name)
		names := map[string]bool{"direct": true, "block": true}
		for _, n := range merged {
			names[n.Name] = true
		}
		for _, g := range cur.Groups {
			names[g.Name] = true
		}
		for i := range cur.Groups {
			var keep []string
			for _, mb := range cur.Groups[i].Members {
				if names[mb] {
					keep = append(keep, mb)
				}
			}
			if len(keep) == 0 && strings.TrimSpace(cur.Groups[i].Filter) == "" {
				return fmt.Errorf("更新后组「%s」没有任何成员，已拒绝应用", cur.Groups[i].Name)
			}
			if keep == nil {
				keep = []string{}
			}
			cur.Groups[i].Members = keep
		}
		cur.Subs[si].Updated = time.Now().In(cst).Format("2006-01-02 15:04")
		cur.Subs[si].Count = len(p.nodes)
		cur.Subs[si].LastErr = ""
		m["nodes"] = merged
		m["groups"] = cur.Groups
		m["subscriptions"] = cur.Subs
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	delete(s.pending, sub.Name)
	s.mu.Unlock()
	return diff, nil
}

func (s *SubManager) setErr(name, msg string) {
	s.d.applyEdit(applyOpts{}, func(m map[string]any) error {
		var subs []Sub
		b, _ := json.Marshal(m["subscriptions"])
		json.Unmarshal(b, &subs)
		for i := range subs {
			if subs[i].Name == name {
				subs[i].LastErr = msg
			}
		}
		m["subscriptions"] = subs
		return nil
	})
}

// 计划更新：weekly = 每周一 08:00（上海），daily = 每天 08:00；失败每小时最多重试一次。
func subDue(sub Sub, now time.Time) bool {
	now = now.In(cst)
	var boundary time.Time
	switch sub.Auto {
	case "daily":
		boundary = time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, cst)
		if now.Before(boundary) {
			boundary = boundary.AddDate(0, 0, -1)
		}
	case "weekly":
		wd := (int(now.Weekday()) + 6) % 7 // 周一 = 0
		boundary = time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, cst).AddDate(0, 0, -wd)
		if now.Before(boundary) {
			boundary = boundary.AddDate(0, 0, -7)
		}
	default:
		return false
	}
	last, err := time.ParseInLocation("2006-01-02 15:04", sub.Updated, cst)
	return err != nil || last.Before(boundary)
}

func (s *SubManager) scheduler() {
	for {
		select {
		case <-s.d.ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
		if !s.d.coreUp.Load() {
			continue
		}
		c := s.d.conf()
		for i, sub := range c.Subs {
			if !subDue(sub, time.Now()) {
				continue
			}
			s.mu.Lock()
			lt := s.lastTry[sub.Name]
			s.mu.Unlock()
			if time.Since(lt) < time.Hour {
				continue
			}
			s.mu.Lock()
			s.lastTry[sub.Name] = time.Now()
			s.mu.Unlock()
			if _, err := s.Preview(i); err != nil {
				s.d.events.add("sub", fmt.Sprintf("订阅「%s」自动更新失败：%v", sub.Name, err))
				s.setErr(sub.Name, err.Error())
				continue
			}
			if _, err := s.Apply(i, true); err != nil {
				s.d.events.add("sub", fmt.Sprintf("订阅「%s」自动更新未应用：%v", sub.Name, err))
				s.setErr(sub.Name, err.Error())
			}
		}
	}
}
