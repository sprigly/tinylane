package main

// M7：通用组成员规则 + 配置迁移 + 引用检查 + 订阅信息条目过滤 + 不支持类型汇总 + 证书指纹固定。
//
// 组成员 = 手选成员（members，有序）+ 名称筛选自动加入的节点（filter，按节点列表顺序），再去掉名称排除命中的（exclude，对手选也生效）。
// 订阅更新 / 删节点后成员自动重算（筛选结果不落盘，生成配置时现算）。
// strict（断网保护）：组里没有可用节点时不回落直连——成员为空生成 block；故障切换组不会被切到直连。
// 非 strict 的故障切换组：内核里多一个隐藏的 direct 候选，看门狗在全部节点都不可用（且国内直连正常）时切到直连，节点恢复后切回。
// 旧的 forbid（如 exit:<出口>）和节点 exit 标签不再参与分组：迁移时 forbid → strict，成员保持原样，exit 字段删除。

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const configVersion = 7

// 订阅里常见的「信息条目」（官网 / 客服 / 剩余流量 / 到期…），按名称关键词过滤（| 分隔，不区分大小写；/正则/ 也可以）
const defaultImportExclude = "官网|网址|客服|邮箱|剩余流量|剩余|到期|过期|套餐|支持AI|重置|公告|官方群|Expire|Traffic"

// ---------- 名称匹配：关键词（| , ，分隔，子串、不区分大小写）或 /正则/ ----------

type nameMatcher struct {
	re   *regexp.Regexp
	keys []string
}

var matcherCache sync.Map // string → *nameMatcher

func compileMatcher(p string) (*nameMatcher, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, nil
	}
	if v, ok := matcherCache.Load(p); ok {
		return v.(*nameMatcher), nil
	}
	if len(p) > 256 {
		return nil, fmt.Errorf("太长（最多 256 字符）")
	}
	m := &nameMatcher{}
	if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
		re, err := regexp.Compile("(?i)" + p[1:len(p)-1])
		if err != nil {
			return nil, fmt.Errorf("正则无效：%v", err)
		}
		m.re = re
	} else {
		for _, k := range strings.FieldsFunc(p, func(r rune) bool { return r == '|' || r == ',' || r == '，' }) {
			if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
				m.keys = append(m.keys, k)
			}
		}
		if len(m.keys) == 0 {
			return nil, nil
		}
	}
	matcherCache.Store(p, m)
	return m, nil
}

func (m *nameMatcher) match(s string) bool {
	if m == nil {
		return false
	}
	if m.re != nil {
		return m.re.MatchString(s)
	}
	l := strings.ToLower(s)
	for _, k := range m.keys {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

// ---------- 组的实际成员 ----------

// computeMembers：手选（排除命中的去掉）+ 筛选命中的节点（排除命中的去掉），去重，顺序 = 手选顺序，再节点列表顺序。
func computeMembers(c *Config, g Group) (eff, auto, hidden []string) {
	inc, _ := compileMatcher(g.Filter)
	exc, _ := compileMatcher(g.Exclude)
	seen := map[string]bool{}
	for _, m := range g.Members {
		if seen[m] {
			continue
		}
		seen[m] = true
		if exc.match(m) {
			hidden = append(hidden, m)
			continue
		}
		eff = append(eff, m)
	}
	if inc != nil {
		for _, n := range c.Nodes {
			if seen[n.Name] || !inc.match(n.Name) || exc.match(n.Name) {
				continue
			}
			seen[n.Name] = true
			eff = append(eff, n.Name)
			auto = append(auto, n.Name)
		}
	}
	return
}

// members：组名 → 实际成员（loadConfig 后缓存在 c.eff；测试里直接构造的 Config 现算）
func (c *Config) members(name string) []string {
	if c.eff != nil {
		return c.eff[name]
	}
	for _, g := range c.Groups {
		if g.Name == name {
			e, _, _ := computeMembers(c, g)
			return e
		}
	}
	return nil
}

func (c *Config) computeEff() {
	c.eff = map[string][]string{}
	for _, g := range c.Groups {
		e, _, _ := computeMembers(c, g)
		c.eff[g.Name] = e
	}
}

// selectorOutbounds：内核 selector 的候选列表（含空组兜底和非 strict 故障切换组的隐藏直连）
func selectorOutbounds(c *Config, g Group) (obs []string, def string) {
	mem := c.members(g.Name)
	if len(mem) == 0 {
		if g.Strict {
			return []string{"block"}, "block"
		}
		return []string{"direct"}, "direct"
	}
	obs = append([]string{}, mem...)
	if !g.Strict && g.Type == "failover" && indexOf(obs, "direct") < 0 {
		obs = append(obs, "direct")
	}
	return obs, mem[0]
}

// ---------- 迁移（M6d 及更早 → M7）----------

// migrateM7：在原始 JSON 上做；返回是否改动和说明。
//   - forbid 非空的组 → strict（断网保护），成员保持原样（原来的成员本来就都满足禁止规则）
//   - 其他故障切换组 → strict（保持原来「全部节点不可用也不走直连」的行为，用户可在面板关掉）
//   - 删除所有组的 forbid、节点的 exit、订阅的 exit（不再使用，不留孤立字段）
func migrateM7(m map[string]any) (bool, []string) {
	switch v := m["config_version"].(type) {
	case float64:
		if int(v) >= configVersion {
			return false, nil
		}
	case int:
		if v >= configVersion {
			return false, nil
		}
	}
	var notes []string
	gs, _ := m["groups"].([]any)
	for _, x := range gs {
		g, _ := x.(map[string]any)
		if g == nil {
			continue
		}
		name := fmt.Sprint(g["name"])
		fb, _ := g["forbid"].([]any)
		if len(fb) > 0 {
			g["strict"] = true
			var fs []string
			for _, f := range fb {
				fs = append(fs, fmt.Sprint(f))
			}
			notes = append(notes, fmt.Sprintf("组「%s」：禁止规则 %s 已去掉，改为只用现有 %d 个成员 + 断网保护", name, strings.Join(fs, "、"), len(asList(g["members"]))))
		} else if g["type"] == "failover" {
			if _, ok := g["strict"]; !ok {
				g["strict"] = true
				notes = append(notes, fmt.Sprintf("组「%s」：开启断网保护（保持原来全部节点不可用也不走直连的行为）", name))
			}
		}
		delete(g, "forbid")
	}
	ne := 0
	if ns, ok := m["nodes"].([]any); ok {
		for _, x := range ns {
			if n, _ := x.(map[string]any); n != nil {
				if _, ok := n["exit"]; ok {
					delete(n, "exit")
					ne++
				}
			}
		}
	}
	if ne > 0 {
		notes = append(notes, fmt.Sprintf("%d 个节点的手填出口标签已删除（改为自动检测）", ne))
	}
	if ss, ok := m["subscriptions"].([]any); ok {
		for _, x := range ss {
			if s, _ := x.(map[string]any); s != nil {
				delete(s, "exit")
			}
		}
	}
	m["config_version"] = configVersion
	return true, notes
}

func asList(v any) []any { l, _ := v.([]any); return l }

// ---------- 引用检查（删组 / 删节点前）----------

// refsTo：除了组成员以外，还有谁把 name 当去向（规则 / 规则集 / 设备 / 主组 / 全局组 / DNS）
func refsTo(c *Config, name string, withGroups bool) []string {
	var out []string
	if c.MainGroup == name {
		out = append(out, "规则模式的默认出口（主组）")
	}
	if c.GlobalGroup == name && c.GlobalGroup != c.MainGroup {
		out = append(out, "全局代理模式的出口")
	}
	if c.DNS.Detour == name && c.DNS.Detour != c.MainGroup {
		out = append(out, "国外 DNS 的出口")
	}
	for i, r := range c.Rules {
		if r.Outbound == name {
			n := r.Name
			if n == "" {
				n = fmt.Sprintf("#%d", i+1)
			}
			out = append(out, "规则「"+n+"」")
		}
	}
	for _, r := range c.CustomRuleSets {
		if r.Outbound == name {
			out = append(out, "规则集「"+r.Name+"」")
		}
	}
	for _, d := range c.Devices {
		if d.Group == name {
			out = append(out, "设备「"+d.Name+"」")
		}
	}
	if withGroups {
		for _, g := range c.Groups {
			if g.Name != name && indexOf(g.Members, name) >= 0 {
				out = append(out, "组「"+groupLabel(g)+"」的成员")
			}
		}
	}
	return out
}

func groupLabel(g Group) string {
	if g.Label != "" {
		return g.Label
	}
	return g.Name
}

// removeNodesFromGroups：从所有组的手选成员里去掉这些节点；返回会变空（无手选、无筛选）的组
func removeNodesFromGroups(groups []Group, gone map[string]bool) ([]Group, []string) {
	var empty []string
	for i := range groups {
		var mem []string
		for _, x := range groups[i].Members {
			if !gone[x] {
				mem = append(mem, x)
			}
		}
		if len(mem) == 0 && strings.TrimSpace(groups[i].Filter) == "" {
			empty = append(empty, groupLabel(groups[i]))
		}
		if mem == nil {
			mem = []string{}
		}
		groups[i].Members = mem
	}
	return groups, empty
}

// ---------- 订阅：信息条目过滤 ----------

func (c *Config) importExclude() string {
	if c.ImportExclude == nil {
		return defaultImportExclude
	}
	return *c.ImportExclude
}

func filterInfoNodes(nodes []Node, pattern string) ([]Node, []string) {
	m, err := compileMatcher(pattern)
	if err != nil || m == nil {
		return nodes, nil
	}
	var keep []Node
	var dropped []string
	for _, n := range nodes {
		if m.match(n.Name) {
			dropped = append(dropped, n.Name)
			continue
		}
		keep = append(keep, n)
	}
	return keep, dropped
}

// 不支持的类型汇总：「跳过 2 个 hysteria（内核不支持）」
type skipCounter map[string]int

func (s skipCounter) warns() []string {
	var out []string
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, fmt.Sprintf("跳过 %d 个 %s（TinyLane 内核不支持这种类型）", s[k], k))
	}
	return out
}

var supportedTypes = map[string]bool{"hysteria2": true, "hy2": true, "vless": true, "vmess": true, "trojan": true, "ss": true, "shadowsocks": true, "tuic": true, "anytls": true}

// ---------- 证书指纹固定（Clash 的 fingerprint = 证书 SHA256）----------
// sing-box 只支持公钥 SHA256 固定：导入时连一次服务器，证书 SHA256 与订阅给的指纹一致才把它的公钥 SHA256 写进
// tls.certificate_public_key_sha256（安全性等同于 Clash 的指纹校验）。连不上 / 不一致的不放宽校验，只提示。

func normFP(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

type pinJob struct {
	idx            int
	server, sni    string
	port           int
	fp             string
	alpn           []string
}

// resolvePins：nodes 里带 CertFP 的 → 同名旧节点指纹没变且已有公钥 → 直接沿用；否则连服务器确认（并发 4，每个 5 s，连不上重试一次）
func resolvePins(nodes []Node, prev []Node, dnsServer string) []string {
	old := map[string]Node{}
	for _, n := range prev {
		old[n.Name] = n
	}
	var jobs []pinJob
	for i := range nodes {
		n := &nodes[i]
		if n.CertFP == "" {
			continue
		}
		t, _ := n.Outbound["tls"].(M)
		if t == nil {
			continue
		}
		if o, ok := old[n.Name]; ok && o.CertFP == n.CertFP && o.Outbound["server"] == n.Outbound["server"] {
			if ot, _ := o.Outbound["tls"].(map[string]any); ot != nil && ot["certificate_public_key_sha256"] != nil {
				t["certificate_public_key_sha256"] = ot["certificate_public_key_sha256"]
				continue
			}
		}
		sni, _ := t["server_name"].(string)
		srv, _ := n.Outbound["server"].(string)
		port, _ := n.Outbound["server_port"].(int)
		var alpn []string
		if a, ok := t["alpn"].([]string); ok {
			alpn = a
		}
		jobs = append(jobs, pinJob{i, srv, firstNonEmpty(sni, srv), port, normFP(n.CertFP), alpn})
	}
	if len(jobs) == 0 {
		return nil
	}
	var mu sync.Mutex
	var fails []string
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j pinJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pin, err := fetchPin(j, dnsServer)
			if err != nil && err.Error() == "连不上" { // 偶发超时：隔 1 s 再试一次
				time.Sleep(time.Second)
				pin, err = fetchPin(j, dnsServer)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fails = append(fails, nodes[j.idx].Name+"（"+err.Error()+"）")
				return
			}
			nodes[j.idx].Outbound["tls"].(M)["certificate_public_key_sha256"] = []string{pin}
		}(j)
	}
	wg.Wait()
	if len(fails) == 0 {
		return nil
	}
	sort.Strings(fails)
	if len(fails) > 6 {
		fails = append(fails[:6], fmt.Sprintf("等 %d 个", len(fails)))
	}
	return []string{fmt.Sprintf("证书指纹没能确认，这些节点暂时连不上（不会放宽证书校验，下次更新订阅再试）：%s", strings.Join(fails, "、"))}
}

func fetchPin(j pinJob, dnsServer string) (string, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if dnsServer != "" && net.ParseIP(dnsServer) != nil {
		d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx_ context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx_, "udp", net.JoinHostPort(dnsServer, "53"))
		}}
	}
	conn, err := tls.DialWithDialer(d, "tcp4", net.JoinHostPort(j.server, fmt.Sprint(j.port)), &tls.Config{ServerName: j.sni, InsecureSkipVerify: true, NextProtos: j.alpn})
	if err != nil {
		return "", fmt.Errorf("连不上")
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("没有证书")
	}
	sum := sha256.Sum256(certs[0].Raw)
	if hex.EncodeToString(sum[:]) != j.fp {
		return "", fmt.Errorf("指纹不一致")
	}
	pk, err := x509.MarshalPKIXPublicKey(certs[0].PublicKey)
	if err != nil {
		return "", fmt.Errorf("公钥无法解析")
	}
	ps := sha256.Sum256(pk)
	return base64.StdEncoding.EncodeToString(ps[:]), nil
}

// nodeFP：节点参数指纹（参数变了要重新测出口）
func nodeFP(n Node) string {
	b, _ := json.Marshal(normJSON(n.Outbound))
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:6])
}
