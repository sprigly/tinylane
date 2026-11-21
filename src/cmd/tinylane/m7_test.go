package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func m7cfg() *Config {
	c := &Config{}
	for _, n := range []string{"hy2 A", "hy2 B", "vless A", "vless B", "hy2 B via A", "vless B via A", "🇭🇰 香港01", "🇭🇰 香港高倍01 3x流量", "🇯🇵 日本01"} {
		c.Nodes = append(c.Nodes, Node{Name: n, Outbound: map[string]any{"type": "anytls"}})
	}
	return c
}

func TestMembersFilterExclude(t *testing.T) {
	c := m7cfg()
	g := Group{Name: "HK", Type: "failover", Filter: "香港|日本", Exclude: "高倍"}
	eff, auto, _ := computeMembers(c, g)
	if strings.Join(eff, ",") != "🇭🇰 香港01,🇯🇵 日本01" || len(auto) != 2 {
		t.Fatalf("筛选结果不对：%v", eff)
	}
	// 手选在前、筛选在后、去重；排除对手选也生效
	g = Group{Name: "X", Members: []string{"🇯🇵 日本01", "🇭🇰 香港高倍01 3x流量"}, Filter: "/^🇭🇰/", Exclude: "3x"}
	eff, auto, hidden := computeMembers(c, g)
	if strings.Join(eff, ",") != "🇯🇵 日本01,🇭🇰 香港01" || len(auto) != 1 || len(hidden) != 1 {
		t.Fatalf("手选+正则+排除不对：eff=%v auto=%v hidden=%v", eff, auto, hidden)
	}
	if _, err := compileMatcher("/[/"); err == nil {
		t.Fatal("坏正则应报错")
	}
}

func TestSelectorStrict(t *testing.T) {
	c := m7cfg()
	c.Groups = []Group{
		{Name: "S", Type: "failover", Members: []string{"hy2 B"}, Strict: true},
		{Name: "N", Type: "failover", Members: []string{"hy2 B"}},
		{Name: "M", Type: "select", Members: []string{"hy2 B"}},
		{Name: "E1", Type: "failover", Filter: "不存在", Strict: true},
		{Name: "E2", Type: "select", Filter: "不存在"},
	}
	want := map[string]string{"S": "hy2 B", "N": "hy2 B,direct", "M": "hy2 B", "E1": "block", "E2": "direct"}
	for _, g := range c.Groups {
		obs, def := selectorOutbounds(c, g)
		if strings.Join(obs, ",") != want[g.Name] {
			t.Fatalf("%s：%v", g.Name, obs)
		}
		if g.Name == "S" && def != "hy2 B" {
			t.Fatal(def)
		}
	}
}

func TestMigrateM7(t *testing.T) {
	raw := `{"groups":[{"name":"主线路","type":"failover","members":["a"],"forbid":null},
	{"name":"指定出口","type":"failover","members":["b","c"],"forbid":["exit:A"]},
	{"name":"测速","type":"select","members":["a","b"],"forbid":null}],
	"nodes":[{"name":"a","exit":"A","outbound":{"type":"vless"}},{"name":"b","exit":"B","outbound":{"type":"vless"}},{"name":"c","exit":"B","outbound":{"type":"vless"}}],
	"subscriptions":[{"name":"主订阅","url":"https://x","exit":"h=A"}]}`
	var m map[string]any
	json.Unmarshal([]byte(raw), &m)
	ch, notes := migrateM7(m)
	if !ch || len(notes) != 3 {
		t.Fatalf("迁移说明：%v", notes)
	}
	b, _ := json.Marshal(m)
	s := string(b)
	if strings.Contains(s, "forbid") || strings.Contains(s, `"exit"`) {
		t.Fatalf("残留旧字段：%s", s)
	}
	gs := m["groups"].([]any)
	if gs[0].(map[string]any)["strict"] != true || gs[1].(map[string]any)["strict"] != true || gs[2].(map[string]any)["strict"] != nil {
		t.Fatalf("strict 不对：%s", s)
	}
	if mem := gs[1].(map[string]any)["members"].([]any); len(mem) != 2 || mem[0] != "b" || mem[1] != "c" {
		t.Fatalf("成员变了：%v", mem)
	}
	if ch2, _ := migrateM7(m); ch2 {
		t.Fatal("二次迁移应不变")
	}
}

func TestRefsAndRemove(t *testing.T) {
	c := m7cfg()
	c.MainGroup = "主线路"
	c.Groups = []Group{{Name: "主线路", Members: []string{"hy2 B"}}, {Name: "AI", Members: []string{"🇯🇵 日本01"}}, {Name: "套娃", Members: []string{"AI"}}}
	c.Rules = []Rule{{Name: "AI 站", Outbound: "AI"}, {Name: "直接用节点", Outbound: "🇭🇰 香港01"}}
	c.Devices = []Device{{Name: "iPad", Group: "AI"}}
	r := refsTo(c, "AI", true)
	if len(r) != 3 {
		t.Fatalf("引用：%v", r)
	}
	if r := refsTo(c, "主线路", true); len(r) != 1 {
		t.Fatalf("主组引用：%v", r)
	}
	if r := refsTo(c, "🇭🇰 香港01", false); len(r) != 1 {
		t.Fatalf("节点引用：%v", r)
	}
	gs, empty := removeNodesFromGroups(append([]Group{}, c.Groups...), map[string]bool{"🇯🇵 日本01": true})
	if len(empty) != 1 || empty[0] != "AI" || len(gs[1].Members) != 0 {
		t.Fatalf("删节点后空组：%v", empty)
	}
	g2 := []Group{{Name: "F", Members: []string{"🇯🇵 日本01"}, Filter: "香港"}}
	if _, e := removeNodesFromGroups(g2, map[string]bool{"🇯🇵 日本01": true}); len(e) != 0 {
		t.Fatal("有筛选的组删空手选不算空")
	}
}

func TestClashAnyTLSAndInfoFilter(t *testing.T) {
	y := `proxies:
  - {name: "邮箱客服x@gmail.com", type: vmess, server: 1.2.3.4, port: 8000, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto}
  - {name: "剩余流量：100 GB", type: vmess, server: 1.2.3.4, port: 8000, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto}
  - {name: "🇭🇰 香港01", type: anytls, server: hk.example.com, port: 443, password: pw, sni: a.example.com, alpn: [h2, http/1.1], client-fingerprint: ios, skip-cert-verify: false, fingerprint: "AB:CD:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD", idle-session-timeout: 30}
  - {name: "🇭🇰 香港高倍01 3x流量", type: anytls, server: hk2.example.com, port: 443, password: pw, sni: a.example.com}
  - {name: "老 ws", type: vmess, server: v.example.com, port: 443, uuid: 11111111-2222-3333-4444-555555555555, alterId: 0, cipher: auto, tls: true, servername: v.example.com, network: ws, ws-path: "/p?ed=2048", ws-headers: {Host: v.example.com}}
  - {name: "h1", type: hysteria, server: x, port: 1}
  - {name: "h1b", type: hysteria, server: x, port: 1}
  - {name: "wg", type: wireguard, server: x, port: 1}
proxy-groups:
  - {name: Proxies, type: select, proxies: [h1]}
`
	nodes, warns, format, err := parseSubscription([]byte(y))
	if err != nil || format != "Clash YAML" {
		t.Fatal(err, format)
	}
	all := strings.Join(warns, "\n")
	if !strings.Contains(all, "跳过 2 个 hysteria") || !strings.Contains(all, "跳过 1 个 wireguard") || !strings.Contains(all, "1 个代理组") {
		t.Fatalf("提示：%s", all)
	}
	nodes, dropped := filterInfoNodes(nodes, defaultImportExclude)
	if len(dropped) != 2 || len(nodes) != 3 {
		t.Fatalf("过滤：%v / %d", dropped, len(nodes))
	}
	a := nodes[0]
	if a.Type() != "anytls" || a.CertFP == "" || a.Outbound["idle_session_timeout"] != "30s" {
		t.Fatalf("anytls：%+v", a)
	}
	tl := a.Outbound["tls"].(M)
	if tl["server_name"] != "a.example.com" || tl["utls"] == nil || tl["insecure"] != nil {
		t.Fatalf("anytls tls：%v", tl)
	}
	ws := nodes[2].Outbound["transport"].(M)
	if ws["path"] != "/p" || ws["max_early_data"] != 2048 || ws["headers"] == nil {
		t.Fatalf("老式 ws：%v", ws)
	}
	// 3x流量 是真节点名，不能被「流量」类关键词误伤
	if nodes[1].Name != "🇭🇰 香港高倍01 3x流量" {
		t.Fatal("误过滤真节点")
	}
}

func TestLinksM7(t *testing.T) {
	cases := map[string]string{
		"anytls://pw@hk.example.com:443?sni=a.example.com&insecure=1#AT": "anytls",
		"vless://11111111-2222-3333-4444-555555555555@r.example.com:443?security=reality&pbk=PUB&sid=ab&sni=www.apple.com&fp=chrome&flow=xtls-rprx-vision&type=tcp#R": "vless",
		"trojan://pw@t.example.com:443?sni=t.example.com&type=ws&path=%2Fws&host=t.example.com#T": "trojan",
		"ss://YWVzLTEyOC1nY206cHc@s.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dx.com#S":  "shadowsocks",
		"tuic://11111111-2222-3333-4444-555555555555:pw@q.example.com:443?sni=q.example.com&congestion_control=bbr#Q": "tuic",
		"hysteria2://pw@h.example.com:443?sni=h.example.com#H": "hysteria2",
	}
	var text []string
	for l, typ := range cases {
		n, err := linkToNode(l)
		if err != nil || n.Type() != typ {
			t.Fatalf("%s → %v %v", l, n.Type(), err)
		}
		text = append(text, l)
	}
	n, _ := linkToNode("vless://11111111-2222-3333-4444-555555555555@r.example.com:443?security=reality&pbk=PUB&sid=ab&sni=www.apple.com&fp=chrome#R")
	if r := n.Outbound["tls"].(M)["reality"]; r == nil {
		t.Fatal("reality 丢了")
	}
	n, _ = linkToNode("ss://YWVzLTEyOC1nY206cHc@s.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dx.com#S")
	if n.Outbound["plugin"] != "obfs-local" || !strings.Contains(n.Outbound["plugin_opts"].(string), "obfs-host=x.com") {
		t.Fatalf("ss 插件：%v", n.Outbound)
	}
	text = append(text, "hysteria://x@y:1#old", "wireguard://x@y:1#wg", "ssr://abc")
	nodes, warns, _, err := parseSubscription([]byte(strings.Join(text, "\n")))
	if err != nil || len(nodes) != len(cases) || !strings.Contains(strings.Join(warns, "|"), "跳过 1 个 hysteria") {
		t.Fatalf("链接订阅：%d %v %v", len(nodes), warns, err)
	}
}

func TestConfigM7Validate(t *testing.T) {
	dir := t.TempDir()
	write := func(js string) error {
		p := filepath.Join(dir, "c.json")
		os.WriteFile(p, []byte(js), 0o600)
		_, err := loadConfig(p)
		return err
	}
	base := `"clash_api":{"secret":"x"},"nodes":[{"name":"a","outbound":{"type":"vless"}}]`
	if err := write(`{` + base + `,"groups":[{"name":"G","type":"failover","members":[],"filter":"a"}]}`); err != nil {
		t.Fatal("只有筛选的组应通过：", err)
	}
	if err := write(`{` + base + `,"groups":[{"name":"G","type":"failover","members":[]}]}`); err == nil {
		t.Fatal("没成员也没筛选应拒绝")
	}
	if err := write(`{` + base + `,"groups":[{"name":"G","type":"failover","members":["a"],"exclude":"/(/"}]}`); err == nil {
		t.Fatal("坏正则应拒绝")
	}
	// 旧配置（forbid + exit）兼容读入：forbid 不再生效，不报错
	if err := write(`{"clash_api":{"secret":"x"},"nodes":[{"name":"a","exit":"A","outbound":{"type":"vless"}}],"groups":[{"name":"G","type":"failover","members":["a"],"forbid":["exit:A"]}]}`); err != nil {
		t.Fatal("旧配置应能读入：", err)
	}
}
