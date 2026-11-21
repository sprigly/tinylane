package main

// M6：远程规则集、导入（订阅/配置/规则，先预览后应用）、高级模式（原始 JSON 编辑 + 90 秒未确认自动回滚）、
// 安全保护（导入/高级模式不能删掉禁止规则和固定规则）、看门狗「上游整体断网不切换」判定。

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

// ---------------- 远程规则集 ----------------

func customRSTag(r CustomRuleSet) string { return "rs-custom-" + shortHash(r.Name) }

func customRSPath(c *Config, r CustomRuleSet) string {
	ext := ".srs"
	if r.Format == "source" {
		ext = ".json"
	}
	return filepath.Join(c.RuleSets.Dir, "custom", shortHash(r.Name)+ext)
}

func shortHash(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:5])
}

type rsStat struct{ count int; dom, ip bool }

// parseRuleSet：用 sing-box 自己的解析器校验（和内核加载用的是同一份代码），并统计条数。
func parseRuleSet(format string, data []byte) (rsStat, error) {
	var st rsStat
	if len(data) == 0 {
		return st, fmt.Errorf("文件为空")
	}
	if len(data) > 4<<20 {
		return st, fmt.Errorf("文件超过 4 MB（路由器闪存有限）")
	}
	var compat option.PlainRuleSetCompat
	var err error
	if format == "binary" {
		if !validSRS(data) {
			return st, fmt.Errorf("不是 .srs 二进制规则集（文件头不是 SRS）")
		}
		compat, err = srs.Read(bytes.NewReader(data), true)
	} else {
		compat, err = sjson.UnmarshalExtended[option.PlainRuleSetCompat](data)
	}
	if err != nil {
		return st, fmt.Errorf("规则集解析失败：%v", err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return st, err
	}
	if len(plain.Rules) == 0 {
		return st, fmt.Errorf("规则集里没有规则")
	}
	var walk func(rs []option.HeadlessRule)
	walk = func(rs []option.HeadlessRule) {
		for _, r := range rs {
			if r.Type == "logical" {
				walk(r.LogicalOptions.Rules)
				continue
			}
			o := r.DefaultOptions
			nd := len(o.Domain) + len(o.DomainSuffix) + len(o.DomainKeyword) + len(o.DomainRegex)
			ni := len(o.IPCIDR)
			st.count += nd + ni
			if nd > 0 {
				st.dom = true
			}
			if ni > 0 {
				st.ip = true
			}
			if nd+ni == 0 {
				st.count++
			}
		}
	}
	walk(plain.Rules)
	return st, nil
}

type RuleSetManager struct {
	d       *Daemon
	mu      sync.Mutex
	lastTry map[string]time.Time
}

func newRuleSetManager(d *Daemon) *RuleSetManager {
	return &RuleSetManager{d: d, lastTry: map[string]time.Time{}}
}

func findRS(c *Config, name string) (CustomRuleSet, bool) {
	for _, r := range c.CustomRuleSets {
		if r.Name == name {
			return r, true
		}
	}
	return CustomRuleSet{}, false
}

// Update：下载 → 校验 → 写文件（留 .prev）→ 写回统计（applyEdit 负责 check + 热重载）。失败时恢复旧文件。
func (m *RuleSetManager) Update(name string) (CustomRuleSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.d.conf()
	r, ok := findRS(c, name)
	if !ok {
		return r, fmt.Errorf("没有规则集 %q", name)
	}
	data, err := m.d.subs.fetch(Sub{URL: r.URL}, "tinylane/"+tlVersion)
	if err == nil {
		var st rsStat
		st, err = parseRuleSet(r.Format, data)
		if err == nil {
			err = m.install(c, r, data, st)
		}
	}
	if err != nil {
		m.setErr(name, err.Error())
		m.d.events.add("config", fmt.Sprintf("规则集「%s」更新失败：%v", name, err))
		r.LastErr = err.Error()
		return r, err
	}
	nc := m.d.conf()
	r, _ = findRS(nc, name)
	return r, nil
}

func (m *RuleSetManager) install(c *Config, r CustomRuleSet, data []byte, st rsStat) error {
	path := customRSPath(c, r)
	old, oldErr := os.ReadFile(path)
	if oldErr == nil && bytes.Equal(old, data) {
		return m.d.applyEdit(applyOpts{}, func(mm map[string]any) error { return setRSFields(mm, r.Name, st, "") })
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return err
	}
	restore := func() {
		if oldErr == nil {
			writeFileAtomic(path, old, 0o644)
		} else {
			os.Remove(path)
		}
	}
	existed := oldErr == nil
	err := m.d.applyEdit(applyOpts{desc: fmt.Sprintf("规则集「%s」已更新（%d 条）", r.Name, st.count)}, func(mm map[string]any) error {
		return setRSFields(mm, r.Name, st, "")
	})
	if err != nil && err != errNoChange {
		restore()
		return err
	}
	if existed {
		// 内容变了但 sing-box 配置没变：内核的本地规则集有文件监听会自动重载；保险起见再做一次 check
		if cerr := m.d.checkCurrent(); cerr != nil {
			restore()
			return fmt.Errorf("新规则集让内核检查失败，已恢复旧文件：%v", cerr)
		}
	}
	return nil
}

func setRSFields(mm map[string]any, name string, st rsStat, lastErr string) error {
	list, _ := mm["rule_sets"].([]any)
	for _, x := range list {
		o, _ := x.(map[string]any)
		if o == nil || o["name"] != name {
			continue
		}
		if lastErr != "" {
			o["last_error"] = lastErr
			return nil
		}
		o["updated"] = time.Now().In(cst).Format("2006-01-02 15:04")
		o["count"] = st.count
		o["has_domain"] = st.dom
		o["has_ip"] = st.ip
		delete(o, "last_error")
		return nil
	}
	return fmt.Errorf("规则集 %q 已被删除", name)
}

func (m *RuleSetManager) setErr(name, msg string) {
	m.d.applyEdit(applyOpts{}, func(mm map[string]any) error { return setRSFields(mm, name, rsStat{}, msg) })
}

func rsDue(r CustomRuleSet, now time.Time) bool {
	if r.Disabled || r.Update == "off" {
		return false
	}
	last, err := time.ParseInLocation("2006-01-02 15:04", r.Updated, cst)
	if err != nil {
		return true
	}
	age := now.Sub(last)
	if r.Update == "daily" {
		return age > 23*time.Hour
	}
	return age > 7*24*time.Hour-time.Hour
}

// scheduler：每 10 分钟看一次；已下载过的只在上海时间 04:00–06:00 更新（热重载会断开现有连接），没下载过的随时下。
func (m *RuleSetManager) scheduler() {
	for {
		select {
		case <-m.d.ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
		if !m.d.coreUp.Load() {
			continue
		}
		c := m.d.conf()
		now := time.Now()
		h := now.In(cst).Hour()
		for _, r := range c.CustomRuleSets {
			if !rsDue(r, now) {
				continue
			}
			if r.Updated != "" && (h < 4 || h >= 6) {
				continue
			}
			m.mu.Lock()
			lt := m.lastTry[r.Name]
			if time.Since(lt) < time.Hour {
				m.mu.Unlock()
				continue
			}
			m.lastTry[r.Name] = now
			m.mu.Unlock()
			m.Update(r.Name)
		}
	}
}

// checkCurrent：用当前配置重新生成并跑一次 tinylane check（含本地规则集文件）。
func (d *Daemon) checkCurrent() error {
	data, err := genSB(d.conf())
	if err != nil {
		return err
	}
	return d.checkSB(data)
}

// ---------------- 安全保护 ----------------

// protectInvariants：整份替换配置（导入 / 高级模式）时，不允许删除、关闭或改去向固定（pin）规则，
// 也不允许去掉远程运维链路的永久直连。（M7：组的成员规则都可以在面板里改，不再有写死的出口禁止规则。）
func protectInvariants(old, nw *Config) error {
	for _, r := range old.Rules {
		if !r.Pin || r.Disabled {
			continue
		}
		found := false
		for _, x := range nw.Rules {
			if x.Name == r.Name && x.Pin && !x.Disabled && x.Outbound == r.Outbound {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("安全保护：不能删除、关闭或改去向固定规则「%s」", r.Name)
		}
	}
	for _, b := range builtinBypassCIDR {
		ok := false
		for _, x := range nw.AlwaysBypass.CIDR {
			if x == b {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("安全保护：远程运维链路 %s 必须永久直连", b)
		}
	}
	return nil
}

// ---------------- 高级模式（原始 JSON） ----------------

const maskSecret = "********"

type RawPending struct {
	mu       sync.Mutex
	prev     []byte
	deadline time.Time
	timer    *time.Timer
}

func (d *Daemon) rawText() (string, string, error) {
	raw, err := os.ReadFile(d.cfgPath)
	if err != nil {
		return "", "", err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}
	if ca, ok := m["clash_api"].(map[string]any); ok && ca["secret"] != nil {
		ca["secret"] = maskSecret
	}
	if pm, ok := m["panel"].(map[string]any); ok {
		delete(pm, "password_hash")
	}
	sb, _ := os.ReadFile(d.sbPath)
	var sm map[string]any
	sbText := ""
	if json.Unmarshal(sb, &sm) == nil {
		if ex, ok := sm["experimental"].(map[string]any); ok {
			if ca, ok := ex["clash_api"].(map[string]any); ok {
				ca["secret"] = maskSecret
			}
		}
		sbText = string(marshal(sm))
	}
	return string(marshal(m)), sbText, nil
}

// parseRawCandidate：把面板提交的 JSON 变成候选配置（掩码的 secret 换回真值，面板哈希保留），校验 + 安全保护 + 生成。
func (d *Daemon) parseRawCandidate(text string) (map[string]any, *Config, error) {
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(text))
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("JSON 语法错误：%v", jsonErrPos(text, err))
	}
	if m == nil {
		return nil, nil, fmt.Errorf("必须是一个 JSON 对象")
	}
	orig, err := os.ReadFile(d.cfgPath)
	if err != nil {
		return nil, nil, err
	}
	var om map[string]any
	json.Unmarshal(orig, &om)
	ca, _ := m["clash_api"].(map[string]any)
	oca, _ := om["clash_api"].(map[string]any)
	if ca == nil {
		ca = map[string]any{}
		m["clash_api"] = ca
	}
	if s, _ := ca["secret"].(string); s == "" || s == maskSecret {
		if oca != nil {
			ca["secret"] = oca["secret"]
		}
	}
	if pm, ok := om["panel"].(map[string]any); ok {
		if h, ok := pm["password_hash"]; ok {
			npm, _ := m["panel"].(map[string]any)
			if npm == nil {
				npm = map[string]any{}
				m["panel"] = npm
			}
			npm["password_hash"] = h
		}
	}
	tmp := filepath.Join(d.runDir, "raw-candidate.json")
	if err := writeFileAtomic(tmp, marshal(m), 0o600); err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmp)
	c, err := loadConfig(tmp)
	if err != nil {
		return nil, nil, err
	}
	if err := protectInvariants(d.conf(), c); err != nil {
		return nil, nil, err
	}
	if _, err := genSB(c); err != nil {
		return nil, nil, err
	}
	return m, c, nil
}

var reOffset = regexp.MustCompile(`offset (\d+)`)

func jsonErrPos(text string, err error) string {
	if se, ok := err.(*json.SyntaxError); ok {
		line := 1 + strings.Count(text[:min(int(se.Offset), len(text))], "\n")
		return fmt.Sprintf("第 %d 行：%v", line, err)
	}
	return err.Error()
}

func summarize(old, nw *Config) []string {
	var out []string
	cnt := func(label string, a, b int) {
		if a != b {
			out = append(out, fmt.Sprintf("%s：%d → %d", label, a, b))
		}
	}
	cnt("节点", len(old.Nodes), len(nw.Nodes))
	cnt("组", len(old.Groups), len(nw.Groups))
	cnt("规则", len(old.Rules), len(nw.Rules))
	cnt("规则集", len(old.CustomRuleSets), len(nw.CustomRuleSets))
	cnt("订阅", len(old.Subs), len(nw.Subs))
	cnt("设备设置", len(old.Devices), len(nw.Devices))
	if old.Mode != nw.Mode {
		out = append(out, "运行模式："+modeCN(old.Mode)+" → "+modeCN(nw.Mode))
	}
	if old.Enabled != nw.Enabled {
		out = append(out, fmt.Sprintf("总开关：%v → %v", old.Enabled, nw.Enabled))
	}
	if old.MainGroup != nw.MainGroup {
		out = append(out, "主线路组："+old.MainGroup+" → "+nw.MainGroup)
	}
	if !bytes.Equal([]byte(buildNft(old)), []byte(buildNft(nw))) {
		out = append(out, "透明代理 nft 规则会重载")
	}
	ob, _ := genSB(old)
	nb, _ := genSB(nw)
	if !bytes.Equal(marshal(ob), marshal(nb)) {
		out = append(out, "内核配置会热重载（现有连接会重建一次）")
	}
	if len(out) == 0 {
		out = []string{"没有实际变化"}
	}
	return out
}

func (d *Daemon) rawCheck(text string) (map[string]any, error) {
	_, c, err := d.parseRawCandidate(text)
	if err != nil {
		return nil, err
	}
	data, _ := genSB(c)
	if err := d.checkSB(data); err != nil {
		return nil, fmt.Errorf("内核检查失败：%v", err)
	}
	return map[string]any{"ok": true, "summary": summarize(d.conf(), c)}, nil
}

// rawApply：应用 + 90 秒确认窗口。面板（或 POST /raw/confirm）不确认 → 自动恢复原配置。
func (d *Daemon) rawApply(text string, window time.Duration) (map[string]any, error) {
	d.raw.mu.Lock()
	busy := d.raw.timer != nil
	d.raw.mu.Unlock()
	if busy {
		return nil, fmt.Errorf("上一次高级模式改动还在等待确认")
	}
	m, c, err := d.parseRawCandidate(text)
	if err != nil {
		return nil, err
	}
	sum := summarize(d.conf(), c)
	orig, _ := os.ReadFile(d.cfgPath)
	if err := d.applyEdit(applyOpts{desc: "高级模式：已应用原始配置（等待确认）"}, func(mm map[string]any) error {
		for k := range mm {
			delete(mm, k)
		}
		for k, v := range m {
			mm[k] = v
		}
		return nil
	}); err != nil {
		return nil, err
	}
	d.raw.mu.Lock()
	d.raw.prev = orig
	d.raw.deadline = time.Now().Add(window)
	d.raw.timer = time.AfterFunc(window, func() { d.rawRollback("未在规定时间内确认") })
	dl := d.raw.deadline.Unix()
	d.raw.mu.Unlock()
	return map[string]any{"ok": true, "confirm_by": dl, "summary": sum}, nil
}

func (d *Daemon) rawConfirm() error {
	d.raw.mu.Lock()
	defer d.raw.mu.Unlock()
	if d.raw.timer == nil {
		return fmt.Errorf("没有等待确认的改动")
	}
	d.raw.timer.Stop()
	d.raw.timer, d.raw.prev = nil, nil
	d.events.add("config", "高级模式改动已确认保留")
	return nil
}

func (d *Daemon) rawRollback(why string) error {
	d.raw.mu.Lock()
	prev := d.raw.prev
	if d.raw.timer != nil {
		d.raw.timer.Stop()
	}
	d.raw.timer, d.raw.prev = nil, nil
	d.raw.mu.Unlock()
	if prev == nil {
		return fmt.Errorf("没有可回滚的改动")
	}
	var pm map[string]any
	json.Unmarshal(prev, &pm)
	err := d.applyEdit(applyOpts{desc: "高级模式改动已回滚（" + why + "）"}, func(mm map[string]any) error {
		for k := range mm {
			delete(mm, k)
		}
		for k, v := range pm {
			mm[k] = v
		}
		return nil
	})
	if err != nil && err != errNoChange {
		d.events.add("error", "高级模式回滚失败："+err.Error())
	}
	return err
}

func (d *Daemon) rawPending() int64 {
	d.raw.mu.Lock()
	defer d.raw.mu.Unlock()
	if d.raw.timer == nil {
		return 0
	}
	return d.raw.deadline.Unix()
}

// ---------------- 导入 ----------------

type importPlan struct {
	Kind     string           `json:"kind"`
	Nodes    []importNodeView `json:"nodes"`
	Rules    []Rule           `json:"rules"`
	RuleSkip int              `json:"rule_skipped"`
	Warns    []string         `json:"warns"`
	Summary  []string         `json:"summary"`
	Token    string           `json:"token"`
	NeedOut  bool             `json:"need_target"` // 规则里有「代理」类去向，需要选组
	full     map[string]any
	nodes    []Node
	rawRules []clashRule
}

type importNodeView struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Action string `json:"action"` // add | same | rename
}

type clashRule struct {
	kind, val, target string
}

type ImportManager struct {
	mu      sync.Mutex
	pending map[string]*importPlan
	at      map[string]time.Time
}

func newImportManager() *ImportManager {
	return &ImportManager{pending: map[string]*importPlan{}, at: map[string]time.Time{}}
}

func randToken() string {
	var b [9]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Clash 规则行：DOMAIN-SUFFIX,x.com,Proxy / IP-CIDR,1.2.3.0/24,DIRECT,no-resolve；纯域名列表（每行一个）也接受
func parseRuleLines(s string) ([]clashRule, int) {
	var out []clashRule
	skip := 0
	inRules := !strings.Contains(s, "rules:")
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "rules:") {
			inRules = true
			continue
		}
		if !inRules {
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '-' && line[0] != '\t' && !strings.HasPrefix(t, "#") && strings.HasSuffix(t, ":") {
			inRules = false // 下一个顶层键
			continue
		}
		t = strings.TrimSpace(strings.TrimPrefix(t, "-"))
		t = strings.Trim(t, `'"`)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		parts := strings.Split(t, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) == 1 {
			v := strings.TrimPrefix(strings.TrimPrefix(parts[0], "+."), ".")
			if _, err := parsePrefix(v); err == nil && strings.Contains(v, "/") {
				out = append(out, clashRule{"ip_cidr", v, ""})
			} else if isDomainLike(v) {
				out = append(out, clashRule{"domain_suffix", strings.ToLower(v), ""})
			} else {
				skip++
			}
			continue
		}
		kind := map[string]string{"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
			"IP-CIDR": "ip_cidr", "IP-CIDR6": "", "DOMAIN-REGEX": "domain_regex"}[strings.ToUpper(parts[0])]
		if kind == "" || len(parts) < 2 {
			skip++
			continue
		}
		tgt := ""
		if len(parts) >= 3 {
			tgt = parts[2]
		}
		out = append(out, clashRule{kind, parts[1], tgt})
	}
	return out, skip
}

var reDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

func isDomainLike(s string) bool { return len(s) < 254 && reDomain.MatchString(s) }

func mapTarget(t, proxyTarget string) string {
	switch strings.ToUpper(t) {
	case "DIRECT":
		return "direct"
	case "REJECT", "REJECT-DROP", "REJECT-TINYGIF":
		return "block"
	}
	return proxyTarget
}

// Preview：识别格式 → 生成计划（不改任何东西）
func (im *ImportManager) Preview(d *Daemon, text, srcURL string) (*importPlan, error) {
	if srcURL != "" {
		if !(strings.HasPrefix(srcURL, "https://") || strings.HasPrefix(srcURL, "http://")) {
			return nil, fmt.Errorf("URL 必须以 http(s):// 开头")
		}
		data, err := d.subs.fetch(Sub{URL: srcURL}, "clash.meta")
		if err != nil {
			return nil, fmt.Errorf("下载失败：%v", err)
		}
		text = string(data)
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if text == "" {
		return nil, fmt.Errorf("内容为空")
	}
	c := d.conf()
	p := &importPlan{Warns: []string{}, Nodes: []importNodeView{}, Rules: []Rule{}}
	if strings.HasPrefix(text, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			return nil, fmt.Errorf("JSON 语法错误：%v", jsonErrPos(text, err))
		}
		if _, ok := m["groups"]; ok {
			// 完整 TinyLane 配置
			if _, ok := m["nodes"]; !ok {
				return nil, fmt.Errorf("看起来是 TinyLane 配置，但没有 nodes")
			}
			cm, nc, err := d.parseRawCandidate(text)
			if err != nil {
				return nil, err
			}
			p.Kind = "TinyLane 完整配置（整份替换，保留本机 clash_api 密钥）"
			p.full = cm
			p.Summary = summarize(c, nc)
			for _, n := range nc.Nodes {
				p.Nodes = append(p.Nodes, importNodeView{n.Name, n.Type(), "replace"})
			}
			return im.store(p), nil
		}
		if _, ok := m["rules"]; ok {
			if _, ok2 := m["version"]; ok2 {
				return nil, fmt.Errorf("这是 sing-box 规则集文件：请在「规则」页用「添加规则集」引用它的 URL")
			}
		}
	}
	// 节点（Clash YAML / sing-box JSON / 分享链接 / Base64）
	looksNodes := strings.Contains(text, "proxies:") || strings.Contains(text, "\"outbounds\"") || strings.Contains(text, "://")
	if !looksNodes && !strings.ContainsAny(text, ", \n") {
		if _, err := b64any(text); err == nil {
			looksNodes = true
		}
	}
	if looksNodes {
		nodes, warns, format, err := parseSubscription([]byte(text))
		if err == nil {
			p.Kind = format + "（节点）"
			var dropped []string
			nodes, dropped = filterInfoNodes(nodes, c.importExclude())
			if len(dropped) > 0 {
				warns = append(warns, fmt.Sprintf("过滤 %d 个信息条目：%s", len(dropped), strings.Join(dropped, "、")))
			}
			warns = append(warns, resolvePins(nodes, c.Nodes, c.DNS.CN[0])...)
			p.Warns = append(p.Warns, warns...)
			have := nodeMap(c)
			for _, n := range nodes {
				act := "add"
				if o, ok := have[n.Name]; ok {
					if bytes.Equal(marshal(normJSON(o.Outbound)), marshal(normJSON(n.Outbound))) {
						act = "same"
					} else {
						act = "rename"
					}
				}
				p.Nodes = append(p.Nodes, importNodeView{n.Name, n.Type(), act})
			}
			p.nodes = nodes
		} else if !strings.Contains(text, "rules:") {
			return nil, err
		}
	}
	// 规则（Clash rules: 段 / 规则行 / 纯域名列表）
	if strings.Contains(text, "rules:") || !looksNodes {
		rs, skip := parseRuleLines(text)
		p.rawRules, p.RuleSkip = rs, skip
		for _, r := range rs {
			if mapTarget(r.target, "") == "" {
				p.NeedOut = true
			}
		}
		if p.Kind == "" {
			p.Kind = "规则列表"
		} else if len(rs) > 0 {
			p.Kind += " + 规则"
		}
		if skip > 0 {
			p.Warns = append(p.Warns, fmt.Sprintf("%d 条规则无法转换（GEOIP / RULE-SET / MATCH / IPv6 等），已跳过", skip))
		}
		p.Rules = buildImportRules(rs, c.MainGroup, false)
	}
	if len(p.Nodes) == 0 && len(p.Rules) == 0 {
		return nil, fmt.Errorf("没有识别出节点或规则（支持：TinyLane 配置、Clash YAML、sing-box JSON、分享链接 / Base64、Clash 规则行、域名列表）")
	}
	add, same, ren := 0, 0, 0
	for _, n := range p.Nodes {
		switch n.Action {
		case "add":
			add++
		case "same":
			same++
		case "rename":
			ren++
		}
	}
	if len(p.Nodes) > 0 {
		p.Summary = append(p.Summary, fmt.Sprintf("节点：新增 %d、已存在 %d、重名改名 %d（导入的节点不会自动加入组）", add, same, ren))
	}
	n := 0
	for _, r := range p.Rules {
		n += len(r.Domain) + len(r.DomainSuffix) + len(r.DomainKeyword) + len(r.DomainRegex) + len(r.IPCIDR)
	}
	if n > 0 {
		p.Summary = append(p.Summary, fmt.Sprintf("规则：%d 条匹配项 → 合并成 %d 条规则，追加在现有规则之后", n, len(p.Rules)))
	}
	return im.store(p), nil
}

func buildImportRules(rs []clashRule, proxyTarget string, _ bool) []Rule {
	by := map[string]*Rule{}
	var order []string
	date := time.Now().In(cst).Format("01-02")
	for _, r := range rs {
		out := mapTarget(r.target, proxyTarget)
		x, ok := by[out]
		if !ok {
			lbl := map[string]string{"direct": "直连", "block": "拒绝"}[out]
			if lbl == "" {
				lbl = out
			}
			x = &Rule{Name: "导入 " + date + " → " + lbl, Outbound: out}
			by[out] = x
			order = append(order, out)
		}
		switch r.kind {
		case "domain":
			x.Domain = append(x.Domain, strings.ToLower(r.val))
		case "domain_suffix":
			x.DomainSuffix = append(x.DomainSuffix, strings.ToLower(strings.TrimPrefix(r.val, ".")))
		case "domain_keyword":
			x.DomainKeyword = append(x.DomainKeyword, strings.ToLower(r.val))
		case "domain_regex":
			x.DomainRegex = append(x.DomainRegex, r.val)
		case "ip_cidr":
			if p, err := parsePrefix(r.val); err == nil && p.Addr().Is4() {
				x.IPCIDR = append(x.IPCIDR, p.Masked().String())
			}
		}
	}
	var out []Rule
	for _, k := range order {
		r := by[k]
		r.Domain, r.DomainSuffix, r.DomainKeyword, r.IPCIDR = uniq(r.Domain), uniq(r.DomainSuffix), uniq(r.DomainKeyword), uniq(r.IPCIDR)
		out = append(out, *r)
	}
	return out
}

func (im *ImportManager) store(p *importPlan) *importPlan {
	im.mu.Lock()
	defer im.mu.Unlock()
	for k, t := range im.at {
		if time.Since(t) > 30*time.Minute {
			delete(im.at, k)
			delete(im.pending, k)
		}
	}
	p.Token = randToken()
	im.pending[p.Token] = p
	im.at[p.Token] = time.Now()
	return p
}

func (im *ImportManager) Apply(d *Daemon, token, target string, withNodes, withRules bool) (map[string]any, error) {
	im.mu.Lock()
	p, ok := im.pending[token]
	if ok {
		delete(im.pending, token)
		delete(im.at, token)
	}
	im.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("预览已过期，请重新导入")
	}
	if p.full != nil {
		if err := d.applyEdit(applyOpts{desc: "导入：整份配置已替换"}, func(mm map[string]any) error {
			for k := range mm {
				delete(mm, k)
			}
			for k, v := range p.full {
				mm[k] = v
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	}
	c := d.conf()
	if target == "" {
		target = c.MainGroup
	}
	nAdd, rAdd := 0, 0
	err := d.applyEdit(applyOpts{desc: "导入：节点/规则"}, func(mm map[string]any) error {
		var cur Config
		b, _ := json.Marshal(mm)
		json.Unmarshal(b, &cur)
		names := map[string]bool{"direct": true, "block": true}
		for _, g := range cur.Groups {
			names[g.Name] = true
		}
		have := map[string]Node{}
		for _, n := range cur.Nodes {
			have[n.Name] = n
			names[n.Name] = true
		}
		if !names[target] {
			return fmt.Errorf("去向 %q 不存在", target)
		}
		if withNodes {
			for _, n := range p.nodes {
				if o, ok := have[n.Name]; ok && bytes.Equal(marshal(normJSON(o.Outbound)), marshal(normJSON(n.Outbound))) {
					continue
				}
				base := n.Name
				for i := 2; names[n.Name]; i++ {
					n.Name = fmt.Sprintf("%s (导入%d)", base, i)
				}
				n.Source = "manual"
				names[n.Name] = true
				cur.Nodes = append(cur.Nodes, n)
				nAdd++
			}
			mm["nodes"] = cur.Nodes
		}
		if withRules && len(p.rawRules) > 0 {
			rs := buildImportRules(p.rawRules, target, true)
			cur.Rules = append(cur.Rules, rs...)
			rAdd = len(rs)
			mm["rules"] = cur.Rules
		}
		if nAdd == 0 && rAdd == 0 {
			return errNoChange
		}
		return nil
	})
	if err == errNoChange {
		return map[string]any{"ok": true, "nodes_added": 0, "rules_added": 0}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "nodes_added": nAdd, "rules_added": rAdd}, nil
}

// ---------------- 看门狗：上游整体断网判定 ----------------

// upstreamOK：路由器本机直连（不经过 tproxy）连国内几个大站的 443，任意一个 2.5 s 内连上就算上游正常。
// 全部失败 = 家里宽带/上级路由本身断了，这时节点探测失败不是节点的问题，看门狗不该来回切。
func upstreamOK() bool {
	targets := []string{"223.5.5.5:443", "119.29.29.29:443", "180.76.76.76:443", "223.6.6.6:443"}
	if t := os.Getenv("TINYLANE_UPSTREAM_TARGETS"); t != "" { // 沙盒测试用
		targets = strings.Split(t, ",")
	}
	ch := make(chan bool, len(targets))
	for _, t := range targets {
		go func(t string) {
			cn, err := net.DialTimeout("tcp4", t, 2500*time.Millisecond)
			if err == nil {
				cn.Close()
			}
			ch <- err == nil
		}(t)
	}
	for range targets {
		if <-ch {
			return true
		}
	}
	return false
}

var upstreamCheck = upstreamOK // 测试可替换

// ---------------- 杂项 ----------------

func sortedRSNames(c *Config) []string {
	var n []string
	for _, r := range c.CustomRuleSets {
		n = append(n, r.Name)
	}
	sort.Strings(n)
	return n
}

var _ = http.StatusOK
