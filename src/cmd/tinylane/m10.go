package main

// M10：更快的自动切换（全部可在面板「设置 → 自动切换」里调）。
//   1. 快速切换：当前节点一次延迟探测失败 → 进入快速复测（每 fast_retest_s 秒测一次当前节点），
//      在 fast_window_s 秒的判定窗口内失败过半（含首次失败，至少 2 次失败）→ 按原规则切到组内第一个可用节点
//      （当场确认、allowedIn / strict、30 分钟内吞吐不达标跳过；上游断网检测全失败时不切不计数）。
//      关掉 = 与 m9 完全相同。
//   2. 内核超时触发：内核 20 秒内输出 ≥ core_err_count 条 Hysteria/QUIC 超时类错误 → 立即触发快速复测
//      （只触发复测，不直接切换）。需要快速切换开着才生效。
//   3. 备用节点也测：每轮额外测每个故障切换组里当前节点之后的第一个允许的节点（多组共用只测一次）。
//   4. 防抖：快速切走后 switch_back_min 分钟内不切回（切回仍需 recover 次正常 + 吞吐通过）。
//   5. 探测历史：memhist 每分钟点加各组当前节点 / 延迟 / 备用节点延迟，另给切换事件时间点。

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	fastRetestDef, fastRetestMin, fastRetestMax = 15, 5, 60
	fastWindowDef, fastWindowMin, fastWindowMax = 30, 15, 180
	coreErrDef, coreErrMin, coreErrMax          = 5, 3, 50
	backMinDef, backMinMin, backMinMax          = 5, 0, 60
	coreErrWindow                               = 20 * time.Second
	coreErrKickGap                              = 30 * time.Second // 两次触发至少间隔
	switchHistMax                               = 500
)

func bptr(b bool) *bool { return &b }
func iptr(i int) *int   { return &i }

func clampi(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// m10Defaults：loadConfig 里调用。手改配置写了越界值不报错，夹到范围内（面板保存时另做严格校验）。
func m10Defaults(w *WatchdogConf) {
	if w.FastSwitch == nil {
		w.FastSwitch = bptr(true)
	}
	if w.CoreErrKick == nil {
		w.CoreErrKick = bptr(true)
	}
	if w.ProbeBackup == nil {
		w.ProbeBackup = bptr(true)
	}
	w.FastRetestS = clampi(w.FastRetestS, fastRetestMin, fastRetestMax, fastRetestDef)
	w.FastWindowS = clampi(w.FastWindowS, fastWindowMin, fastWindowMax, fastWindowDef)
	w.CoreErrCount = clampi(w.CoreErrCount, coreErrMin, coreErrMax, coreErrDef)
	if w.SwitchBackMin == nil {
		w.SwitchBackMin = iptr(backMinDef)
	} else if *w.SwitchBackMin < backMinMin || *w.SwitchBackMin > backMinMax {
		w.SwitchBackMin = iptr(clampi(*w.SwitchBackMin, backMinMin, backMinMax, backMinDef))
	}
}

// 访问器（nil = 缺省；测试里直接构造的 Config 也能用）
func fastOn(c *Config) bool { return c.Watchdog.FastSwitch == nil || *c.Watchdog.FastSwitch }
func coreKickOn(c *Config) bool {
	return fastOn(c) && (c.Watchdog.CoreErrKick == nil || *c.Watchdog.CoreErrKick)
}
func probeBackupOn(c *Config) bool { return c.Watchdog.ProbeBackup == nil || *c.Watchdog.ProbeBackup }
func fastRetest(c *Config) int {
	return clampi(c.Watchdog.FastRetestS, fastRetestMin, fastRetestMax, fastRetestDef)
}
func fastWindow(c *Config) int {
	return clampi(c.Watchdog.FastWindowS, fastWindowMin, fastWindowMax, fastWindowDef)
}
func coreErrN(c *Config) int {
	return clampi(c.Watchdog.CoreErrCount, coreErrMin, coreErrMax, coreErrDef)
}
func backMin(c *Config) int {
	if c.Watchdog.SwitchBackMin == nil {
		return backMinDef
	}
	return *c.Watchdog.SwitchBackMin
}

func autoView(c *Config) map[string]any {
	return map[string]any{"fast_switch": fastOn(c), "fast_retest_s": fastRetest(c), "fast_window_s": fastWindow(c),
		"core_err_kick": c.Watchdog.CoreErrKick == nil || *c.Watchdog.CoreErrKick, "core_err_count": coreErrN(c),
		"probe_backup": probeBackupOn(c), "switch_back_min": backMin(c),
		"ranges": map[string][2]int{"fast_retest_s": {fastRetestMin, fastRetestMax}, "fast_window_s": {fastWindowMin, fastWindowMax},
			"core_err_count": {coreErrMin, coreErrMax}, "switch_back_min": {backMinMin, backMinMax}}}
}

type autoIn struct {
	FastSwitch    *bool `json:"fast_switch"`
	FastRetestS   *int  `json:"fast_retest_s"`
	FastWindowS   *int  `json:"fast_window_s"`
	CoreErrKick   *bool `json:"core_err_kick"`
	CoreErrCount  *int  `json:"core_err_count"`
	ProbeBackup   *bool `json:"probe_backup"`
	SwitchBackMin *int  `json:"switch_back_min"`
}

// validAuto：面板保存时的严格范围校验，返回要写进 watchdog 的键值。
func validAuto(a autoIn) (map[string]any, error) {
	out := map[string]any{}
	rng := func(p *int, key, name string, lo, hi int) error {
		if p == nil {
			return nil
		}
		if *p < lo || *p > hi {
			return fmt.Errorf("%s只能是 %d–%d", name, lo, hi)
		}
		out[key] = *p
		return nil
	}
	if err := rng(a.FastRetestS, "fast_retest_s", "复测间隔", fastRetestMin, fastRetestMax); err != nil {
		return nil, err
	}
	if err := rng(a.FastWindowS, "fast_window_s", "判定窗口", fastWindowMin, fastWindowMax); err != nil {
		return nil, err
	}
	if err := rng(a.CoreErrCount, "core_err_count", "内核超时条数", coreErrMin, coreErrMax); err != nil {
		return nil, err
	}
	if err := rng(a.SwitchBackMin, "switch_back_min", "切回冷却", backMinMin, backMinMax); err != nil {
		return nil, err
	}
	if a.FastRetestS != nil && a.FastWindowS != nil && *a.FastWindowS < *a.FastRetestS {
		return nil, fmt.Errorf("判定窗口不能比复测间隔短")
	}
	for k, p := range map[string]*bool{"fast_switch": a.FastSwitch, "core_err_kick": a.CoreErrKick, "probe_backup": a.ProbeBackup} {
		if p != nil {
			out[k] = *p
		}
	}
	return out, nil
}

// ---- 快速复测状态（每个故障切换组一份，存在 groupState 里，调用方持 w.mu）----

func (st *groupState) clearFast() { st.FastStart, st.FastNode, st.FastN, st.FastFail = 0, "", 0, 0 }

// fastSample：记录当前节点一次探测结果。不在快速复测中且失败 → 开始。
func (w *Watchdog) fastSample(group, cur string, ok bool, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.gstate(group)
	if st.FastStart > 0 && st.FastNode != cur {
		st.clearFast()
	}
	if st.FastStart == 0 {
		if ok {
			return
		}
		st.FastStart, st.FastNode, st.FastN, st.FastFail = now.Unix(), cur, 1, 1
		st.Note = "当前节点探测失败，正在快速复测"
		return
	}
	st.FastN++
	if !ok {
		st.FastFail++
	}
}

func (w *Watchdog) fastActive() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, st := range w.groups {
		if st.FastStart > 0 {
			return true
		}
	}
	return false
}

// fastVerdict：(要切, 结束复测)。exp = 窗口内应有的次数；失败数 ≥ exp/2+1（至少 2）提前判定，
// 窗口到了按实际次数「失败过半」判定。
func fastVerdict(n, fail int, elapsed int64, retest, window int) (bad, done bool) {
	exp := window/retest + 1
	need := exp/2 + 1
	if need < 2 {
		need = 2
	}
	if fail >= need && fail*2 > n {
		return true, true
	}
	if elapsed >= int64(window) {
		return fail >= 2 && fail*2 > n, true
	}
	return false, false
}

// fastEval：快速复测判定；切走了返回 true。
func (w *Watchdog) fastEval(c *Config, g Group, cur string, nodes map[string]Node) bool {
	now := time.Now()
	w.mu.Lock()
	st := w.gstate(g.Name)
	if st.FastStart == 0 || st.FastNode != cur {
		w.mu.Unlock()
		return false
	}
	n, f, el := st.FastN, st.FastFail, now.Unix()-st.FastStart
	bad, done := fastVerdict(n, f, el, fastRetest(c), fastWindow(c))
	if done {
		st.clearFast()
		if !bad && st.Note == "当前节点探测失败，正在快速复测" {
			st.Note = ""
		}
	}
	w.mu.Unlock()
	if !bad {
		return false
	}
	reason := fmt.Sprintf("快速复测：%d 秒内 %d 次探测有 %d 次失败", el, n, f)
	if w.failoverPick(c, g, cur, nodes, reason) {
		w.mu.Lock()
		w.gstate(g.Name).BackAfter = time.Now().Add(time.Duration(backMin(c)) * time.Minute).Unix()
		w.mu.Unlock()
		return true
	}
	w.mu.Lock()
	if g.Strict {
		w.gstate(g.Name).Note = "快速复测判定当前节点不稳，但没有可用的备用节点（断网保护），保持 " + cur
	} else {
		w.gstate(g.Name).Note = "快速复测判定当前节点不稳，但没有可用的备用节点，保持 " + cur
	}
	w.mu.Unlock()
	return false
}

// fastRound：快速复测轮，只测处在快速复测中的组的当前节点（kicked = 内核报错触发，测全部故障切换组的当前节点）。
func (w *Watchdog) fastRound(c *Config, kicked bool) {
	nodes := nodeMap(c)
	now := time.Now()
	type gi struct {
		g   Group
		cur string
	}
	var gs []gi
	seen := map[string]bool{}
	var test []string
	for _, g := range c.Groups {
		if g.Type != "failover" {
			continue
		}
		w.mu.Lock()
		st := w.gstate(g.Name)
		held := st.HoldUntil > now.Unix()
		if held {
			st.clearFast()
		}
		need := st.FastStart > 0 || kicked
		w.mu.Unlock()
		if held || !need {
			continue
		}
		cur, err := w.groupNow(g.Name)
		if err != nil || !allowedIn(c, g, cur, nodes) {
			continue
		}
		w.mu.Lock()
		w.gstate(g.Name).Cur = cur
		w.mu.Unlock()
		gs = append(gs, gi{g, cur})
		if !seen[cur] {
			seen[cur] = true
			test = append(test, cur)
		}
	}
	if len(test) == 0 {
		return
	}
	w.delayMany(test)
	allFail := true
	w.mu.Lock()
	for _, n := range test {
		if w.health(n).Delay > 0 {
			allFail = false
		}
	}
	w.mu.Unlock()
	if allFail && !upstreamCheck() {
		w.mu.Lock()
		for _, n := range test {
			if h := w.health(n); h.FailStreak > 0 {
				h.FailStreak--
			}
		}
		for _, x := range gs {
			st := w.gstate(x.g.Name)
			st.clearFast()
			st.Note = "上游网络不通（国内直连也失败），暂停自动切换"
		}
		first := !w.upDown
		w.upDown = true
		w.mu.Unlock()
		if first {
			w.d.events.add("system", "上游网络不通（节点和国内直连都失败）：暂停自动切换，等网络恢复")
		}
		return
	}
	for _, x := range gs {
		w.mu.Lock()
		ok := w.health(x.cur).Delay > 0
		w.mu.Unlock()
		w.fastSample(x.g.Name, x.cur, ok, now)
		w.fastEval(c, x.g, x.cur, nodes)
	}
}

// KickFast：内核报错触发的快速复测（快速切换关着时不做任何事 = 与 m9 相同）。
func (w *Watchdog) KickFast() {
	if !coreKickOn(w.d.conf()) {
		return
	}
	w.fastReq.Store(true)
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// ---- 切换历史（给曲线标切换点）----

type switchEv struct {
	T    int64  `json:"t"`
	G    string `json:"g"`
	From string `json:"from"`
	To   string `json:"to"`
	Why  string `json:"why"`
	Fast bool   `json:"fast,omitempty"`
}

func (w *Watchdog) recordSwitch(e switchEv) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cut := time.Now().Add(-48 * time.Hour).Unix()
	i := 0
	for i < len(w.swh) && (w.swh[i].T < cut || len(w.swh)-i >= switchHistMax) {
		i++
	}
	w.swh = append(w.swh[i:len(w.swh):len(w.swh)], e)
}

func (w *Watchdog) switches() []switchEv {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]switchEv{}, w.swh...)
}

// gPt：memhist 每分钟点里一个故障切换组的状态。D/BD：ms，0 = 失败，-1 = 最近没测。
type gPt struct {
	G  string `json:"g"`
	N  string `json:"n"`
	D  int    `json:"d"`
	B  string `json:"b,omitempty"`
	BD int    `json:"bd,omitempty"`
}

func (w *Watchdog) histGroups(c *Config) []gPt {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	stale := time.Now().Unix() - int64(3*c.Watchdog.Interval+30)
	dv := func(n string) int {
		h := w.nodes[n]
		if h == nil || h.DelayAt < stale {
			return -1
		}
		return h.Delay
	}
	var out []gPt
	for _, g := range c.Groups {
		if g.Type != "failover" {
			continue
		}
		st := w.groups[g.Name]
		if st == nil || st.Cur == "" {
			continue
		}
		p := gPt{G: g.Name, N: st.Cur, D: dv(st.Cur)}
		if st.Cur == "direct" {
			p.D = -1
		}
		if st.Backup != "" {
			p.B, p.BD = st.Backup, dv(st.Backup)
		}
		out = append(out, p)
	}
	return out
}

// ---- 内核输出旁路：原样转发，同时数超时类错误 ----

var coreErrKeys = [][]byte{
	[]byte("no recent network activity"),
	[]byte("canceled by remote"),
	[]byte("handshake timeout"),
	[]byte("handshake: timeout"),
	[]byte("handshake did not complete"),
}

func isCoreTimeoutLine(l []byte) bool {
	for _, k := range coreErrKeys {
		if bytes.Contains(l, k) {
			return true
		}
	}
	return false
}

type coreErrCounter struct {
	mu       sync.Mutex
	ts       []time.Time
	lastKick time.Time
	total    int64
	kicks    int64
	now      func() time.Time
	limit    func() int // 当前阈值（读配置）
	onKick   func(n int)
}

func (c *coreErrCounter) hit() {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	c.mu.Lock()
	c.total++
	cut := now.Add(-coreErrWindow)
	i := 0
	for i < len(c.ts) && c.ts[i].Before(cut) {
		i++
	}
	c.ts = append(c.ts[i:], now)
	if len(c.ts) > 64 {
		c.ts = c.ts[len(c.ts)-64:]
	}
	n, lim := len(c.ts), coreErrDef
	if c.limit != nil {
		lim = c.limit()
	}
	fire := n >= lim && (c.lastKick.IsZero() || now.Sub(c.lastKick) >= coreErrKickGap)
	if fire {
		c.lastKick = now
		c.kicks++
	}
	c.mu.Unlock()
	if fire && c.onKick != nil {
		c.onKick(n)
	}
}

func (c *coreErrCounter) stats() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lk int64
	if !c.lastKick.IsZero() {
		lk = c.lastKick.Unix()
	}
	return map[string]any{"total": c.total, "kicks": c.kicks, "last_kick": lk}
}

// lineTap：io.Writer，把内核输出原样写到 out，按行检查关键词。
type lineTap struct {
	out io.Writer
	buf []byte
	cnt *coreErrCounter
}

func (t *lineTap) Write(p []byte) (int, error) {
	total := len(p)
	n, err := t.out.Write(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(t.buf)+len(p) <= 4096 {
				t.buf = append(t.buf, p...)
			}
			break
		}
		line := p[:i]
		if len(t.buf) > 0 {
			t.buf = append(t.buf, line...)
			line = t.buf
		}
		if isCoreTimeoutLine(line) {
			t.cnt.hit()
		}
		t.buf = t.buf[:0]
		p = p[i+1:]
	}
	if err == nil {
		n = total
	}
	return n, err
}

func (d *Daemon) coreErrs() *coreErrCounter {
	d.coreErrOnce.Do(func() {
		var lastEv time.Time
		d.cerr = &coreErrCounter{
			limit: func() int { return coreErrN(d.conf()) },
			onKick: func(n int) {
				if d.wd == nil || !coreKickOn(d.conf()) {
					return
				}
				d.wd.KickFast()
				if time.Since(lastEv) > 10*time.Minute {
					lastEv = time.Now()
					d.events.add("system", fmt.Sprintf("内核 20 秒内报了 %d 条连接超时，立即复测当前节点（10 分钟内不再重复记录）", n))
				}
			},
		}
	})
	return d.cerr
}

func autoViewD(d *Daemon, c *Config) map[string]any {
	v := autoView(c)
	if d.cerr != nil {
		v["core_err"] = d.cerr.stats()
	}
	return v
}
