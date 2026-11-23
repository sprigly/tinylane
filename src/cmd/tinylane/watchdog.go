package main

// M2 看门狗：只管 type=failover 的组，成员顺序 = 优先级。
//   每 interval（60 s）：经 clash_api 对「当前节点」和「比它优先级高的节点」做延迟探测（gstatic 204）。
//     当前节点连续 fail 次失败 → 按顺序切到第一个可用节点（当场再探一次确认）。
//     更高优先级节点连续 recover 次正常（并且吞吐探测通过）→ 切回。
//   每 heavy_interval（15 min）：对各组当前节点经 probe-in → tl-probe 做小下载 + 小上传；
//     不达标就每轮复测，连续 fail 次不达标 → 切走。
//   M7：候选 = 组的实际成员（手选 + 名称筛选 − 排除），只测这些；非 strict 的组全部节点不可用（且国内直连正常）时切到直连，
//   节点恢复后切回；strict（断网保护）的组永远不会被切到直连或组外节点。
//   面板手动选择 → 该组暂停自动切换 hold_minutes。

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type NodeHealth struct {
	Delay      int    `json:"delay"`       // 最近一次延迟 ms（0 = 失败/未测）
	DelayAt    int64  `json:"delay_at"`    // unix
	OKStreak   int    `json:"ok_streak"`   // 连续成功
	FailStreak int    `json:"fail_streak"` // 连续失败
	DownKBps   int    `json:"down_kbps"`   // 最近吞吐
	UpKBps     int    `json:"up_kbps"`
	HeavyAt    int64  `json:"heavy_at"`
	HeavyOK    *bool  `json:"heavy_ok,omitempty"`
	HeavyFail  int    `json:"heavy_fail"` // 连续吞吐不达标
	HeavyErr   string `json:"heavy_err,omitempty"`
	LastOK     int    `json:"last_ok,omitempty"`    // 最近一次成功的延迟（失败时面板灰显它，而不是立刻显示「超时」）
	LastOKAt   int64  `json:"last_ok_at,omitempty"` // unix
}

type groupState struct {
	HoldUntil int64  `json:"hold_until"` // 手动锁定到（unix）
	LastCheck int64  `json:"last_check"`
	LastHeavy int64  `json:"last_heavy"`
	Note      string `json:"note"`
	// M10
	Cur       string `json:"cur,omitempty"`        // 最近一轮看到的当前节点
	Backup    string `json:"backup,omitempty"`     // 本轮额外测的备用节点
	FastStart int64  `json:"fast_start,omitempty"` // 快速复测开始（unix，0 = 没在复测）
	FastNode  string `json:"fast_node,omitempty"`
	FastN     int    `json:"fast_n,omitempty"`
	FastFail  int    `json:"fast_fail,omitempty"`
	BackAfter int64  `json:"back_after,omitempty"` // 快速切走后，这之前不切回
}

type Watchdog struct {
	d       *Daemon
	mu      sync.Mutex
	nodes   map[string]*NodeHealth
	groups  map[string]*groupState
	probeMu sync.Mutex // tl-probe 只能同时测一个节点
	kick    chan struct{}
	upDown  bool // 上游整体断网中（M6）
	// M10
	fullReq atomic.Bool // Kick()：立即做一轮完整检测
	fastReq atomic.Bool // KickFast()：立即复测当前节点
	swh     []switchEv
}

func newWatchdog(d *Daemon) *Watchdog {
	return &Watchdog{d: d, nodes: map[string]*NodeHealth{}, groups: map[string]*groupState{}, kick: make(chan struct{}, 1)}
}

func (w *Watchdog) health(name string) *NodeHealth {
	h := w.nodes[name]
	if h == nil {
		h = &NodeHealth{}
		w.nodes[name] = h
	}
	return h
}

func (w *Watchdog) gstate(name string) *groupState {
	g := w.groups[name]
	if g == nil {
		g = &groupState{}
		w.groups[name] = g
	}
	return g
}

// Snapshot 给面板用
func (w *Watchdog) Snapshot() (map[string]NodeHealth, map[string]groupState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := map[string]NodeHealth{}
	for k, v := range w.nodes {
		n[k] = *v
	}
	g := map[string]groupState{}
	for k, v := range w.groups {
		g[k] = *v
	}
	return n, g
}

func (w *Watchdog) Hold(group string, minutes int) {
	w.mu.Lock()
	w.gstate(group).HoldUntil = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	w.mu.Unlock()
}

func (w *Watchdog) Release(group string) {
	w.mu.Lock()
	w.gstate(group).HoldUntil = 0
	w.mu.Unlock()
	w.Kick()
}

func (w *Watchdog) Kick() {
	w.fullReq.Store(true)
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func (w *Watchdog) run() {
	// 等内核起来
	for i := 0; i < 60 && !w.d.coreUp.Load(); i++ {
		select {
		case <-w.d.ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	// M10：完整检测仍是每 interval 一轮；快速复测中 / 内核报错触发时，中间插入只测当前节点的快速轮。
	// 快速切换关掉时只走完整检测，与 m9 相同。
	var next time.Time
	for {
		c := w.d.conf()
		active := !c.Watchdog.Disabled && w.d.coreUp.Load() && !w.d.fallback.Load()
		full := w.fullReq.Swap(false)
		if active {
			if full || !time.Now().Before(next) {
				w.fastReq.Store(false)
				w.round(c)
				next = time.Now().Add(time.Duration(c.Watchdog.Interval) * time.Second)
			} else if fastOn(c) {
				kicked := w.fastReq.Swap(false)
				if kicked || w.fastActive() {
					w.fastRound(c, kicked)
				}
			}
		} else {
			next = time.Now().Add(time.Duration(c.Watchdog.Interval) * time.Second)
		}
		wait := time.Until(next)
		if active && fastOn(c) && w.fastActive() {
			if r := time.Duration(fastRetest(c)) * time.Second; r < wait {
				wait = r
			}
		}
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-w.d.ctx.Done():
			return
		case <-w.kick:
		case <-time.After(wait):
		}
	}
}

type clashProxy struct {
	Now string   `json:"now"`
	All []string `json:"all"`
}

func (w *Watchdog) groupNow(name string) (string, error) {
	var p clashProxy
	err := w.d.clash().doCtx(w.d.ctx, 5*time.Second, "GET", "/proxies/"+url.PathEscape(name), nil, &p)
	return p.Now, err
}

// Delay 经 clash_api 测单个出站延迟（ms，0 = 失败）
func (w *Watchdog) Delay(name string) int {
	c := w.d.conf()
	q := url.Values{"timeout": {fmt.Sprint(c.Watchdog.TimeoutMS)}, "url": {c.Watchdog.URL}}
	var r struct{ Delay int }
	var err error
	// 最多 2 次：上游一阵丢包时单次 QUIC/TLS 握手丢包很常见，一次失败不算失败
	for attempt := 0; attempt < 2; attempt++ {
		r.Delay = 0
		err = w.d.clash().doCtx(w.d.ctx, time.Duration(c.Watchdog.TimeoutMS+3000)*time.Millisecond, "GET",
			"/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), nil, &r)
		if err == nil && r.Delay > 0 {
			break
		}
		if w.d.ctx.Err() != nil {
			break
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	h := w.health(name)
	h.DelayAt = time.Now().Unix()
	if err != nil || r.Delay <= 0 {
		h.Delay, h.OKStreak = 0, 0
		h.FailStreak++
		return 0
	}
	h.Delay = r.Delay
	h.LastOK, h.LastOKAt = r.Delay, h.DelayAt
	h.OKStreak++
	h.FailStreak = 0
	return r.Delay
}

func (w *Watchdog) delayMany(names []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, n := range names {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			w.Delay(n)
			<-sem
		}(n)
	}
	wg.Wait()
}

// Heavy：经 probe-in（固定走 tl-probe）下载 down_bytes + 上传 up_bytes，返回 KB/s。
func (w *Watchdog) Heavy(name string) (down, up int, err error) {
	c := w.d.conf()
	if c.ProbeListen == "" {
		return 0, 0, fmt.Errorf("未配置 probe_listen")
	}
	w.probeMu.Lock()
	defer w.probeMu.Unlock()
	if err := w.d.clash().doCtx(w.d.ctx, 5*time.Second, "PUT", "/proxies/"+url.PathEscape(probeTag), map[string]string{"name": name}, nil); err != nil {
		return 0, 0, fmt.Errorf("切换 tl-probe: %w", err)
	}
	px, _ := url.Parse("http://" + c.ProbeListen)
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(px), DisableKeepAlives: true}}
	host := c.Watchdog.SpeedHost
	// 下载
	t0 := time.Now()
	resp, err := hc.Get(fmt.Sprintf("https://%s/__down?bytes=%d", host, c.Watchdog.DownBytes))
	if err == nil {
		n, e2 := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if e2 != nil {
			err = e2
		} else if resp.StatusCode != 200 || n < int64(c.Watchdog.DownBytes) {
			err = fmt.Errorf("下载不完整（HTTP %d，%d 字节）", resp.StatusCode, n)
		}
	}
	dt := time.Since(t0).Seconds()
	if err == nil && dt > 0 {
		down = int(float64(c.Watchdog.DownBytes) / 1024 / dt)
	}
	derr := err
	// 上传
	body := make([]byte, c.Watchdog.UpBytes)
	rand.Read(body)
	t1 := time.Now()
	resp, err = hc.Post(fmt.Sprintf("https://%s/__up", host), "application/octet-stream", bytes.NewReader(body))
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			err = fmt.Errorf("上传 HTTP %d", resp.StatusCode)
		}
	}
	ut := time.Since(t1).Seconds()
	if err == nil && ut > 0 {
		up = int(float64(c.Watchdog.UpBytes) / 1024 / ut)
	}
	uerr := err
	ok := derr == nil && uerr == nil && down >= c.Watchdog.MinDownKBps && up >= c.Watchdog.MinUpKBps
	var why string
	switch {
	case derr != nil:
		why = "下载失败：" + shortErr(derr)
	case uerr != nil:
		why = "上传失败：" + shortErr(uerr)
	case down < c.Watchdog.MinDownKBps:
		why = fmt.Sprintf("下载太慢 %d KB/s", down)
	case up < c.Watchdog.MinUpKBps:
		why = fmt.Sprintf("上传太慢 %d KB/s", up)
	}
	w.mu.Lock()
	h := w.health(name)
	h.DownKBps, h.UpKBps, h.HeavyAt, h.HeavyErr = down, up, time.Now().Unix(), why
	okv := ok
	h.HeavyOK = &okv
	if ok {
		h.HeavyFail = 0
	} else {
		h.HeavyFail++
	}
	w.mu.Unlock()
	if !ok {
		return down, up, fmt.Errorf("%s", why)
	}
	return down, up, nil
}

func shortErr(e error) string {
	s := e.Error()
	if len(s) > 80 {
		s = s[len(s)-80:]
	}
	return s
}

func nodeMap(c *Config) map[string]Node {
	m := map[string]Node{}
	for _, n := range c.Nodes {
		m[n.Name] = n
	}
	return m
}

// allowedIn：该组能不能选这个成员（必须是节点，且在组的实际成员里）
func allowedIn(c *Config, g Group, member string, nodes map[string]Node) bool {
	if _, ok := nodes[member]; !ok {
		return false
	}
	return indexOf(c.members(g.Name), member) >= 0
}

func (w *Watchdog) round(c *Config) {
	nodes := nodeMap(c)
	now := time.Now()
	type gi struct {
		g    Group
		cur  string
		held bool
	}
	var gs []gi
	testSet := map[string]bool{}
	var test []string
	for _, g := range c.Groups {
		if g.Type != "failover" {
			continue
		}
		cur, err := w.groupNow(g.Name)
		if err != nil {
			continue
		}
		w.mu.Lock()
		st := w.gstate(g.Name)
		held := st.HoldUntil > now.Unix()
		st.LastCheck = now.Unix()
		st.Cur, st.Backup = cur, ""
		if held {
			st.clearFast()
		}
		w.mu.Unlock()
		gs = append(gs, gi{g, cur, held})
		mem := c.members(g.Name)
		curIdx := indexOf(mem, cur)
		for i, m := range mem {
			if !allowedIn(c, g, m, nodes) || testSet[m] {
				continue
			}
			if m == cur || curIdx < 0 || i < curIdx {
				testSet[m] = true
				test = append(test, m)
			}
		}
	}
	// M10：每组当前节点之后第一个允许的备用节点也测（不参与下面的「全部失败」判断，保持 m9 语义）
	var extra []string
	if probeBackupOn(c) {
		exSet := map[string]bool{}
		for _, x := range gs {
			mem := c.members(x.g.Name)
			ci := indexOf(mem, x.cur)
			if ci < 0 {
				continue
			}
			for _, m := range mem[ci+1:] {
				if !allowedIn(c, x.g, m, nodes) {
					continue
				}
				w.mu.Lock()
				w.gstate(x.g.Name).Backup = m
				w.mu.Unlock()
				if !testSet[m] && !exSet[m] {
					exSet[m] = true
					extra = append(extra, m)
				}
				break
			}
		}
	}
	// 同一节点一轮只测一次（多个组共用节点时不重复计数）
	w.delayMany(append(append([]string(nil), test...), extra...))
	// M6：本轮测到的节点全失败 → 先看国内直连通不通。不通 = 宽带/上级路由断了，不是节点的问题：
	// 这一轮失败不计数、不切换（11-19 01:22 那次上游中断里，看门狗在恢复瞬间切了 3 次）。
	if len(test) > 0 {
		allFail := true
		w.mu.Lock()
		for _, n := range test {
			if w.health(n).Delay > 0 {
				allFail = false
				break
			}
		}
		w.mu.Unlock()
		if allFail && !upstreamCheck() {
			w.mu.Lock()
			for _, n := range append(append([]string(nil), test...), extra...) {
				if h := w.health(n); h.FailStreak > 0 && h.Delay == 0 {
					h.FailStreak--
				}
			}
			for _, x := range gs {
				w.gstate(x.g.Name).Note = "上游网络不通（国内直连也失败），暂停自动切换"
				w.gstate(x.g.Name).clearFast()
			}
			first := !w.upDown
			w.upDown = true
			w.mu.Unlock()
			if first {
				w.d.events.add("system", "上游网络不通（节点和国内直连都失败）：暂停自动切换，等网络恢复")
			}
			return
		}
		w.mu.Lock()
		was := w.upDown
		w.upDown = false
		w.mu.Unlock()
		if was {
			w.d.events.add("system", "上游网络已恢复，自动切换继续")
		}
	}
	heavyDone := map[string]bool{}
	for _, x := range gs {
		if indexOf(c.members(x.g.Name), x.cur) < 0 || c.ProbeListen == "" {
			continue
		}
		if heavyDone[x.cur] {
			w.mu.Lock()
			w.gstate(x.g.Name).LastHeavy = now.Unix()
			w.mu.Unlock()
			continue
		}
		w.mu.Lock()
		st := w.gstate(x.g.Name)
		hc := w.health(x.cur)
		// 本轮延迟都失败了就不做吞吐（省时间，延迟失败本身会触发切换）
		due := hc.Delay > 0 && (now.Unix()-st.LastHeavy >= int64(c.Watchdog.HeavyInterval) || hc.HeavyFail > 0)
		if due {
			st.LastHeavy = now.Unix()
		}
		w.mu.Unlock()
		if due {
			heavyDone[x.cur] = true
			w.Heavy(x.cur)
		}
	}
	fast := fastOn(c)
	for _, x := range gs {
		if x.held {
			continue
		}
		if fast && testSet[x.cur] {
			w.mu.Lock()
			ok := w.health(x.cur).Delay > 0
			w.mu.Unlock()
			w.fastSample(x.g.Name, x.cur, ok, now)
			if w.fastEval(c, x.g, x.cur, nodes) {
				continue
			}
		}
		w.decide(c, x.g, x.cur, nodes)
	}
}

func (w *Watchdog) decide(c *Config, g Group, cur string, nodes map[string]Node) {
	w.mu.Lock()
	hc := *w.health(cur)
	w.mu.Unlock()
	mem := c.members(g.Name)
	curIdx := indexOf(mem, cur)
	curBad := curIdx < 0 || !allowedIn(c, g, cur, nodes) || hc.FailStreak >= c.Watchdog.Fail || hc.HeavyFail >= c.Watchdog.Fail
	if curBad {
		reason := "当前节点不在组内"
		if cur == "direct" {
			reason = "节点恢复，从直连切回"
		}
		switch {
		case hc.FailStreak >= c.Watchdog.Fail:
			reason = fmt.Sprintf("连续 %d 次延迟探测失败", hc.FailStreak)
		case hc.HeavyFail >= c.Watchdog.Fail:
			reason = fmt.Sprintf("连续 %d 次吞吐探测不达标（%s）", hc.HeavyFail, hc.HeavyErr)
		}
		if w.failoverPick(c, g, cur, nodes, reason) {
			return
		}
		// 非 strict 的故障切换组：全部节点都不可用 → 回落直连（上游断网的轮次在 round 里已提前返回，不会走到这里）
		if !g.Strict && cur != "direct" && len(mem) > 0 && (hc.FailStreak >= c.Watchdog.Fail || curIdx < 0) {
			w.switchTo(g, cur, "direct", "组内节点全部不可用，回落直连（未开启断网保护）")
			return
		}
		w.mu.Lock()
		if cur == "direct" {
			w.gstate(g.Name).Note = "组内节点全部不可用，暂时直连；节点恢复后自动切回"
		} else if g.Strict {
			w.gstate(g.Name).Note = "没有可用的备用节点（断网保护：不回落直连），保持 " + cur
		} else {
			w.gstate(g.Name).Note = "没有可用的备用节点，保持 " + cur
		}
		w.mu.Unlock()
		return
	}
	// M10 防抖：快速切走后冷却期内不切回
	w.mu.Lock()
	ba := w.gstate(g.Name).BackAfter
	w.mu.Unlock()
	if curIdx > 0 && ba > time.Now().Unix() {
		w.mu.Lock()
		w.gstate(g.Name).Note = "刚因不稳快速切走，" + time.Unix(ba, 0).In(cst).Format("15:04") + " 之前不切回"
		w.mu.Unlock()
		return
	}
	// 切回更高优先级
	for i := 0; i < curIdx; i++ {
		m := mem[i]
		if !allowedIn(c, g, m, nodes) {
			continue
		}
		w.mu.Lock()
		hm := *w.health(m)
		w.mu.Unlock()
		if hm.OKStreak < c.Watchdog.Recover {
			continue
		}
		if c.ProbeListen != "" {
			if hm.HeavyOK == nil || !*hm.HeavyOK || time.Now().Unix()-hm.HeavyAt > int64(c.Watchdog.HeavyInterval) {
				if _, _, err := w.Heavy(m); err != nil {
					continue
				}
			}
		}
		w.switchTo(g, cur, m, fmt.Sprintf("高优先级节点连续 %d 次正常，切回", hm.OKStreak))
		return
	}
	w.mu.Lock()
	if st := w.gstate(g.Name); st.FastStart == 0 {
		st.Note = ""
	}
	w.mu.Unlock()
}

// failoverPick：按组顺序找第一个可用的其他节点（30 分钟内吞吐不达标的跳过，当场再测确认）并切过去。
func (w *Watchdog) failoverPick(c *Config, g Group, cur string, nodes map[string]Node, reason string) bool {
	for _, m := range c.members(g.Name) {
		if m == cur || !allowedIn(c, g, m, nodes) {
			continue
		}
		w.mu.Lock()
		hm := *w.health(m)
		w.mu.Unlock()
		if hm.HeavyFail >= c.Watchdog.Fail && time.Now().Unix()-hm.HeavyAt < 1800 {
			continue // 30 分钟内吞吐不达标的先跳过
		}
		if w.Delay(m) == 0 { // 当场确认
			continue
		}
		return w.switchTo(g, cur, m, reason)
	}
	return false
}

func (w *Watchdog) switchTo(g Group, from, to, reason string) bool {
	c := w.d.conf()
	cg, _ := findGroup(c, g.Name)
	okDirect := to == "direct" && !cg.Strict && cg.Type == "failover" && len(c.members(g.Name)) > 0
	if !okDirect && !allowedIn(c, cg, to, nodeMap(c)) { // 最后一道闸（用最新配置）
		w.d.events.add("error", fmt.Sprintf("看门狗拒绝把 %s 切到 %s（不在组内 / 断网保护）", g.Name, to))
		return false
	}
	if err := w.d.clash().doCtx(w.d.ctx, 5*time.Second, "PUT", "/proxies/"+url.PathEscape(g.Name), map[string]string{"name": to}, nil); err != nil {
		w.d.events.add("error", fmt.Sprintf("%s 切换到 %s 失败：%v", g.Name, to, err))
		return false
	}
	w.mu.Lock()
	st := w.gstate(g.Name)
	st.Note = ""
	st.clearFast()
	st.Cur = to
	w.mu.Unlock()
	w.recordSwitch(switchEv{T: time.Now().Unix(), G: g.Name, From: from, To: to, Why: reason, Fast: strings.HasPrefix(reason, "快速复测")})
	w.d.events.add("switch", fmt.Sprintf("%s：%s → %s（%s）", g.Name, from, to, reason))
	return true
}

func indexOf(a []string, s string) int {
	for i, x := range a {
		if x == s {
			return i
		}
	}
	return -1
}

// 给面板：按名字排序的节点健康列表
func sortedNames(m map[string]NodeHealth) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

var _ = context.Background
