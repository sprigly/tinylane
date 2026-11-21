package main

// M7 出口自动识别：新节点（或参数变了的节点）经 tl-probe 请求一次 IP 回显，记下出口 IP / 国家 / 运营商。
//   - 只测一次（结果存 /etc/tinylane/egress.json，按节点参数指纹失效），面板可手动重测；
//   - 一次只测一个（和看门狗吞吐探测共用 probeMu，互不干扰），测完一个歇 1 s；
//   - 失败只记原因，不影响导入；节点删除后条目随之删除（不留残留）；
//   - 设置 egress_probe=false 关掉自动检测（手动重测仍可用）。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Egress struct {
	FP   string `json:"fp"`
	IP   string `json:"ip,omitempty"`
	CC   string `json:"cc,omitempty"`   // 国家/地区代码
	City string `json:"city,omitempty"`
	Org  string `json:"org,omitempty"`  // 运营商 / ASN 名称
	At   int64  `json:"at"`
	Err  string `json:"err,omitempty"`
}

type EgressMgr struct {
	d       *Daemon
	path    string
	mu      sync.Mutex
	m       map[string]Egress
	queue   []string
	force   map[string]bool
	running string
	wake    chan struct{}
	batch   [2]int // 本批 已测 / 失败
}

func newEgressMgr(d *Daemon) *EgressMgr {
	e := &EgressMgr{d: d, path: filepath.Join(filepath.Dir(d.cfgPath), "egress.json"), m: map[string]Egress{}, force: map[string]bool{}, wake: make(chan struct{}, 1)}
	if b, err := os.ReadFile(e.path); err == nil {
		json.Unmarshal(b, &e.m)
	}
	return e
}

func (e *EgressMgr) saveLocked() {
	if len(e.m) == 0 {
		os.Remove(e.path)
		return
	}
	writeFileAtomic(e.path, marshal(e.m), 0o600)
}

// sync：配置变了 → 删掉已不存在 / 参数变了的节点的记录；自动模式下把没测过的排进队列
func (e *EgressMgr) sync(c *Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	fps := map[string]string{}
	for _, n := range c.Nodes {
		fps[n.Name] = nodeFP(n)
	}
	changed := false
	for name, x := range e.m {
		if fp, ok := fps[name]; !ok || fp != x.FP {
			delete(e.m, name)
			changed = true
		}
	}
	if changed {
		e.saveLocked()
	}
	var q []string
	for _, x := range e.queue { // 队列里去掉已删除的节点
		if _, ok := fps[x]; ok {
			q = append(q, x)
		}
	}
	e.queue = q
	if c.egressAuto() {
		for _, n := range c.Nodes {
			if _, ok := e.m[n.Name]; !ok && indexOf(e.queue, n.Name) < 0 && e.running != n.Name {
				e.queue = append(e.queue, n.Name)
			}
		}
	}
	if len(e.queue) > 0 {
		select {
		case e.wake <- struct{}{}:
		default:
		}
	}
}

// enqueue：手动重测（names 为空 = 全部）
func (e *EgressMgr) enqueue(names []string) int {
	c := e.d.conf()
	have := nodeMap(c)
	e.mu.Lock()
	if len(names) == 0 {
		for _, n := range c.Nodes {
			names = append(names, n.Name)
		}
	}
	n := 0
	for _, x := range names {
		if _, ok := have[x]; !ok {
			continue
		}
		e.force[x] = true
		if indexOf(e.queue, x) < 0 {
			e.queue = append(e.queue, x)
		}
		n++
	}
	e.mu.Unlock()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	return n
}

func (e *EgressMgr) get(name string) (Egress, bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x, ok := e.m[name]
	pend := e.running == name || indexOf(e.queue, name) >= 0
	return x, ok, pend
}

func (e *EgressMgr) status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{"queue": len(e.queue), "running": e.running, "auto": e.d.conf().egressAuto()}
}

func (e *EgressMgr) loop() {
	for {
		select {
		case <-e.d.ctx.Done():
			return
		case <-e.wake:
		case <-time.After(5 * time.Minute):
		}
		for {
			if e.d.ctx.Err() != nil {
				return
			}
			if !e.d.coreUp.Load() || e.d.fallback.Load() {
				time.Sleep(5 * time.Second)
				continue
			}
			e.mu.Lock()
			if len(e.queue) == 0 {
				done, bad := e.batch[0], e.batch[1]
				e.batch = [2]int{}
				e.mu.Unlock()
				if done > 0 {
					msg := fmt.Sprintf("出口检测完成：%d 个节点", done)
					if bad > 0 {
						msg += fmt.Sprintf("（%d 个没测出来）", bad)
					}
					e.d.events.add("node", msg)
				}
				break
			}
			name := e.queue[0]
			e.queue = e.queue[1:]
			force := e.force[name]
			delete(e.force, name)
			_, tested := e.m[name]
			if tested && !force {
				e.mu.Unlock()
				continue
			}
			e.running = name
			e.mu.Unlock()
			n, ok := nodeMap(e.d.conf())[name]
			var res Egress
			if ok {
				res = e.probe(name)
				res.FP = nodeFP(n)
			}
			e.mu.Lock()
			e.running = ""
			if _, still := nodeMap(e.d.conf())[name]; ok && still {
				e.m[name] = res
				e.saveLocked()
				e.batch[0]++
				if res.Err != "" {
					e.batch[1]++
				}
			}
			e.mu.Unlock()
			time.Sleep(time.Second)
		}
	}
}

func (e *EgressMgr) probeLock() *sync.Mutex {
	if e.d.wd != nil {
		return &e.d.wd.probeMu
	}
	return &egressLocalMu
}

var egressLocalMu sync.Mutex

// probe：tl-probe 切到该节点 → 经 probe 入站请求 IP 回显（先 ipinfo.io/json：IP/国家/城市/ASN，失败再 1.1.1.1 trace：IP/国家）
func (e *EgressMgr) probe(name string) Egress {
	c := e.d.conf()
	r := Egress{At: time.Now().Unix()}
	if c.ProbeListen == "" {
		r.Err = "未配置探测入口"
		return r
	}
	mu := e.probeLock()
	mu.Lock()
	defer mu.Unlock()
	if err := e.d.clash().doCtx(e.d.ctx, 5*time.Second, "PUT", "/proxies/"+url.PathEscape(probeTag), map[string]string{"name": name}, nil); err != nil {
		r.Err = "切换探测入口失败"
		return r
	}
	px, _ := url.Parse("http://" + c.ProbeListen)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(px), DisableKeepAlives: true}}
	get := func(u string) ([]byte, error) {
		resp, err := hc.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	}
	if b, err := get("https://ipinfo.io/json"); err == nil {
		var m struct {
			IP      string `json:"ip"`
			Country string `json:"country"`
			City    string `json:"city"`
			Org     string `json:"org"`
		}
		if json.Unmarshal(b, &m) == nil && m.IP != "" {
			r.IP, r.CC, r.City, r.Org = m.IP, m.Country, m.City, m.Org
			return r
		}
	}
	b, err := get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		r.Err = egressErr(err)
		return r
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "ip":
			r.IP = v
		case "loc":
			r.CC = v
		}
	}
	if r.IP == "" {
		r.Err = "没有拿到 IP"
	}
	return r
}

func egressErr(err error) string {
	e := err.Error()
	switch {
	case strings.Contains(e, "Timeout") || strings.Contains(e, "deadline") || strings.Contains(e, "timeout"):
		return "经这个节点 10 秒内没连上（节点可能不可用）"
	case strings.Contains(e, "refused"):
		return "连接被拒绝"
	case strings.Contains(e, "EOF") || strings.Contains(e, "reset"):
		return "连接被断开（节点可能不可用）"
	}
	return shortErr(err)
}
