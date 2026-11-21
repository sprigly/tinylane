package main

// 面板：监听 LAN IP（默认 br-lan 第一个 IPv4:9999），登录（PBKDF2 哈希存在 tinylane.json），
// 内嵌单文件 UI（gzip），JSON API 代理 clash_api 并经 applyEdit 修改配置。
// 安全：会话 cookie HttpOnly + SameSite=Strict；所有写操作要求 X-TL 头（跨站表单发不出来）；登录失败限速。

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed webui.html.gz
var webUI []byte

type Panel struct {
	d        *Daemon
	mu       sync.Mutex
	sessions map[string]*psess
	fails    map[string][]time.Time
	gfails   []time.Time         // 全局失败记录（防多 IP 轮换爆破）
	connPrev map[string][2]int64 // 连接 id → 上次 up/down
	connAt   time.Time
	ipRate   map[string][2]int64 // 源 IP → 上下行 B/s
}

func newPanel(d *Daemon) *Panel {
	return &Panel{d: d, sessions: map[string]*psess{}, fails: map[string][]time.Time{}, connPrev: map[string][2]int64{}, ipRate: map[string][2]int64{}}
}

func (p *Panel) listenAddrs() []string {
	c := p.d.conf()
	if len(c.Panel.Listen) > 0 {
		return c.Panel.Listen
	}
	if ifc, err := net.InterfaceByName(c.LAN.Iface); err == nil {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return []string{ipn.IP.String() + ":9999"}
			}
		}
	}
	return nil
}

func (p *Panel) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.index)
	for k := range iconTypes {
		mux.HandleFunc(k, p.icon)
	}
	mux.HandleFunc("/api/", p.api)
	mux.HandleFunc("/cgi-bin/luci/tinylane-sso", p.luciSSO)
	for {
		addrs := p.listenAddrs()
		if len(addrs) == 0 {
			// LAN 接口还没地址（开机早期）：等一会再试
			time.Sleep(5 * time.Second)
			continue
		}
		var wg sync.WaitGroup
		for _, a := range addrs {
			wg.Add(1)
			go func(a string) {
				defer wg.Done()
				srv := &http.Server{Addr: a, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
				p.d.events.add("system", "面板监听 http://"+a)
				err := srv.ListenAndServe()
				p.d.events.add("error", "面板监听 "+a+" 失败："+err.Error())
			}(a)
		}
		wg.Wait()
		select {
		case <-p.d.ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func secHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

func (p *Panel) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	secHeaders(w)
	// 允许被同一台路由器上的 LuCI（任意端口）嵌入；其它站点不能嵌入
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors "+frameAncestors(r))
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(webUI)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(webUI))
	if err == nil {
		io.Copy(w, zr)
	}
}

// ---------------- 密码 ----------------

const pbkdfIter = 60000 // MT7981 上约 0.1–0.2 s

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	k, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k))
}

func checkPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10000000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(k, want) == 1
}

func randomPassword() string {
	const al = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 14)
	rand.Read(b)
	for i := range b {
		b[i] = al[int(b[i])%len(al)]
	}
	return string(b)
}

// cmdPasswd：面板不再有独立密码（用 root 密码 / LuCI 会话）。--clear 删掉旧配置里的 panel.password_hash。
func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	clear := fs.Bool("clear", false, "删除旧的独立面板密码哈希")
	fs.Parse(args)
	if !*clear {
		return fmt.Errorf("面板用路由器 root 密码登录（与 LuCI 相同），用 passwd 命令改 root 密码；tinylane passwd --clear 删除旧的独立面板密码哈希")
	}
	if err := editRawFile(*in, func(m map[string]any) error {
		if pm, ok := m["panel"].(map[string]any); ok {
			delete(pm, "password_hash")
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "已删除 panel.password_hash")
	return nil
}

func cmdGroupType(args []string) error {
	fs := flag.NewFlagSet("group-type", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	fs.Parse(args)
	if fs.NArg() != 2 || (fs.Arg(1) != "select" && fs.Arg(1) != "failover") {
		return fmt.Errorf("用法：tinylane group-type <组> select|failover")
	}
	found := false
	err := editRawFile(*in, func(m map[string]any) error {
		gs, _ := m["groups"].([]any)
		for _, g := range gs {
			if gm, ok := g.(map[string]any); ok && gm["name"] == fs.Arg(0) {
				gm["type"] = fs.Arg(1)
				found = true
			}
		}
		if !found {
			return fmt.Errorf("没有组 %q", fs.Arg(0))
		}
		return nil
	})
	if err == nil {
		fmt.Printf("组 %s → %s\n", fs.Arg(0), fs.Arg(1))
	}
	return err
}

// editRawFile：保留未知字段地改 tinylane.json，并用 loadConfig 校验，失败不写。
func editRawFile(path string, mutate func(m map[string]any) error) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if err := mutate(m); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := writeFileAtomic(tmp, marshal(m), 0o600); err != nil {
		return err
	}
	if _, err := loadConfig(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------- 会话 ----------------

func clientIP(r *http.Request) string {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

// authed / login / LuCI 单点登录：见 auth.go

func jok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jerr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------------- API 路由 ----------------

func (p *Panel) api(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	path := strings.TrimPrefix(r.URL.Path, "/api")
	if r.Method != "GET" {
		// 写操作：必须带 X-TL 头 + 同源（防 CSRF）
		if r.Header.Get("X-TL") != "1" {
			jerr(w, 403, "缺少 X-TL 头")
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || u.Host != r.Host {
				jerr(w, 403, "跨站请求被拒绝")
				return
			}
		}
		lim := int64(256 << 10)
		if strings.HasPrefix(path, "/import/") || strings.HasPrefix(path, "/raw/") {
			lim = 2 << 20 // 导入 / 高级模式可能是整份配置或一大段规则
		}
		r.Body = http.MaxBytesReader(w, r.Body, lim)
	}
	if path == "/login" && r.Method == "POST" {
		p.login(w, r)
		return
	}
	if path == "/luci-login" && r.Method == "POST" {
		p.luciLogin(w, r)
		return
	}
	if path == "/session" {
		jok(w, map[string]any{"authed": p.authed(r), "has_password": true, "auth": "root", "version": tlVersion})
		return
	}
	if !p.authed(r) {
		jerr(w, 401, "未登录")
		return
	}
	var in map[string]json.RawMessage
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err != io.EOF {
			jerr(w, 400, "JSON 无效")
			return
		}
	}
	rt := p.routes()
	for k, v := range p.routesM6() {
		rt[k] = v
	}
	h, ok := rt[r.Method+" "+path]
	if !ok {
		jerr(w, 404, "没有这个接口")
		return
	}
	v, err := h(r, in)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if v == nil {
		v = map[string]any{"ok": true}
	}
	if b, ok := v.([]byte); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="tinylane-config.json"`)
		w.Write(b)
		return
	}
	jok(w, v)
}

type handler func(r *http.Request, in map[string]json.RawMessage) (any, error)

func gets(in map[string]json.RawMessage, k string) string {
	var s string
	json.Unmarshal(in[k], &s)
	return s
}

func getb(in map[string]json.RawMessage, k string) bool {
	var b bool
	json.Unmarshal(in[k], &b)
	return b
}

func geti(in map[string]json.RawMessage, k string) int {
	var i int
	if err := json.Unmarshal(in[k], &i); err != nil {
		return -1
	}
	return i
}

func (p *Panel) routes() map[string]handler {
	d := p.d
	return map[string]handler{
		"POST /logout": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			if ck, err := r.Cookie("tl_s"); err == nil {
				p.mu.Lock()
				delete(p.sessions, ck.Value)
				p.mu.Unlock()
			}
			return nil, nil
		},
		"GET /state": func(r *http.Request, _ map[string]json.RawMessage) (any, error) { return p.state(), nil },
		"GET /live":  func(r *http.Request, _ map[string]json.RawMessage) (any, error) { return p.live(), nil },
		"GET /conns": func(r *http.Request, _ map[string]json.RawMessage) (any, error) { return p.conns() },
		"POST /mode": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			mode := gets(in, "mode")
			if mode != "rule" && mode != "global" && mode != "direct" {
				return nil, fmt.Errorf("模式无效")
			}
			if err := d.clash().do("PATCH", "/configs", map[string]string{"mode": mode}, nil); err != nil {
				return nil, err
			}
			return nil, d.applyEdit(applyOpts{hot: true, desc: "运行模式 → " + modeCN(mode)}, func(m map[string]any) error { m["mode"] = mode; return nil })
		},
		"POST /enabled": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, d.setEnabled(getb(in, "on"))
		},
		"POST /select": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			group, node := gets(in, "group"), gets(in, "node")
			c := d.conf()
			g, ok := findGroup(c, group)
			if !ok {
				return nil, fmt.Errorf("没有组 %q", group)
			}
			if indexOf(c.members(group), node) < 0 {
				return nil, fmt.Errorf("%q 不是 %s 的成员", node, group)
			}
			if err := d.clash().do("PUT", "/proxies/"+url.PathEscape(group), map[string]string{"name": node}, nil); err != nil {
				return nil, err
			}
			if g.Type == "failover" && d.wd != nil {
				d.wd.Hold(group, c.Watchdog.HoldMinutes)
			}
			d.events.add("switch", fmt.Sprintf("%s：手动选择 %s", group, node))
			return nil, nil
		},
		"POST /auto": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			if d.wd != nil {
				d.wd.Release(gets(in, "group"))
			}
			return nil, nil
		},
		"POST /delay": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var names []string
			json.Unmarshal(in["names"], &names)
			if len(names) > 64 {
				return nil, fmt.Errorf("一次最多 64 个")
			}
			if d.wd == nil {
				return nil, fmt.Errorf("看门狗未启动")
			}
			d.wd.delayMany(names)
			n, _ := d.wd.Snapshot()
			return n, nil
		},
		"POST /speed": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			if d.wd == nil {
				return nil, fmt.Errorf("看门狗未启动")
			}
			name := gets(in, "node")
			if _, ok := nodeMap(d.conf())[name]; !ok {
				return nil, fmt.Errorf("没有节点 %q", name)
			}
			dn, up, err := d.wd.Heavy(name)
			res := map[string]any{"down_kbps": dn, "up_kbps": up}
			if err != nil {
				res["error"] = err.Error()
			}
			return res, nil
		},
		"POST /group": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name := gets(in, "name")
			return nil, d.applyEdit(applyOpts{desc: "组「" + name + "」已修改"}, func(m map[string]any) error {
				gs, _ := m["groups"].([]any)
				for _, g := range gs {
					gm, ok := g.(map[string]any)
					if !ok || gm["name"] != name {
						continue
					}
					return applyGroupFields(gm, in, false)
				}
				return fmt.Errorf("没有组 %q", name)
			})
		},
		// M7：新建 / 删除组
		"POST /group/add": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name := strings.TrimSpace(gets(in, "name"))
			if name == "" || len(name) > 40 || strings.ContainsAny(name, "\"/") {
				return nil, fmt.Errorf("组名称无效（1–40 个字符，不能含 / \\ \"）")
			}
			c := d.conf()
			if _, ok := nodeMap(c)[name]; ok || name == "direct" || name == "block" || name == probeTag {
				return nil, fmt.Errorf("名称「%s」已被占用", name)
			}
			if _, ok := findGroup(c, name); ok {
				return nil, fmt.Errorf("已有同名组")
			}
			return nil, d.applyEdit(applyOpts{desc: "新建组「" + name + "」"}, func(m map[string]any) error {
				gm := map[string]any{"name": name, "type": "failover", "members": []string{}}
				if err := applyGroupFields(gm, in, true); err != nil {
					return err
				}
				gs, _ := m["groups"].([]any)
				m["groups"] = append(gs, gm)
				return nil
			})
		},
		"POST /group/delete": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name := gets(in, "name")
			c := d.conf()
			g, ok := findGroup(c, name)
			if !ok {
				return nil, fmt.Errorf("没有组 %q", name)
			}
			if refs := refsTo(c, name, true); len(refs) > 0 {
				return nil, fmt.Errorf("组「%s」还在被使用：%s。请先把它们改到其他组（或直连）再删除", groupLabel(g), strings.Join(refs, "、"))
			}
			return nil, d.applyEdit(applyOpts{desc: "删除组「" + groupLabel(g) + "」"}, func(m map[string]any) error {
				gs, _ := m["groups"].([]any)
				var keep []any
				for _, x := range gs {
					if gm, _ := x.(map[string]any); gm != nil && gm["name"] == name {
						continue
					}
					keep = append(keep, x)
				}
				m["groups"] = keep
				return nil
			})
		},
		"POST /rules": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var rules []Rule
			if err := json.Unmarshal(in["rules"], &rules); err != nil {
				return nil, fmt.Errorf("规则格式无效：%v", err)
			}
			for i, x := range rules {
				if len(x.Domain)+len(x.DomainSuffix)+len(x.DomainKeyword)+len(x.DomainRegex)+len(x.IPCIDR)+len(x.Port)+len(x.SourceIP) == 0 {
					return nil, fmt.Errorf("规则 #%d 没有匹配条件", i+1)
				}
				for _, re := range x.DomainRegex {
					if len(re) > 256 {
						return nil, fmt.Errorf("正则太长")
					}
				}
			}
			return nil, d.applyEdit(applyOpts{desc: fmt.Sprintf("自定义规则已保存（%d 条）", len(rules))}, func(m map[string]any) error {
				m["rules"] = rules
				return nil
			})
		},
		"POST /optimize": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var q SQMConfig
			if err := json.Unmarshal(in["sqm"], &q); err != nil {
				return nil, fmt.Errorf("整形参数无效")
			}
			by, to := getb(in, "kernel_cn_bypass"), geti(in, "direct_connect_timeout_s")
			if to < 1 || to > 120 {
				return nil, fmt.Errorf("直连超时只能是 1–120 秒")
			}
			return nil, d.applyEdit(applyOpts{desc: "国内直连优化设置已保存"}, func(m map[string]any) error {
				if q.Iface == "" {
					q.Iface = "wan"
				}
				m["sqm"] = q
				m["kernel_cn_bypass"] = by
				m["direct_connect_timeout_s"] = to
				if _, ok := in["kernel_conn_log"]; ok {
					m["kernel_conn_log"] = getb(in, "kernel_conn_log")
				}
				return nil
			})
		},
		"POST /optimize/measure": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return d.sqmMeasure()
		},
		"POST /guest": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			on := getb(in, "direct_only")
			return nil, d.applyEdit(applyOpts{desc: map[bool]string{true: "访客只允许直连：开", false: "访客只允许直连：关"}[on]}, func(m map[string]any) error {
				gm, _ := m["guest"].(map[string]any)
				if gm == nil {
					gm = map[string]any{}
				}
				gm["direct_only"] = on
				m["guest"] = gm
				return nil
			})
		},
		"POST /device/mode": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			ip, mode, group, name := gets(in, "ip"), gets(in, "mode"), gets(in, "group"), gets(in, "name")
			return nil, d.applyEdit(applyOpts{desc: fmt.Sprintf("设备 %s → %s %s", ip, modeCN(mode), group)}, func(m map[string]any) error {
				var devs []Device
				b, _ := json.Marshal(m["devices"])
				json.Unmarshal(b, &devs)
				var out []Device
				for _, x := range devs {
					if x.IP != ip {
						out = append(out, x)
					}
				}
				if mode != "follow" && mode != "" {
					if name == "" {
						name = ip
					}
					out = append(out, Device{Name: name, IP: ip, Mode: mode, Group: group})
				}
				m["devices"] = out
				return nil
			})
		},
		"POST /device/guest": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			mac := strings.ToLower(gets(in, "mac"))
			on := getb(in, "guest")
			if !isMAC(mac) {
				return nil, fmt.Errorf("需要设备 MAC")
			}
			return nil, d.applyEdit(applyOpts{desc: fmt.Sprintf("设备 %s 标记为%s", mac, map[bool]string{true: "访客", false: "家人"}[on])}, func(m map[string]any) error {
				gm, _ := m["guest"].(map[string]any)
				if gm == nil {
					gm = map[string]any{}
				}
				gm["macs"] = toggleList(gm["macs"], mac, on)
				m["guest"] = gm
				return nil
			})
		},
		"POST /device/block": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			mac := strings.ToLower(gets(in, "mac"))
			on := getb(in, "block")
			if !isMAC(mac) {
				return nil, fmt.Errorf("需要设备 MAC")
			}
			if on && arpMAC(clientIP(r)) == mac {
				return nil, fmt.Errorf("不能拉黑你正在用的这台设备")
			}
			return nil, d.applyEdit(applyOpts{desc: fmt.Sprintf("设备 %s %s", mac, map[bool]string{true: "已拉黑", false: "已解除拉黑"}[on])}, func(m map[string]any) error {
				bm, _ := m["blacklist"].(map[string]any)
				if bm == nil {
					bm = map[string]any{}
				}
				bm["macs"] = toggleList(bm["macs"], mac, on)
				m["blacklist"] = bm
				return nil
			})
		},
		"GET /history": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			q := r.URL.Query()
			hours, _ := strconv.Atoi(q.Get("hours"))
			if hours <= 0 || hours > 24 {
				hours = 24
			}
			if d.hist == nil {
				return nil, fmt.Errorf("历史记录未启动")
			}
			return d.hist.query(q.Get("ip"), q.Get("q"), hours, 400, d.kern), nil
		},
		"POST /device/kick": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			mac := strings.ToLower(gets(in, "mac"))
			if !isMAC(mac) {
				return nil, fmt.Errorf("需要设备 MAC")
			}
			if arpMAC(clientIP(r)) == mac {
				return nil, fmt.Errorf("不能踢掉你正在用的这台设备")
			}
			ban := geti(in, "ban_s")
			if err := d.kick(mac, ban); err != nil {
				return nil, err
			}
			name := d.conf().DeviceNames[mac]
			if name == "" {
				name = mac
			}
			d.events.add("device", fmt.Sprintf("%s 已踢下线（%d 秒内禁止重连）", name, ban))
			return nil, nil
		},
		"POST /device/name": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			mac, name := strings.ToLower(gets(in, "mac")), strings.TrimSpace(gets(in, "name"))
			if !isMAC(mac) || len(name) > 64 {
				return nil, fmt.Errorf("MAC 或名称无效")
			}
			typ, hasType := gets(in, "type"), in["type"] != nil
			if hasType && typ != "" && typ != "phone" && typ != "computer" && typ != "tablet" && typ != "tv" && typ != "other" {
				return nil, fmt.Errorf("设备类型无效")
			}
			return nil, d.applyEdit(applyOpts{}, func(m map[string]any) error {
				if hasType {
					di, _ := m["device_info"].(map[string]any)
					if di == nil {
						di = map[string]any{}
					}
					e, _ := di[mac].(map[string]any)
					if e == nil {
						e = map[string]any{}
					}
					if typ == "" {
						delete(e, "type")
					} else {
						e["type"] = typ
					}
					if _, ok := e["first_seen"]; !ok {
						e["first_seen"] = time.Now().Unix()
					}
					di[mac] = e
					m["device_info"] = di
				}
				dn, _ := m["device_names"].(map[string]any)
				if dn == nil {
					dn = map[string]any{}
				}
				if name == "" {
					delete(dn, mac)
				} else {
					dn[mac] = name
				}
				m["device_names"] = dn
				return nil
			})
		},
		"POST /node/add": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			n, err := linkToNode(strings.TrimSpace(gets(in, "link")))
			if err != nil {
				return nil, err
			}
			if nm := strings.TrimSpace(gets(in, "name")); nm != "" {
				n.Name = nm
			}
			n.Source = "manual"
			if _, dup := nodeMap(d.conf())[n.Name]; dup {
				return nil, fmt.Errorf("已有同名节点「%s」，请填一个名称", n.Name)
			}
			nl := []Node{n}
			if w := resolvePins(nl, nil, d.conf().DNS.CN[0]); len(w) > 0 {
				return nil, fmt.Errorf("证书指纹没能确认（连不上服务器或指纹不一致），没有添加")
			}
			n = nl[0]
			return map[string]string{"name": n.Name}, d.applyEdit(applyOpts{desc: "手动添加节点 " + n.Name}, func(m map[string]any) error {
				nodes, _ := m["nodes"].([]any)
				m["nodes"] = append(nodes, n)
				return nil
			})
		},
		"POST /node/delete": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name := gets(in, "name")
			if refs := refsTo(d.conf(), name, false); len(refs) > 0 {
				return nil, fmt.Errorf("节点「%s」还被 %s 直接使用，请先改到某个组再删除", name, strings.Join(refs, "、"))
			}
			return nil, d.applyEdit(applyOpts{desc: "删除节点 " + name}, func(m map[string]any) error {
				var cur Config
				b, _ := json.Marshal(m)
				json.Unmarshal(b, &cur)
				var keep []Node
				for _, n := range cur.Nodes {
					if n.Name == name {
						orphan := strings.HasPrefix(n.Source, "sub:")
						for _, sb := range cur.Subs {
							if "sub:"+sb.Name == n.Source {
								orphan = false
							}
						}
						if n.Source != "manual" && !orphan {
							return fmt.Errorf("订阅节点不能删除（下次订阅更新会回来），只能删手动节点")
						}
						continue
					}
					keep = append(keep, n)
				}
				groups, empty := removeNodesFromGroups(cur.Groups, map[string]bool{name: true})
				if len(empty) > 0 {
					return fmt.Errorf("删除后组「%s」没有成员：请先给它加其他节点、设置名称筛选，或删除这个组", strings.Join(empty, "、"))
				}
				if keep == nil {
					keep = []Node{}
				}
				m["nodes"], m["groups"] = keep, groups
				return nil
			})
		},
		// M7：出口检测（names 为空 = 全部节点）
		"POST /node/egress": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var names []string
			json.Unmarshal(in["names"], &names)
			if d.egress == nil {
				return nil, fmt.Errorf("出口检测未启动")
			}
			return map[string]int{"queued": d.egress.enqueue(names)}, nil
		},
		"POST /import/settings": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, d.applyEdit(applyOpts{desc: "导入设置已保存"}, func(m map[string]any) error {
				if _, ok := in["import_exclude"]; ok {
					v := strings.TrimSpace(gets(in, "import_exclude"))
					if v == defaultImportExclude {
						delete(m, "import_exclude")
					} else {
						m["import_exclude"] = v
					}
				}
				if _, ok := in["egress_probe"]; ok {
					if getb(in, "egress_probe") {
						delete(m, "egress_probe")
					} else {
						m["egress_probe"] = false
					}
				}
				return nil
			})
		},
		"POST /node/mtu": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name, on := gets(in, "name"), getb(in, "on")
			return nil, d.applyEdit(applyOpts{desc: fmt.Sprintf("%s MTU 修正：%v", name, on)}, func(m map[string]any) error {
				nodes, _ := m["nodes"].([]any)
				for _, n := range nodes {
					if nm, ok := n.(map[string]any); ok && nm["name"] == name {
						if on {
							delete(nm, "mtu_fix")
						} else {
							nm["mtu_fix"] = false
						}
						return nil
					}
				}
				return fmt.Errorf("没有节点 %q", name)
			})
		},
		"POST /sub/save": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			idx := geti(in, "index")
			s := Sub{Name: strings.TrimSpace(gets(in, "name")), URL: strings.TrimSpace(gets(in, "url")), Auto: gets(in, "auto")}
			return nil, d.applyEdit(applyOpts{desc: "订阅「" + s.Name + "」已保存"}, func(m map[string]any) error {
				var subs []Sub
				b, _ := json.Marshal(m["subscriptions"])
				json.Unmarshal(b, &subs)
				for i, x := range subs {
					if x.Name == s.Name && i != idx {
						return fmt.Errorf("已有同名订阅")
					}
				}
				if idx >= 0 && idx < len(subs) {
					if subs[idx].Name != s.Name {
						return fmt.Errorf("订阅名称不能修改（节点按名称归属）")
					}
					s.Updated, s.Count, s.UA = subs[idx].Updated, subs[idx].Count, subs[idx].UA
					subs[idx] = s
				} else {
					subs = append(subs, s)
				}
				m["subscriptions"] = subs
				return nil
			})
		},
		"POST /sub/delete": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			// M7：订阅连同它导入的节点一起删除，并从所有组移除（不留残留）；节点被规则/设备直接引用时拒绝
			idx := geti(in, "index")
			c := d.conf()
			if idx < 0 || idx >= len(c.Subs) {
				return nil, fmt.Errorf("订阅不存在")
			}
			sn := c.Subs[idx].Name
			own := subOwner(idx, sn)
			for _, n := range c.Nodes {
				if own(n) {
					if refs := refsTo(c, n.Name, false); len(refs) > 0 {
						return nil, fmt.Errorf("订阅里的节点「%s」还被 %s 直接使用，请先改到某个组再删除订阅", n.Name, strings.Join(refs, "、"))
					}
				}
			}
			cnt := 0
			err := d.applyEdit(applyOpts{desc: "订阅「" + sn + "」已删除"}, func(m map[string]any) error {
				var cur Config
				b, _ := json.Marshal(m)
				json.Unmarshal(b, &cur)
				si := -1
				for i, x := range cur.Subs {
					if x.Name == sn {
						si = i
					}
				}
				if si < 0 {
					return fmt.Errorf("订阅不存在")
				}
				own := subOwner(si, sn)
				gone := map[string]bool{}
				keep := []Node{}
				for _, n := range cur.Nodes {
					if own(n) {
						gone[n.Name] = true
						continue
					}
					keep = append(keep, n)
				}
				cnt = len(gone)
				groups, empty := removeNodesFromGroups(cur.Groups, gone)
				if len(empty) > 0 {
					return fmt.Errorf("删除后组「%s」没有成员：请先给它加其他节点、设置名称筛选，或删除这个组", strings.Join(empty, "、"))
				}
				subs := append(cur.Subs[:si:si], cur.Subs[si+1:]...)
				if len(subs) == 0 {
					delete(m, "subscriptions")
				} else {
					m["subscriptions"] = subs
				}
				m["nodes"], m["groups"] = keep, groups
				return nil
			})
			if err != nil {
				return nil, err
			}
			return map[string]int{"nodes_removed": cnt}, nil
		},
		"POST /sub/preview": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return d.subs.Preview(geti(in, "index"))
		},
		"POST /sub/apply": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return d.subs.Apply(geti(in, "index"), false)
		},
		"POST /rulesets/update": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			if err := updateRules(d.conf(), true); err != nil {
				return nil, err
			}
			if err := d.hotReload(); err != nil {
				return nil, err
			}
			if err := d.syncNft(); err != nil {
				return nil, err
			}
			d.events.add("config", "规则集已更新")
			return nil, nil
		},
		"POST /passwd": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, fmt.Errorf("面板现在用路由器 root 密码登录（与 LuCI 相同），请在 LuCI「系统 → 管理权」里修改")
		},
		"GET /export": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			raw, err := os.ReadFile(d.cfgPath)
			if err != nil {
				return nil, err
			}
			var m map[string]any
			json.Unmarshal(raw, &m)
			if pm, ok := m["panel"].(map[string]any); ok {
				delete(pm, "password_hash")
			}
			return marshal(m), nil
		},
	}
}

func modeCN(m string) string {
	switch m {
	case "global":
		return "全局代理"
	case "direct":
		return "全局直连"
	case "rule":
		return "规则分流"
	case "follow", "":
		return "跟随全局"
	}
	return m
}

func findGroup(c *Config, name string) (Group, bool) {
	for _, g := range c.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

func toggleList(v any, s string, on bool) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if xs, ok := x.(string); ok && strings.ToLower(xs) != s {
				out = append(out, xs)
			}
		}
	}
	if on {
		out = append(out, s)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// ---------------- 状态 ----------------

type nodeView struct {
	Name   string      `json:"name"`
	Type   string      `json:"type"`
	Source string      `json:"source"`
	Egress *Egress     `json:"egress,omitempty"` // M7：自动测得的出口
	EgPend bool        `json:"eg_pending,omitempty"`
	MTU    *bool       `json:"mtu,omitempty"` // 仅 hy2
	Health *NodeHealth `json:"health,omitempty"`
}

type groupView struct {
	Group
	Now       string   `json:"now"`
	Eff       []string `json:"eff"`    // M7：实际成员（手选 + 名称筛选 − 排除）
	Auto      []string `json:"auto"`   // 由名称筛选自动加入的
	Hidden    []string `json:"hidden"` // 手选了但被「排除含」去掉的
	HoldUntil int64    `json:"hold_until"`
	Note      string   `json:"note"`
	LastCheck int64    `json:"last_check"`
}

func (p *Panel) state() map[string]any {
	d := p.d
	c := d.conf()
	var health map[string]NodeHealth
	var gst map[string]groupState
	if d.wd != nil {
		health, gst = d.wd.Snapshot()
	}
	var nv []nodeView
	for _, n := range c.Nodes {
		v := nodeView{Name: n.Name, Type: n.Type(), Source: n.Source}
		if d.egress != nil {
			if e, ok, pend := d.egress.get(n.Name); ok {
				ee := e
				v.Egress, v.EgPend = &ee, pend
			} else {
				v.EgPend = pend
			}
		}
		if n.Type() == "hysteria2" {
			b := n.mtuFix()
			v.MTU = &b
		}
		if h, ok := health[n.Name]; ok {
			hh := h
			v.Health = &hh
		}
		nv = append(nv, v)
	}
	var proxies struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	d.clash().doCtx(d.ctx, 4*time.Second, "GET", "/proxies", nil, &proxies)
	var cfgs struct{ Mode string }
	modeErr := d.clash().doCtx(d.ctx, 3*time.Second, "GET", "/configs", nil, &cfgs)
	mode := strings.ToLower(cfgs.Mode)
	if modeErr != nil || mode == "" {
		mode = c.Mode
	}
	var gv []groupView
	for _, g := range c.Groups {
		v := groupView{Group: g, Now: proxies.Proxies[g.Name].Now}
		v.Eff, v.Auto, v.Hidden = computeMembers(c, g)
		for _, l := range []*[]string{&v.Eff, &v.Auto, &v.Hidden} {
			if *l == nil {
				*l = []string{}
			}
		}
		if v.Members == nil {
			v.Members = []string{}
		}
		if s, ok := gst[g.Name]; ok {
			v.HoldUntil, v.Note, v.LastCheck = s.HoldUntil, s.Note, s.LastCheck
		}
		gv = append(gv, v)
	}
	rs := map[string]int64{}
	for _, f := range []string{"geosite-cn.srs", "geoip-cn.srs"} {
		if st, err := os.Stat(filepath.Join(c.RuleSets.Dir, f)); err == nil {
			rs[f] = st.ModTime().Unix()
		}
	}
	subs := c.Subs
	if subs == nil {
		subs = []Sub{}
	}
	rules := c.Rules
	if rules == nil {
		rules = []Rule{}
	}
	st := map[string]any{
		"version": tlVersion, "enabled": c.Enabled, "mode": mode, "fallback": d.fallback.Load(), "core_up": d.coreUp.Load(),
		"core_restarts": d.coreRestarts.Load(),
		"main_group":    c.MainGroup, "groups": gv, "nodes": nv, "rules": rules,
		"guest": c.Guest, "devices": c.Devices, "subs": subs, "rulesets": rs,
		"watchdog": c.Watchdog, "events": d.events.recent(60),
		"optimize": map[string]any{"sqm": c.SQM, "kernel_cn_bypass": c.KernelCNBypass == nil || *c.KernelCNBypass, "direct_connect_timeout_s": c.DirectTimeoutS, "kernel_conn_log": kernLogOn(c), "kern": d.kern.stats(),
			"cn4_count": len(loadCN4(c.RuleSets.Dir)), "sqm_available": fileExists(d.sqmScript)},
		"basic": map[string]any{"lan_iface": c.LAN.Iface, "tproxy_port": c.TProxyPort, "dns_cn": c.DNS.CN, "dns_foreign": c.DNS.Foreign, "mixed": c.MixedListen},
		"rss":   map[string]int64{"core": procRSS(d.corePid()), "daemon": procRSS(os.Getpid())},
		"import": map[string]any{"exclude": c.importExclude(), "default_exclude": defaultImportExclude, "egress_probe": c.egressAuto()},
	}
	if d.egress != nil {
		st["egress"] = d.egress.status()
	}
	p.stateM6(st)
	return st
}

func (p *Panel) live() map[string]any {
	pts, ok := p.d.traffic.snapshot()
	return map[string]any{"traffic": pts, "fresh": ok, "fallback": p.d.fallback.Load(), "core_up": p.d.coreUp.Load(), "enabled": p.d.conf().Enabled}
}

type connView struct {
	ID    string `json:"id"`
	Src   string `json:"src"`
	Host  string `json:"host"`
	Port  string `json:"port"`
	Net   string `json:"net"`
	Rule  string `json:"rule"`
	Out   string `json:"out"`   // 实际出站（节点 / direct）
	Group string `json:"group"` // 最外层组（没有组 = 同 out）
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Start string `json:"start"`
	Kern  bool   `json:"kern,omitempty"` // M6d：国内 IP 内核直连（conntrack）
}

type devView struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	Host   string `json:"hostname"`
	Online bool   `json:"online"`
	Conns  int    `json:"conns"`
	Direct int    `json:"direct"`
	Proxy  int    `json:"proxy"`
	Block  int    `json:"blocked"`
	UpR    int64  `json:"up_rate"`
	DownR  int64  `json:"down_rate"`
	Guest  bool   `json:"guest"`
	Black  bool   `json:"black"`
	Mode   string `json:"mode"`
	Group  string `json:"group"`
	Self   bool   `json:"self"`
	Type   string `json:"type,omitempty"`
	First  int64  `json:"first_seen,omitempty"`
	Last   int64  `json:"last_seen,omitempty"`
	Conn   string `json:"conn,omitempty"`
	Wifi   bool   `json:"wifi"`
	Band   string `json:"band,omitempty"`
	Signal int    `json:"signal,omitempty"`
	TxRate int64  `json:"link_rate,omitempty"` // 路由器→设备 PHY 速率 bit/s
	Known  bool   `json:"known"`
	// M6c：online | sleep（30 分钟内有活动，如合盖休眠的 Mac）| offline
	State      string `json:"state"`
	LastActive int64  `json:"last_active,omitempty"`
	// M6：nft 按设备计数（含国内直连绕过 sing-box 的流量）
	TodayUp   int64 `json:"today_up"`
	TodayDown int64 `json:"today_down"`
	NUpR      int64 `json:"nft_up_rate"`
	NDownR    int64 `json:"nft_down_rate"`
}

func (p *Panel) conns() (any, error) {
	d := p.d
	var r struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				Network, SourceIP, Host, DestinationIP, DestinationPort string
			} `json:"metadata"`
			Upload, Download int64
			Rule             string
			Chains           []string
			Start            string
		} `json:"connections"`
		DownloadTotal int64 `json:"downloadTotal"`
		UploadTotal   int64 `json:"uploadTotal"`
	}
	if err := d.clash().doCtx(d.ctx, 5*time.Second, "GET", "/connections", nil, &r); err != nil {
		return nil, fmt.Errorf("内核未响应：%v", err)
	}
	now := time.Now()
	p.mu.Lock()
	dt := now.Sub(p.connAt).Seconds()
	recompute := dt >= 1
	newPrev := map[string][2]int64{}
	rates := map[string][2]int64{}
	var list []connView
	var dc []devConn
	for _, c := range r.Connections {
		m := c.Metadata
		host := m.Host
		if host == "" {
			host = m.DestinationIP
		}
		out, grp := "", ""
		if len(c.Chains) > 0 {
			out, grp = c.Chains[0], c.Chains[len(c.Chains)-1]
		}
		if out == probeTag || grp == probeTag {
			continue
		}
		dc = append(dc, devConn{m.SourceIP, out, c.Rule, c.Start})
		list = append(list, connView{c.ID, m.SourceIP, host, m.DestinationPort, m.Network, shortRule(c.Rule), out, grp, c.Upload, c.Download, c.Start, false})
		newPrev[c.ID] = [2]int64{c.Upload, c.Download}
		if recompute {
			pr := p.connPrev[c.ID]
			ru := rates[m.SourceIP]
			ru[0] += max64(0, c.Upload-pr[0])
			ru[1] += max64(0, c.Download-pr[1])
			rates[m.SourceIP] = ru
		}
	}
	if recompute {
		for ip, v := range rates {
			rates[ip] = [2]int64{int64(float64(v[0]) / dt), int64(float64(v[1]) / dt)}
		}
		if !p.connAt.IsZero() {
			p.ipRate = rates
		}
		p.connPrev, p.connAt = newPrev, now
	}
	rate := p.ipRate
	p.mu.Unlock()
	kv, kd := d.kern.liveViews()
	list, dc = append(list, kv...), append(dc, kd...)
	sort.Slice(list, func(i, j int) bool { return list[i].Start > list[j].Start })
	total := len(list)
	if len(list) > 300 {
		list = list[:300]
	}
	return map[string]any{"conns": list, "total": total, "devices": p.devices(dc, rate), "down_total": r.DownloadTotal, "up_total": r.UploadTotal}, nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func shortRule(s string) string {
	// "rule_set=geosite-cn => route(direct)" → "rule_set=geosite-cn"
	if i := strings.Index(s, " => "); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

type devConn struct{ src, out, rule, start string }

func (p *Panel) devices(cl []devConn, rate map[string][2]int64) []devView {
	c := p.d.conf()
	wifi := p.d.wifiClients()
	leases := readLeases(p.d.leases)
	neigh := readNeigh(c.LAN.Iface)
	now := time.Now().Unix()
	renew := leaseRenew(p.d.leases, now)
	arp := map[string]string{}
	for ip, e := range neigh {
		if neighValid(e.state) && e.mac != "" {
			arp[ip] = e.mac
		}
	}
	connLast := map[string]int64{}
	// state：hostapd 已关联 / neigh 正在通信 = 在线；否则看最近活动（休眠 / 离线）
	setState := func(v *devView) {
		online := v.Wifi || (v.IP != "" && neighActive(neigh[v.IP].state))
		key := v.MAC
		if key == "" {
			key = v.IP
		}
		if online {
			noteSeen(key, now)
		}
		last := lastSeen(v.MAC, v.IP)
		if t := renew[v.IP]; t > last && v.IP != "" && (v.MAC == "" || leases[v.IP][0] == v.MAC) {
			last = t
		}
		if t := connLast[v.IP]; t > last && v.IP != "" {
			last = t
		}
		if last > now {
			last = now
		}
		v.State, v.LastActive = devState(online, last, now), last
		v.Online = v.State == "online"
		if !v.Wifi && v.State == "sleep" && v.MAC != "" {
			if b := lastBand(v.MAC); b != "" {
				v.Conn = "Wi‑Fi · " + b
			}
		}
	}
	by := map[string]*devView{}
	get := func(ip string) *devView {
		if v, ok := by[ip]; ok {
			return v
		}
		v := &devView{IP: ip, Mode: "follow"}
		by[ip] = v
		return v
	}
	for ip, l := range leases {
		v := get(ip)
		v.MAC, v.Host = l[0], l[1]
	}
	for ip, mac := range arp {
		v := get(ip)
		if v.MAC == "" {
			v.MAC = mac
		}
	}
	lan := []netip.Prefix{}
	for _, s := range c.LAN.CIDR {
		if pf, err := parsePrefix(s); err == nil {
			lan = append(lan, pf)
		}
	}
	for _, x := range cl {
		ip := x.src
		if ip == "" || !inLAN(lan, ip) {
			continue
		}
		v := get(ip) // M6c：有连接不再算在线（离开 Wi‑Fi 后残留的连接会挂很久），只统计
		v.Conns++
		if t := connStartUnix(x.start); t > connLast[ip] && t <= now+5 {
			connLast[ip] = t
		}
		out := x.out
		switch {
		case strings.Contains(x.rule, "reject"):
			v.Block++
		case out == "direct":
			v.Direct++
		case out == probeTag:
		default:
			v.Proxy++
		}
	}
	guestMAC := map[string]bool{}
	for _, m := range c.Guest.MACs {
		guestMAC[strings.ToLower(m)] = true
	}
	black := map[string]bool{}
	for _, m := range c.Blacklist.MACs {
		black[strings.ToLower(m)] = true
	}
	devMode := map[string]Device{}
	for _, x := range c.Devices {
		devMode[x.IP] = x
	}
	var out []devView
	for ip, v := range by {
		if !inLAN(lan, ip) {
			continue
		}
		if r, ok := rate[ip]; ok {
			v.UpR, v.DownR = r[0], r[1]
		}
		v.Name = c.DeviceNames[strings.ToLower(v.MAC)]
		v.Guest = guestMAC[strings.ToLower(v.MAC)] || inPrefixes(c.Guest.IPs, ip)
		v.Black = black[strings.ToLower(v.MAC)]
		if dm, ok := devMode[ip]; ok {
			v.Mode, v.Group = dm.Mode, dm.Group
			if v.Name == "" && dm.Name != ip {
				v.Name = dm.Name
			}
		}
		if ip == lanSelfIP(c) {
			continue
		}
		fillDev(v, c, wifi)
		setState(v)
		out = append(out, *v)
	}
	// 记录过（迁移 / 改过名）但现在不在租约和 ARP 里的设备，也列出来（离线）
	have := map[string]bool{}
	for _, v := range out {
		if v.MAC != "" {
			have[strings.ToLower(v.MAC)] = true
		}
	}
	known := map[string]bool{}
	for m := range c.DeviceInfo {
		known[strings.ToLower(m)] = true
	}
	for m := range c.DeviceNames {
		known[strings.ToLower(m)] = true
	}
	for m := range known {
		if have[m] || black[m] || !isMAC(m) {
			continue
		}
		v := devView{MAC: m, Mode: "follow", Name: c.DeviceNames[m]}
		if di, ok := c.DeviceInfo[m]; ok {
			for _, ip := range di.IPs {
				if strings.Count(ip, ".") == 3 {
					v.IP = ip
					break
				}
			}
			v.Host = di.Hostname
		}
		v.Guest = guestMAC[m]
		fillDev(&v, c, wifi)
		setState(&v) // hostapd 里有它（比如刚连上还没拿到租约）= 在线
		out = append(out, v)
	}
	// 黑名单里但已离线的 MAC 也列出来（方便解除）
	for m := range black {
		found := false
		for _, v := range out {
			if strings.ToLower(v.MAC) == m {
				found = true
			}
		}
		if !found {
			out = append(out, devView{MAC: m, Black: true, Name: c.DeviceNames[m], Mode: "follow", State: "offline"})
		}
	}
	for i := range out {
		t, rt := p.d.acct.lookup(out[i].MAC, out[i].IP)
		out[i].TodayUp, out[i].TodayDown, out[i].NUpR, out[i].NDownR = t[0], t[1], rt[0], rt[1]
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := stateRank(out[i].State), stateRank(out[j].State)
		if ri != rj {
			return ri < rj
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

func stateRank(s string) int {
	switch s {
	case "online":
		return 0
	case "sleep":
		return 1
	}
	return 2
}

func lanSelfIP(c *Config) string {
	if ifc, err := net.InterfaceByName(c.LAN.Iface); err == nil {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
	}
	return ""
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	return bytes.Compare(pa, pb) < 0
}

// /tmp/dhcp.leases：expiry mac ip hostname clientid
func readLeases(path string) map[string][2]string {
	out := map[string][2]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) >= 4 {
			h := fl[3]
			if h == "*" {
				h = ""
			}
			out[fl[2]] = [2]string{strings.ToLower(fl[1]), h}
		}
	}
	return out
}

// /proc/net/arp：IP HWtype Flags HWaddr Mask Device；Flags 0x2 = 有效
func readARP(iface string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(arpPath)
	if err != nil {
		return out
	}
	for i, l := range strings.Split(string(b), "\n") {
		fl := strings.Fields(l)
		if i == 0 || len(fl) < 6 || fl[5] != iface || fl[2] == "0x0" || fl[3] == "00:00:00:00:00:00" {
			continue
		}
		out[fl[0]] = strings.ToLower(fl[3])
	}
	return out
}

func arpMAC(ip string) string {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		fl := strings.Fields(l)
		if len(fl) >= 4 && fl[0] == ip {
			return strings.ToLower(fl[3])
		}
	}
	return ""
}

func inLAN(lan []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range lan {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

func inPrefixes(list []string, ip string) bool {
	var ps []netip.Prefix
	for _, s := range list {
		if p, err := parsePrefix(s); err == nil {
			ps = append(ps, p)
		}
	}
	return inLAN(ps, ip)
}

func fillDev(v *devView, c *Config, wifi map[string]wifiClient) {
	m := strings.ToLower(v.MAC)
	v.MAC = m
	if di, ok := c.DeviceInfo[m]; ok {
		v.Known, v.Type, v.First, v.Last, v.Conn = true, di.Type, di.FirstSeen, di.LastSeen, di.Conn
		if v.Host == "" {
			v.Host = di.Hostname
		}
	}
	if _, ok := c.DeviceNames[m]; ok {
		v.Known = true
	}
	if w, ok := wifi[m]; ok && m != "" {
		v.Wifi, v.Band, v.Signal, v.TxRate = true, w.Band, w.Signal, w.TxRate
		v.Conn = "Wi‑Fi · " + w.Band
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// applyGroupFields：面板编辑组（M7）。只改请求里出现的字段；members 可为空（有名称筛选时）。
func applyGroupFields(gm map[string]any, in map[string]json.RawMessage, isNew bool) error {
	if _, ok := in["members"]; ok {
		var members []string
		if err := json.Unmarshal(in["members"], &members); err != nil {
			return fmt.Errorf("成员格式无效")
		}
		if members == nil {
			members = []string{}
		}
		gm["members"] = members
	}
	if t := gets(in, "type"); t != "" {
		gm["type"] = t
	}
	for _, k := range []string{"filter", "exclude", "label"} {
		if _, ok := in[k]; ok {
			v := strings.TrimSpace(gets(in, k))
			if v == "" {
				delete(gm, k)
			} else {
				gm[k] = v
			}
		}
	}
	if _, ok := in["strict"]; ok {
		if getb(in, "strict") {
			gm["strict"] = true
		} else {
			delete(gm, "strict")
		}
	}
	delete(gm, "forbid") // 旧字段
	return nil
}
