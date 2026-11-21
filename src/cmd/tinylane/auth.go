package main

// 面板认证（M3.1）：
//  1. LuCI 单点登录：LuCI 页面 iframe 打开 http://<host>:9999/cgi-bin/luci/tinylane-sso#sid=<LuCI 会话>。
//     浏览器会把 path=/cgi-bin/luci/ 的 sysauth_http / sysauth_https cookie 带过来（cookie 不分端口），
//     守护进程用 `ubus call session access` 校验（要求有 luci-app-tinylane 的 write 权限，root 登录是 *），
//     通过就发自己的 tl_s 会话；cookie 不可用时页面 JS 把 #sid 交给 POST /api/luci-login 再校验一次。
//     由 LuCI 会话换来的面板会话每 5 分钟重新校验，LuCI 退出/超时后面板也失效。
//  2. 兜底：独立登录页用 root 密码，按 /etc/shadow 的 crypt 哈希校验（不存任何密码/哈希）。
//  限速：每 IP 5 分钟 5 次失败锁定；root 密码登录另有全局 5 分钟 20 次失败锁定；每次失败延迟 300 ms。
//  LuCI cookie 单点登录不受锁定影响（防止局域网里有人乱试密码把管理员也锁在外面）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"regexp"
	"strings"
	"time"
)

type psess struct {
	exp     time.Time
	luciSID string // 非空 = 由 LuCI 会话换来
	checked time.Time
}

var reSID = regexp.MustCompile(`^[0-9a-f]{32}$`)

const luciACL = "luci-app-tinylane"

// LuCI 换来的面板会话多久重新校验一次（测试可用环境变量 TINYLANE_LUCI_RECHECK_S 缩短）
var luciRecheck = func() time.Duration {
	if s, err := strconv.Atoi(os.Getenv("TINYLANE_LUCI_RECHECK_S")); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return 5 * time.Minute
}()

// luciSessionOK：LuCI（rpcd）会话是否有效且有 luci-app-tinylane 写权限。
func (p *Panel) luciSessionOK(sid string) bool {
	if !reSID.MatchString(sid) || strings.Trim(sid, "0") == "" {
		return false
	}
	arg, _ := json.Marshal(map[string]string{"ubus_rpc_session": sid, "scope": "access-group", "object": luciACL, "function": "write"})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, p.d.ubusPath, "call", "session", "access", string(arg)).Output()
	if err != nil {
		return false
	}
	var r struct {
		Access bool `json:"access"`
	}
	return json.Unmarshal(out, &r) == nil && r.Access
}

func (p *Panel) sessTTL() time.Duration {
	return time.Duration(p.d.conf().Panel.SessionHours) * time.Hour
}

func (p *Panel) authed(r *http.Request) bool {
	ck, err := r.Cookie("tl_s")
	if err != nil {
		return false
	}
	p.mu.Lock()
	s, ok := p.sessions[ck.Value]
	if !ok || time.Now().After(s.exp) {
		delete(p.sessions, ck.Value)
		p.mu.Unlock()
		return false
	}
	recheck := s.luciSID != "" && time.Since(s.checked) > luciRecheck
	sid := s.luciSID
	p.mu.Unlock()
	if recheck {
		if !p.luciSessionOK(sid) {
			p.mu.Lock()
			delete(p.sessions, ck.Value)
			p.mu.Unlock()
			p.d.events.add("system", "LuCI 会话已失效，面板会话随之退出")
			return false
		}
		p.mu.Lock()
		s.checked = time.Now()
		p.mu.Unlock()
	}
	p.mu.Lock()
	s.exp = time.Now().Add(p.sessTTL())
	p.mu.Unlock()
	return true
}

// locked：返回是否已被限速（并清理过期记录）。
func (p *Panel) locked(ip string, global bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	keep := func(ts []time.Time) []time.Time {
		var out []time.Time
		for _, t := range ts {
			if time.Since(t) < 5*time.Minute {
				out = append(out, t)
			}
		}
		return out
	}
	p.fails[ip] = keep(p.fails[ip])
	if len(p.fails[ip]) == 0 {
		delete(p.fails, ip)
	}
	p.gfails = keep(p.gfails)
	return len(p.fails[ip]) >= 5 || (global && len(p.gfails) >= 20)
}

func (p *Panel) fail(ip string) {
	p.mu.Lock()
	p.fails[ip] = append(p.fails[ip], time.Now())
	p.gfails = append(p.gfails, time.Now())
	p.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
}

func (p *Panel) newSession(w http.ResponseWriter, ip, luciSID string) {
	tok := make([]byte, 24)
	rand.Read(tok)
	t := hex.EncodeToString(tok)
	p.mu.Lock()
	for k, s := range p.sessions {
		if time.Now().After(s.exp) {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) >= 32 {
		var oldK string
		var oldE time.Time
		for k, s := range p.sessions {
			if oldK == "" || s.exp.Before(oldE) {
				oldK, oldE = k, s.exp
			}
		}
		delete(p.sessions, oldK)
	}
	p.sessions[t] = &psess{exp: time.Now().Add(p.sessTTL()), luciSID: luciSID, checked: time.Now()}
	delete(p.fails, ip)
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "tl_s", Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(p.sessTTL().Seconds())})
}

// 兜底：root 密码登录（/etc/shadow）。
func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if p.locked(ip, true) {
		jerr(w, 429, "密码错误次数太多，请 5 分钟后再试")
		return
	}
	var in struct{ Password string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		jerr(w, 400, "请求无效")
		return
	}
	ok, err := verifyShadowPassword(p.d.shadowPath, "root", in.Password)
	if err != nil && err != errCryptUnsupported && in.Password != "" {
		// 读不到 shadow / root 没密码：不暴露细节
		p.d.events.add("error", "面板登录：无法校验 root 密码（"+err.Error()+"）")
	}
	if err == errCryptUnsupported {
		p.d.events.add("error", "面板登录：root 密码哈希类型不受支持，请从 LuCI 进入")
	}
	if !ok {
		p.fail(ip)
		jerr(w, 401, "密码错误")
		return
	}
	p.newSession(w, ip, "")
	p.d.events.add("system", "面板登录（root 密码）来自 "+ip)
	jok(w, map[string]any{"ok": true})
}

// POST /api/luci-login {"sid": "..."}：LuCI 页面把会话 ID 交过来（cookie 不可用时）。
func (p *Panel) luciLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if p.locked(ip, false) { // 只按 IP 锁：别人在局域网乱试密码不能把 LuCI 单点登录也锁住
		jerr(w, 429, "失败次数太多，请 5 分钟后再试")
		return
	}
	var in struct{ Sid string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		jerr(w, 400, "请求无效")
		return
	}
	if !p.luciSessionOK(in.Sid) {
		p.fail(ip)
		jerr(w, 401, "LuCI 会话无效或已过期")
		return
	}
	p.newSession(w, ip, in.Sid)
	p.d.events.add("system", "面板登录（LuCI 会话）来自 "+ip)
	jok(w, map[string]any{"ok": true})
}

// GET /cgi-bin/luci/tinylane-sso：用 LuCI 的 sysauth cookie 换面板会话，然后回到 /（#sid 片段浏览器会保留）。
func (p *Panel) luciSSO(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	ip := clientIP(r)
	// 不受密码锁定影响：只认 rpcd 里真实存在的 128 位会话 ID
	if !p.authed(r) {
		for _, n := range []string{"sysauth_http", "sysauth_https", "sysauth"} {
			if ck, err := r.Cookie(n); err == nil {
				// 过期的旧 cookie 很常见，不计入失败（会话 ID 128 位随机，无法爆破）
				if p.luciSessionOK(ck.Value) {
					p.newSession(w, ip, ck.Value)
					p.d.events.add("system", "面板登录（LuCI cookie）来自 "+ip)
				}
				break
			}
		}
	}
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
}

// frameAncestors：只允许同一主机（任意端口，http/https）嵌入面板。
func frameAncestors(r *http.Request) string {
	host := r.Host
	if u, err := url.Parse("http://" + host); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	ok := regexp.MustCompile(`^[A-Za-z0-9.\-]+$|^\[[0-9a-fA-F:.]+\]$`)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if !ok.MatchString(host) {
		return "'self'"
	}
	return "'self' http://" + host + ":* https://" + host + ":* http://" + host + " https://" + host
}
