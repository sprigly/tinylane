package main

// M6 设备相关：按设备流量统计（独立 nft 表 inet tinylane_acct，只计数不改判决，含国内直连 cn4 绕过的流量）、
// 访客 SSID（tinylane-guest.sh 写 uci + 一次 network reload + 自检，失败自动撤回）、新设备默认访客。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---------------- 流量统计 ----------------

func buildAcctNft(c *Config) string {
	lan := strings.Join(collapse(c.LAN.CIDR), ", ")
	var b strings.Builder
	fmt.Fprintf(&b, "# 由 tinylane 生成：按设备流量计数（只计数，policy accept，不影响任何转发）\n")
	fmt.Fprintf(&b, "table inet tinylane_acct {\n")
	for _, s := range []string{"up4", "down4"} {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tsize 1024\n\t\tflags dynamic,timeout\n\t\ttimeout 2d\n\t\tcounter\n\t}\n", s)
	}
	fmt.Fprintf(&b, "\tchain pre {\n\t\ttype filter hook prerouting priority -310; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q ip saddr { %s } ip daddr != { %s } update @up4 { ip saddr }\n\t}\n", c.LAN.Iface, lan, lan)
	fmt.Fprintf(&b, "\tchain post {\n\t\ttype filter hook postrouting priority 310; policy accept;\n")
	fmt.Fprintf(&b, "\t\toifname %q ip daddr { %s } ip saddr != { %s } update @down4 { ip daddr }\n\t}\n}\n", c.LAN.Iface, lan, lan)
	return b.String()
}

type acctDay struct {
	Day  string              `json:"day"`
	Tot  map[string][2]int64 `json:"tot"` // key（MAC 或 IP）→ 今日 上/下 字节
	Last map[string][2]int64 `json:"-"`   // IP → 上次计数
}

type Acct struct {
	d     *Daemon
	mu    sync.Mutex
	day   acctDay
	rate  map[string][2]int64 // IP → B/s
	at    time.Time
	ok    bool
	err   string
	saved time.Time
}

var reAcctElem = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)[^,}]*?counter packets \d+ bytes (\d+)`)

func parseAcctSet(text, set string) map[string]int64 {
	out := map[string]int64{}
	i := strings.Index(text, "set "+set+" ")
	if i < 0 {
		return out
	}
	seg := text[i:]
	if j := strings.Index(seg[4:], "set "); j >= 0 {
		seg = seg[:j+4]
	}
	for _, m := range reAcctElem.FindAllStringSubmatch(seg, -1) {
		v, _ := strconv.ParseInt(m[2], 10, 64)
		out[m[1]] = v
	}
	return out
}

func (d *Daemon) runScriptOut(script, arg string, env []string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, script, arg)
	cmd.Env = append(append(os.Environ(), "RUN="+d.runDir), env...)
	return cmd.CombinedOutput()
}

func newAcct(d *Daemon) *Acct {
	a := &Acct{d: d, rate: map[string][2]int64{}}
	a.day = acctDay{Day: time.Now().In(cst).Format("2006-01-02"), Tot: map[string][2]int64{}, Last: map[string][2]int64{}}
	if b, err := os.ReadFile(filepath.Join(d.workDir, "acct.json")); err == nil {
		var x acctDay
		if json.Unmarshal(b, &x) == nil && x.Day == a.day.Day && x.Tot != nil {
			a.day.Tot = x.Tot
		}
	}
	return a
}

func (a *Acct) setup() error {
	c := a.d.conf()
	path := filepath.Join(a.d.runDir, "acct.nft")
	if err := writeFileAtomic(path, []byte(buildAcctNft(c)), 0o600); err != nil {
		return err
	}
	out, err := a.d.runScriptOut(a.d.nftScript, "acct-up", []string{"ACCT_FILE=" + path}, 20*time.Second)
	if err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *Acct) loop() {
	if err := a.setup(); err != nil {
		a.mu.Lock()
		a.err = "流量统计未启用：" + err.Error()
		a.mu.Unlock()
		a.d.events.add("error", a.err)
		return
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		a.poll()
		select {
		case <-a.d.ctx.Done():
			a.save()
			return
		case <-t.C:
		}
	}
}

func (a *Acct) poll() {
	out, err := a.d.runScriptOut(a.d.nftScript, "acct-dump", nil, 10*time.Second)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.ok, a.err = false, strings.TrimSpace(string(out))
		if strings.Contains(a.err, "No such file") || strings.Contains(a.err, "does not exist") {
			go a.setup() // 表被别人删了（如 fw4 restart 不会删 inet 自有表，但手动 flush ruleset 会）→ 重建
		}
		return
	}
	up, down := parseAcctSet(string(out), "up4"), parseAcctSet(string(out), "down4")
	day := now.In(cst).Format("2006-01-02")
	if day != a.day.Day {
		a.day.Day, a.day.Tot = day, map[string][2]int64{}
	}
	dt := now.Sub(a.at).Seconds()
	keyOf := a.keyMap()
	newRate := map[string][2]int64{}
	ips := map[string]bool{}
	for ip := range up {
		ips[ip] = true
	}
	for ip := range down {
		ips[ip] = true
	}
	for ip := range ips {
		cur := [2]int64{up[ip], down[ip]}
		prev, had := a.day.Last[ip]
		var du, dd int64
		if had {
			du, dd = cur[0]-prev[0], cur[1]-prev[1]
			if du < 0 {
				du = cur[0]
			}
			if dd < 0 {
				dd = cur[1]
			}
		} else if a.ok { // 新出现的元素：计数从 0 开始，全部算增量
			du, dd = cur[0], cur[1]
		}
		a.day.Last[ip] = cur
		k := keyOf(ip)
		if du > 0 && had { // M6c：设备自己发出的包 = 它醒着（下行不算：发给休眠设备的包也会被计数）
			noteSeen(k, now.Unix())
		}
		t := a.day.Tot[k]
		a.day.Tot[k] = [2]int64{t[0] + du, t[1] + dd}
		if had && dt > 0.5 {
			newRate[ip] = [2]int64{int64(float64(du) / dt), int64(float64(dd) / dt)}
		}
	}
	a.rate, a.at, a.ok, a.err = newRate, now, true, ""
	if now.Sub(a.saved) > time.Minute {
		a.saveLocked()
	}
}

// keyMap：IP → MAC（租约/ARP），没有 MAC 就用 IP。今日统计按 MAC 记，换 IP 也不丢。
func (a *Acct) keyMap() func(string) string {
	c := a.d.conf()
	leases := readLeases(a.d.leases)
	arp := readARP(c.LAN.Iface)
	return func(ip string) string {
		if l, ok := leases[ip]; ok && l[0] != "" {
			return strings.ToLower(l[0])
		}
		if m, ok := arp[ip]; ok && m != "" {
			return strings.ToLower(m)
		}
		return ip
	}
}

func (a *Acct) save() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.saveLocked()
}

func (a *Acct) saveLocked() {
	b, _ := json.Marshal(a.day)
	writeFileAtomic(filepath.Join(a.d.workDir, "acct.json"), b, 0o600)
	a.saved = time.Now()
}

// lookup：给面板的设备卡（今日 上/下、实时 上/下）
func (a *Acct) lookup(mac, ip string) (today [2]int64, rate [2]int64) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac != "" {
		today = a.day.Tot[strings.ToLower(mac)]
	}
	if today == [2]int64{} && ip != "" {
		today = a.day.Tot[ip]
	}
	if ip != "" {
		rate = a.rate[ip]
	}
	return
}

func (a *Acct) status() map[string]any {
	if a == nil {
		return map[string]any{"ok": false, "error": "未启动"}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var tu, td int64
	for _, v := range a.day.Tot {
		tu += v[0]
		td += v[1]
	}
	return map[string]any{"ok": a.ok, "error": a.err, "day": a.day.Day, "today_up": tu, "today_down": td, "at": a.at.Unix()}
}

// ---------------- 访客 SSID ----------------

func (g GuestWifi) check() error {
	if !g.Enabled && g.SSID == "" {
		return nil
	}
	if g.SSID == "" || len(g.SSID) > 32 || !utf8.ValidString(g.SSID) {
		return fmt.Errorf("访客 Wi‑Fi 名称要 1–32 字节")
	}
	for _, r := range g.SSID {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("访客 Wi‑Fi 名称不能含控制字符")
		}
	}
	if g.Key != "" {
		if len(g.Key) < 8 || len(g.Key) > 63 {
			return fmt.Errorf("访客 Wi‑Fi 密码要 8–63 位")
		}
		for _, r := range g.Key {
			if r < 0x20 || r > 0x7e {
				return fmt.Errorf("访客 Wi‑Fi 密码只能用英文字母、数字和符号")
			}
		}
	}
	switch g.Band {
	case "both", "2g", "5g", "":
	default:
		return fmt.Errorf("访客 Wi‑Fi 频段只能是 both/2g/5g")
	}
	if g.CheckPing != "" && net.ParseIP(g.CheckPing) == nil {
		return fmt.Errorf("guest_wifi.check_ping 要是 IP")
	}
	p, err := parsePrefix(g.Subnet)
	if g.Subnet != "" && (err != nil || !p.Addr().Is4() || p.Bits() != 24 || !p.Addr().IsPrivate()) {
		return fmt.Errorf("访客网段要是私有 /24（如 192.168.77.1/24）")
	}
	if g.Subnet != "" && err == nil && p.Masked().Addr().String() == "192.168.1.0" {
		return fmt.Errorf("访客网段不能和局域网相同")
	}
	return nil
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func buildGuestEnv(g GuestWifi) string {
	en := 0
	if g.Enabled {
		en = 1
	}
	ip, _, _ := strings.Cut(g.Subnet, "/")
	return fmt.Sprintf("ENABLED=%d\nSSID=%s\nKEY=%s\nBAND=%s\nGUEST_IP=%s\nWG_PING=%s\n", en, shq(g.SSID), shq(g.Key), shq(g.Band), shq(ip), shq(g.CheckPing))
}

type guestJob struct {
	mu      sync.Mutex
	running bool
	msg     string
	at      int64
}

func (d *Daemon) guestScript() string {
	return filepath.Join(filepath.Dir(d.nftScript), "tinylane-guest.sh")
}

// applyGuestWifi：写 guest.env → tinylane-guest.sh apply（脚本自己做：记下原 Wi‑Fi 接口 → uci → network reload
// → 30 秒内自检主 Wi‑Fi 接口都还在、wg0 能 ping 通 → 不通就撤回并再 reload 一次）。异步执行，面板轮询状态。
func (d *Daemon) applyGuestWifi(g GuestWifi) error {
	d.gjob.mu.Lock()
	if d.gjob.running {
		d.gjob.mu.Unlock()
		return fmt.Errorf("访客 Wi‑Fi 正在应用中，稍等")
	}
	d.gjob.running, d.gjob.msg = true, "正在应用…（约 30–60 秒，主 Wi‑Fi 会断开几秒）"
	d.gjob.mu.Unlock()
	envPath := filepath.Join(d.runDir, "guest.env")
	if err := writeFileAtomic(envPath, []byte(buildGuestEnv(g)), 0o600); err != nil {
		d.gjob.mu.Lock()
		d.gjob.running = false
		d.gjob.mu.Unlock()
		return err
	}
	go func() {
		out, err := d.runScriptOut(d.guestScript(), "apply", []string{"GUEST_ENV=" + envPath}, 180*time.Second)
		msg := lastLines(strings.TrimSpace(string(out)), 1)
		ok := err == nil && strings.HasPrefix(msg, "OK")
		if ok && g.Enabled {
			d.applyEdit(applyOpts{}, func(m map[string]any) error {
				gw, _ := m["guest_wifi"].(map[string]any)
				if gw != nil {
					gw["applied"] = time.Now().In(cst).Format("2006-01-02 15:04")
				}
				return nil
			})
		}
		if !ok && g.Enabled {
			// 自检失败已撤回：配置里也关掉，避免下次开机又试
			d.applyEdit(applyOpts{}, func(m map[string]any) error {
				if gw, _ := m["guest_wifi"].(map[string]any); gw != nil {
					gw["enabled"] = false
				}
				return nil
			})
		}
		if msg == "" && err != nil {
			msg = err.Error()
		}
		d.gjob.mu.Lock()
		d.gjob.running, d.gjob.msg, d.gjob.at = false, msg, time.Now().Unix()
		d.gjob.mu.Unlock()
		kind := "config"
		if !ok {
			kind = "error"
		}
		d.events.add(kind, "访客 Wi‑Fi："+msg)
	}()
	return nil
}

func (d *Daemon) guestStatus() map[string]any {
	d.gjob.mu.Lock()
	defer d.gjob.mu.Unlock()
	return map[string]any{"running": d.gjob.running, "msg": d.gjob.msg, "at": d.gjob.at, "available": fileExists(d.guestScript())}
}

// ---------------- 新设备默认访客 ----------------

func knownMACs(c *Config) map[string]bool {
	k := map[string]bool{}
	for m := range c.DeviceInfo {
		k[strings.ToLower(m)] = true
	}
	for m := range c.DeviceNames {
		k[strings.ToLower(m)] = true
	}
	for _, m := range c.Guest.MACs {
		k[strings.ToLower(m)] = true
	}
	for _, m := range c.Blacklist.MACs {
		k[strings.ToLower(m)] = true
	}
	for _, dv := range c.Devices {
		if dv.MAC != "" {
			k[strings.ToLower(dv.MAC)] = true
		}
	}
	return k
}

// seenNow：当前租约 + ARP 里的 MAC → 主机名
func (d *Daemon) seenNow() map[string]string {
	c := d.conf()
	out := map[string]string{}
	for _, l := range readLeases(d.leases) {
		if isMAC(l[0]) {
			out[strings.ToLower(l[0])] = l[1]
		}
	}
	for _, m := range readARP(c.LAN.Iface) {
		if isMAC(m) {
			if _, ok := out[strings.ToLower(m)]; !ok {
				out[strings.ToLower(m)] = ""
			}
		}
	}
	return out
}

// setNewDefault：打开时把「现在在线 / 有租约」的设备都记为已知（不会被打成访客），之后才出现的 MAC 才算新设备。
func (d *Daemon) setNewDefault(on bool) error {
	seen := d.seenNow()
	now := time.Now().Unix()
	return d.applyEdit(applyOpts{desc: map[bool]string{true: "新设备默认访客：已开启（现有设备记为家人）", false: "新设备默认访客：已关闭"}[on]}, func(m map[string]any) error {
		g, _ := m["guest"].(map[string]any)
		if g == nil {
			g = map[string]any{}
			m["guest"] = g
		}
		g["new_device_default"] = on
		if on {
			di, _ := m["device_info"].(map[string]any)
			if di == nil {
				di = map[string]any{}
				m["device_info"] = di
			}
			for mac, host := range seen {
				if _, ok := di[mac]; !ok {
					e := map[string]any{"first_seen": now}
					if host != "" && host != "*" {
						e["hostname"] = host
					}
					di[mac] = e
				}
			}
		}
		return nil
	})
}

func (d *Daemon) newDeviceLoop() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		c := d.conf()
		if !c.Guest.NewDefault {
			continue
		}
		known := knownMACs(c)
		var fresh []string
		seen := d.seenNow()
		for mac := range seen {
			if !known[mac] {
				fresh = append(fresh, mac)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		now := time.Now().Unix()
		err := d.applyEdit(applyOpts{desc: fmt.Sprintf("新设备 %s 已自动设为访客（仅直连）", strings.Join(fresh, "、"))}, func(m map[string]any) error {
			g, _ := m["guest"].(map[string]any)
			if g == nil {
				return errNoChange
			}
			macs, _ := g["macs"].([]any)
			di, _ := m["device_info"].(map[string]any)
			if di == nil {
				di = map[string]any{}
				m["device_info"] = di
			}
			for _, mac := range fresh {
				macs = append(macs, mac)
				e := map[string]any{"first_seen": now}
				if h := seen[mac]; h != "" && h != "*" {
					e["hostname"] = h
				}
				di[mac] = e
			}
			g["macs"] = macs
			return nil
		})
		if err != nil && err != errNoChange {
			d.events.add("error", "新设备自动设为访客失败："+err.Error())
		}
	}
}
