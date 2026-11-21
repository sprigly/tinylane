package main

// M6c：设备三态 + 离线设备残留连接清理。
//
// 11-19 实测：Mac 合盖休眠时大部分时间不在 hostapd、ARP FAILED，每 15–17 分钟
// 短暂唤醒（Power Nap）连上 Wi‑Fi 1–18 秒、续租 DHCP、建一批连接后又断开；这些连接
// 没关就挂在 sing-box 里，旧版把「有连接」当在线，于是一直显示在线。
//
// 状态（state）：
//   online  hostapd 已关联，或 neigh REACHABLE/DELAY/PROBE（有线设备靠这个）
//   sleep   当前不在线，但 30 分钟内有过活动（在线、DHCP 续租、自己发出过包、新建连接）
//   offline 超过 30 分钟没有活动
// 有连接本身不再算在线（连接数照样统计）。
//
// 清理：某 IP 未关联且 neigh 无效（FAILED/INCOMPLETE/不在表里）连续 ≥2 分钟 → 经 clash API
// DELETE /connections/{id} 关掉这个 IP 的残留连接（每 IP 5 分钟最多一次、每次 ≤200 条），
// events.log 记一行。设备唤醒后会自己重连。只读 neigh/hostapd/租约，不主动扫描。

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var arpPath = "/proc/net/arp"

const sleepWindow = 30 * 60 // 秒

// ---------------- neigh ----------------

type neighEnt struct {
	mac, state string // state：REACHABLE STALE DELAY PROBE FAILED INCOMPLETE PERMANENT NOARP
}

// neighSource：`ip -4 neigh show dev <iface>` 的输出（测试里替换）。
var neighSource = func(iface string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "ip", "-4", "neigh", "show", "dev", iface).Output()
	return string(b), err
}

var neighC struct {
	sync.Mutex
	at    time.Time
	iface string
	m     map[string]neighEnt
}

// readNeigh：IP → MAC + 状态，缓存 2 秒。ip 命令失败时退回 /proc/net/arp
// （flags 0x2 当 STALE——不能区分 REACHABLE，宁可显示休眠也不误判在线）。
func readNeigh(iface string) map[string]neighEnt {
	neighC.Lock()
	defer neighC.Unlock()
	if neighC.m != nil && neighC.iface == iface && time.Since(neighC.at) < 2*time.Second {
		return neighC.m
	}
	m := map[string]neighEnt{}
	if out, err := neighSource(iface); err == nil {
		for _, l := range strings.Split(out, "\n") {
			fl := strings.Fields(l)
			if len(fl) < 2 || strings.Count(fl[0], ".") != 3 {
				continue
			}
			e := neighEnt{state: strings.ToUpper(fl[len(fl)-1])}
			for i := 1; i+1 < len(fl); i++ {
				if fl[i] == "lladdr" {
					e.mac = strings.ToLower(fl[i+1])
				}
			}
			m[fl[0]] = e
		}
	} else {
		for ip, a := range readARPAll(iface) {
			st := "FAILED"
			if a.valid {
				st = "STALE"
			}
			m[ip] = neighEnt{a.mac, st}
		}
	}
	neighC.m, neighC.at, neighC.iface = m, time.Now(), iface
	return m
}

// 正在通信
func neighActive(st string) bool {
	return st == "REACHABLE" || st == "DELAY" || st == "PROBE" || st == "PERMANENT" || st == "NOARP"
}

// 还有有效的二层地址（含 STALE）；FAILED/INCOMPLETE/没有条目 = 无效
func neighValid(st string) bool { return neighActive(st) || st == "STALE" }

type arpEnt struct {
	mac   string
	valid bool // flags 0x2（含 STALE）
}

// readARPAll：iface 上的全部 ARP 条目（含 FAILED/INCOMPLETE 的 0x0 条目）。
func readARPAll(iface string) map[string]arpEnt {
	out := map[string]arpEnt{}
	b, err := os.ReadFile(arpPath)
	if err != nil {
		return out
	}
	for i, l := range strings.Split(string(b), "\n") {
		fl := strings.Fields(l)
		if i == 0 || len(fl) < 6 || fl[5] != iface {
			continue
		}
		mac := strings.ToLower(fl[3])
		valid := fl[2] != "0x0" && mac != "00:00:00:00:00:00"
		if mac == "00:00:00:00:00:00" {
			mac = ""
		}
		out[fl[0]] = arpEnt{mac, valid}
	}
	return out
}

// ---------------- 最近活动 ----------------

// 内存里记每台设备（MAC，没有就 IP）最近一次活动时间（unix 秒）和最近的 Wi‑Fi 频段。
var devSeen = struct {
	sync.Mutex
	t    map[string]int64
	band map[string]string
}{t: map[string]int64{}, band: map[string]string{}}

func noteSeen(key string, t int64) {
	if key == "" || t <= 0 {
		return
	}
	key = strings.ToLower(key)
	devSeen.Lock()
	if t > devSeen.t[key] && (len(devSeen.t) < 1024 || devSeen.t[key] != 0) {
		devSeen.t[key] = t
	}
	devSeen.Unlock()
}

func lastSeen(keys ...string) int64 {
	devSeen.Lock()
	defer devSeen.Unlock()
	var t int64
	for _, k := range keys {
		if k != "" && devSeen.t[strings.ToLower(k)] > t {
			t = devSeen.t[strings.ToLower(k)]
		}
	}
	return t
}

// markWifiSeen：wifiClients 每次刷新时调用——在 hostapd 里 = 此刻在线。
func markWifiSeen(m map[string]wifiClient) {
	now := time.Now().Unix()
	devSeen.Lock()
	for mac, w := range m {
		if len(devSeen.t) < 1024 || devSeen.t[mac] != 0 {
			devSeen.t[mac] = now
			devSeen.band[mac] = w.Band
		}
	}
	devSeen.Unlock()
}

func lastBand(mac string) string {
	devSeen.Lock()
	defer devSeen.Unlock()
	return devSeen.band[mac]
}

// DHCP 续租时间 = 租约到期 − 租期（设备醒着才会续租；守护进程重启后也有）。
var leaseTimeSec = func() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "uci", "-q", "get", "dhcp.lan.leasetime").Output()
	if err != nil {
		return 0
	}
	return parseLeaseTime(strings.TrimSpace(string(b)))
}

var leaseTT struct {
	sync.Once
	v int64
}

func parseLeaseTime(s string) int64 {
	if s == "" {
		return 0
	}
	mul := int64(1)
	switch s[len(s)-1] {
	case 'h':
		mul, s = 3600, s[:len(s)-1]
	case 'm':
		mul, s = 60, s[:len(s)-1]
	case 'd':
		mul, s = 86400, s[:len(s)-1]
	case 's':
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n * mul
}

// leaseRenew：IP → 最近续租时间（unix 秒）。

func leaseRenew(path string, now int64) map[string]int64 {
	leaseTT.Do(func() { leaseTT.v = leaseTimeSec() })
	out := map[string]int64{}
	if leaseTT.v <= 0 {
		return out
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		fl := strings.Fields(l)
		if len(fl) < 3 {
			continue
		}
		exp, err := strconv.ParseInt(fl[0], 10, 64)
		if err != nil || exp == 0 {
			continue
		}
		t := exp - leaseTT.v
		if t > now || t < now-86400 {
			continue
		}
		out[fl[2]] = t
	}
	return out
}

// devState：在线 / 休眠 / 离线。
func devState(online bool, last, now int64) string {
	if online {
		return "online"
	}
	if last > 0 && now-last <= sleepWindow {
		return "sleep"
	}
	return "offline"
}

func connStartUnix(s string) int64 {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Unix()
	}
	return 0
}

// ---------------- 残留连接清理 ----------------

const (
	staleAfter    = 2 * time.Minute
	staleCooldown = 5 * time.Minute
	staleMaxKill  = 200
)

type staleTracker struct {
	absent  map[string]time.Time
	cleaned map[string]time.Time
}

func newStaleTracker() *staleTracker {
	return &staleTracker{absent: map[string]time.Time{}, cleaned: map[string]time.Time{}}
}

// step：conns = IP → 连接 id；返回这轮要关的（IP → id）。
func (s *staleTracker) step(now time.Time, conns map[string][]string, gone func(ip string) bool) map[string][]string {
	kill := map[string][]string{}
	for ip := range s.absent {
		if _, ok := conns[ip]; !ok {
			delete(s.absent, ip)
		}
	}
	for ip, t := range s.cleaned {
		if now.Sub(t) > staleCooldown {
			delete(s.cleaned, ip)
		}
	}
	for ip, ids := range conns {
		if !gone(ip) {
			delete(s.absent, ip)
			continue
		}
		t0, ok := s.absent[ip]
		if !ok {
			s.absent[ip] = now
			continue
		}
		if now.Sub(t0) < staleAfter {
			continue
		}
		if t, ok := s.cleaned[ip]; ok && now.Sub(t) < staleCooldown {
			continue
		}
		ids = append([]string(nil), ids...)
		sort.Strings(ids)
		if len(ids) > staleMaxKill {
			ids = ids[:staleMaxKill]
		}
		kill[ip] = ids
		s.cleaned[ip] = now
	}
	return kill
}

func (d *Daemon) staleConnLoop() {
	st := newStaleTracker()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		if !d.coreUp.Load() {
			continue
		}
		d.staleConnRound(st, time.Now())
	}
}

// staleConnRound 返回关掉的连接数。
func (d *Daemon) staleConnRound(st *staleTracker, now time.Time) int {
	c := d.conf()
	var r struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				SourceIP string
			} `json:"metadata"`
			Chains []string
			Start  string
		} `json:"connections"`
	}
	if err := d.clash().doCtx(d.ctx, 5*time.Second, "GET", "/connections", nil, &r); err != nil {
		return 0
	}
	lan := lanPrefixes(c)
	self := lanSelfIP(c)
	leases := readLeases(d.leases)
	neigh := readNeigh(c.LAN.Iface)
	macOf := func(ip string) string {
		if l, ok := leases[ip]; ok && l[0] != "" {
			return l[0]
		}
		return neigh[ip].mac
	}
	conns := map[string][]string{}
	for _, x := range r.Connections {
		ip := x.Metadata.SourceIP
		if ip == "" || ip == self || !inLAN(lan, ip) {
			continue
		}
		if len(x.Chains) > 0 && (x.Chains[0] == probeTag || x.Chains[len(x.Chains)-1] == probeTag) {
			continue
		}
		conns[ip] = append(conns[ip], x.ID)
		if t := connStartUnix(x.Start); t > 0 && t <= now.Unix()+5 {
			k := macOf(ip)
			if k == "" {
				k = ip
			}
			noteSeen(k, t) // 新建连接 = 它醒过
		}
	}
	if len(conns) == 0 {
		st.step(now, conns, func(string) bool { return false })
		return 0
	}
	wifi := d.wifiClients()
	gone := func(ip string) bool {
		mac := macOf(ip)
		if _, inW := wifi[mac]; mac != "" && inW {
			return false
		}
		return !neighValid(neigh[ip].state)
	}
	kill := st.step(now, conns, gone)
	total := 0
	for ip, ids := range kill {
		n := 0
		for _, id := range ids {
			if d.clash().doCtx(d.ctx, 2*time.Second, "DELETE", "/connections/"+id, nil, nil) == nil {
				n++
			}
		}
		total += n
		label := ip
		if mac := macOf(ip); mac != "" {
			if nm := c.DeviceNames[mac]; nm != "" {
				label = nm + "（" + ip + "）"
			}
		}
		if d.events != nil {
			d.events.add("device", fmt.Sprintf("设备 %s 不在 Wi‑Fi 且 ARP 失效已 2 分钟以上：关闭它的 %d 条残留连接（唤醒后会自动重连）", label, n))
		}
	}
	return total
}

func lanPrefixes(c *Config) []netip.Prefix {
	var lan []netip.Prefix
	for _, s := range c.LAN.CIDR {
		if pf, err := parsePrefix(s); err == nil {
			lan = append(lan, pf)
		}
	}
	return lan
}
