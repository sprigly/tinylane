package main

// M4：Wi‑Fi 客户端（信号 / 频段 / 踢下线，经 ubus hostapd.*）+ 24 小时连接历史（/tmp 环形文件）。

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------- Wi‑Fi ----------------

type wifiClient struct {
	Iface  string `json:"iface"`
	Band   string `json:"band"`
	Signal int    `json:"signal"`
	RxRate int64  `json:"rx_rate"` // bit/s（hostapd rate.rx）
	TxRate int64  `json:"tx_rate"`
}

type wifiCache struct {
	mu  sync.Mutex
	at  time.Time
	m   map[string]wifiClient
	ifs []string
	ok  bool // M6c：本轮所有 hostapd 接口都查到了（查询失败时不拿「不在 hostapd」当离线依据）
}

var wifiC wifiCache

func (d *Daemon) ubusOut(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(d.ctx, timeout)
	defer cancel()
	return exec.CommandContext(ctx, d.ubusPath, args...).Output()
}

func (d *Daemon) hostapdIfaces() []string {
	out, err := d.ubusOut(3*time.Second, "list", "hostapd.*")
	if err != nil {
		return nil
	}
	var l []string
	for _, s := range strings.Fields(string(out)) {
		if strings.HasPrefix(s, "hostapd.") && !strings.ContainsAny(s, "'\"`$;&|") {
			l = append(l, s)
		}
	}
	return l
}

// wifiClients：MAC(小写) → 信号等，缓存 5 秒（面板 3 秒轮询 /conns）。
func (d *Daemon) wifiClients() map[string]wifiClient {
	wifiC.mu.Lock()
	defer wifiC.mu.Unlock()
	if time.Since(wifiC.at) < 5*time.Second && wifiC.m != nil {
		return wifiC.m
	}
	m := map[string]wifiClient{}
	ifs := d.hostapdIfaces()
	ok := len(ifs) > 0
	for _, ifc := range ifs {
		out, err := d.ubusOut(3*time.Second, "call", ifc, "get_clients")
		if err != nil {
			ok = false
			continue
		}
		var r struct {
			Freq    int `json:"freq"`
			Clients map[string]struct {
				Signal int `json:"signal"`
				Rate   struct {
					Rx int64 `json:"rx"`
					Tx int64 `json:"tx"`
				} `json:"rate"`
			} `json:"clients"`
		}
		if json.Unmarshal(out, &r) != nil {
			ok = false
			continue
		}
		band := "2.4 GHz"
		if r.Freq >= 5900 {
			band = "6 GHz"
		} else if r.Freq >= 4900 {
			band = "5 GHz"
		}
		for mac, c := range r.Clients {
			m[strings.ToLower(mac)] = wifiClient{Iface: strings.TrimPrefix(ifc, "hostapd."), Band: band, Signal: c.Signal, RxRate: c.Rate.Rx, TxRate: c.Rate.Tx}
		}
	}
	wifiC.m, wifiC.at, wifiC.ifs, wifiC.ok = m, time.Now(), ifs, ok
	markWifiSeen(m)
	return m
}

// kick：从所在 AP 断开，ban 秒内拒绝它重连（hostapd 内存里，Wi‑Fi 重启即失效）。
func (d *Daemon) kick(mac string, banSec int) error {
	wifiC.mu.Lock()
	wifiC.at = time.Time{} // 强制刷新
	wifiC.mu.Unlock()
	cl, ok := d.wifiClients()[mac]
	if !ok {
		return fmt.Errorf("这台设备不在 Wi‑Fi 上（有线设备不能踢，可以用「拉黑」）")
	}
	if banSec < 0 || banSec > 86400 {
		return fmt.Errorf("禁止重连时长无效")
	}
	arg, _ := json.Marshal(map[string]any{"addr": mac, "reason": 5, "deauth": true, "ban_time": banSec * 1000})
	if _, err := d.ubusOut(5*time.Second, "call", "hostapd."+cl.Iface, "del_client", string(arg)); err != nil {
		return fmt.Errorf("hostapd 拒绝：%v", err)
	}
	return nil
}

// ---------------- 24 小时连接历史 ----------------
// 守护进程每 3 秒读一次内核 /connections，新出现的连接追加一行 JSON 到 /tmp/tinylane/history.log；
// 文件超过 1 MB 就改名为 history.log.1（覆盖旧的），所以总共最多约 2 MB。tmpfs：路由器重启后丢失。
// 只记录连接建立（不含之后的流量），3 秒内开关完的短连接可能漏记。

type histRec struct {
	T int64  `json:"t"`
	S string `json:"s"`
	H string `json:"h"`
	P string `json:"p"`
	N string `json:"n"`
	O string `json:"o"`
	G string `json:"g"`
	R string `json:"r"`
	U int64  `json:"u,omitempty"` // M6d 内核直连：上行 / 下行字节、结束时间
	D int64  `json:"d,omitempty"`
	K bool   `json:"k,omitempty"`
	E int64  `json:"e,omitempty"`
}

const histMax = 1 << 20

type History struct {
	mu   sync.Mutex
	path string
	seen map[string]bool
}

func (d *Daemon) historyLoop(h *History) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
		}
		if !d.coreUp.Load() {
			continue
		}
		var r struct {
			Connections []struct {
				ID       string `json:"id"`
				Metadata struct {
					Network, SourceIP, Host, DestinationIP, DestinationPort string
				} `json:"metadata"`
				Rule   string
				Chains []string
				Start  string
			} `json:"connections"`
		}
		if err := d.clash().doCtx(d.ctx, 4*time.Second, "GET", "/connections", nil, &r); err != nil {
			continue
		}
		now := map[string]bool{}
		var add []histRec
		for _, c := range r.Connections {
			now[c.ID] = true
			if h.seen != nil && h.seen[c.ID] {
				continue
			}
			out, grp := "", ""
			if len(c.Chains) > 0 {
				out, grp = c.Chains[0], c.Chains[len(c.Chains)-1]
			}
			if out == probeTag || grp == probeTag {
				continue
			}
			m := c.Metadata
			host := m.Host
			if host == "" {
				host = m.DestinationIP
			}
			ts := time.Now().Unix()
			if st, err := time.Parse(time.RFC3339Nano, c.Start); err == nil {
				ts = st.Unix()
			}
			add = append(add, histRec{ts, m.SourceIP, host, m.DestinationPort, m.Network, out, grp, shortRule(c.Rule), 0, 0, false, 0})
		}
		first := h.seen == nil
		h.seen = now
		if first || len(add) == 0 { // 第一次只建立基线，避免守护进程重启时重复记录
			continue
		}
		h.append(add)
	}
}

func (h *History) append(recs []histRec) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if st, err := os.Stat(h.path); err == nil && st.Size() > histMax {
		os.Rename(h.path, h.path+".1")
	}
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, r := range recs {
		b, _ := json.Marshal(r)
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
}

// query：最近 hours 小时内、匹配 ip / q 的记录，新的在前，最多 limit 条。
func (h *History) query(ip, q string, hours, limit int, kern *KernConns) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	q = strings.ToLower(q)
	var all []histRec
	total, oldest := 0, int64(0)
	var size int64
	for _, p := range []string{h.path + ".1", h.path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil {
			size += st.Size()
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4096), 64<<10)
		for sc.Scan() {
			var r histRec
			if json.Unmarshal(sc.Bytes(), &r) != nil || r.T < since {
				continue
			}
			if oldest == 0 || r.T < oldest {
				oldest = r.T
			}
			if ip != "" && r.S != ip {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(r.H+" "+r.O+" "+r.G+" "+r.R), q) {
				continue
			}
			total++
			all = append(all, r)
			if len(all) > limit*4 { // 控制内存：只保留较新的一段
				all = all[len(all)-limit:]
			}
		}
		f.Close()
	}
	if kr := kern.records(ip, q, since); len(kr) > 0 { // M6d：内存里的内核直连记录（活动 + 最近结束）
		total += len(kr)
		for _, r := range kr {
			if oldest == 0 || r.T < oldest {
				oldest = r.T
			}
		}
		all = append(all, kr...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].T > all[j].T })
	if len(all) > limit {
		all = all[:limit]
	}
	if all == nil {
		all = []histRec{}
	}
	return map[string]any{"list": all, "total": total, "oldest": oldest, "bytes": size, "cap_bytes": 2 * histMax}
}

func newHistory(dir string) *History { return &History{path: filepath.Join(dir, "history.log")} }
