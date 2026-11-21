package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// 假环境：Mac .138（a6:30:19:7a:51:5c）已离开 Wi‑Fi（ARP 0x0、不在 hostapd、28 条残留连接）；
// iPhone .136 在 hostapd；有线 NAS .150 ARP REACHABLE（0x2）不在 hostapd；
// 旧笔记本 .160 曾是 Wi‑Fi，ARP 还 STALE（0x2）但已不在 hostapd。
const fakeARP = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.138    0x1         0x0         a6:30:19:7a:51:5c     *        br-lan
192.168.1.136    0x1         0x2         3e:11:22:33:44:55     *        br-lan
192.168.1.150    0x1         0x2         00:11:32:aa:bb:cc     *        br-lan
192.168.1.160    0x1         0x2         66:77:88:99:aa:bb     *        br-lan
192.168.1.170    0x1         0x0         00:00:00:00:00:00     *        br-lan
192.168.16.1     0x1         0x2         00:00:5e:00:01:01     *        wan
`

const fakeNeigh = `192.168.1.136  FAILED
192.168.1.138  FAILED
192.168.1.221 lladdr f6:3f:7e:58:e7:a1 REACHABLE
192.168.1.150 lladdr 00:11:32:aa:bb:cc REACHABLE
192.168.1.160 lladdr 66:77:88:99:aa:bb STALE
192.168.1.170  INCOMPLETE
`

type fakeKernel struct {
	mu      sync.Mutex
	conns   map[string]string // id → src
	deleted []string
}

func (k *fakeKernel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case r.Method == "GET" && r.URL.Path == "/connections":
		var list []map[string]any
		for id, src := range k.conns {
			list = append(list, map[string]any{"id": id, "metadata": map[string]any{"sourceIP": src, "host": "example.com", "destinationPort": "443", "network": "tcp"}, "chains": []string{"direct"}, "rule": "final", "start": time.Now().Format(time.RFC3339Nano)})
		}
		json.NewEncoder(w).Encode(map[string]any{"connections": list})
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/connections/"):
		id := strings.TrimPrefix(r.URL.Path, "/connections/")
		delete(k.conns, id)
		k.deleted = append(k.deleted, id)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func setupM6c(t *testing.T) (*Daemon, *fakeKernel) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "arp"), []byte(fakeARP), 0o600)
	now := time.Now().Unix()
	lt := int64(12 * 3600)
	leases := fmt.Sprintf("%d a6:30:19:7a:51:5c 192.168.1.138 Mac *\n%d 02:93:a1:ba:20:e8 192.168.1.136 * *\n%d f6:3f:7e:58:e7:a1 192.168.1.221 iPhone *\n",
		now-15*60+lt, now-3*3600+lt, now-60*60+lt) // Mac 15 分钟前续租；旧私有地址 3 小时前
	os.WriteFile(filepath.Join(dir, "leases"), []byte(leases), 0o600)
	leaseTT.Do(func() {})
	leaseTT.v = lt
	neighSource = func(string) (string, error) { return fakeNeigh, nil }
	neighC.Lock()
	neighC.m = nil
	neighC.Unlock()
	devSeen.Lock()
	devSeen.t, devSeen.band = map[string]int64{}, map[string]string{}
	devSeen.Unlock()
	arpPath = filepath.Join(dir, "arp")
	t.Cleanup(func() { arpPath = "/proc/net/arp" })

	k := &fakeKernel{conns: map[string]string{}}
	for i := 0; i < 28; i++ {
		k.conns["mac-"+string(rune('a'+i%26))+string(rune('0'+i/26))] = "192.168.1.138"
	}
	for i := 0; i < 5; i++ {
		k.conns["iph-"+string(rune('a'+i))] = "192.168.1.221"
	}
	k.conns["nas-a"] = "192.168.1.150"
	k.conns["old-a"] = "192.168.1.160"
	srv := httptest.NewServer(k)
	t.Cleanup(srv.Close)

	c := &Config{}
	c.LAN.Iface = "br-lan"
	c.LAN.CIDR = []string{"192.168.1.0/24"}
	c.ClashAPI.Listen = strings.TrimPrefix(srv.URL, "http://")
	c.DeviceNames = map[string]string{"a6:30:19:7a:51:5c": "Mac"}
	c.DeviceInfo = map[string]DevInfo{"66:77:88:99:aa:bb": {Conn: "Wi‑Fi · 5 GHz"}}
	d := &Daemon{leases: filepath.Join(dir, "leases"), events: newEventLog(filepath.Join(dir, "events.log"))}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	t.Cleanup(d.cancel)
	d.setConfig(c)
	// 假 hostapd：只有 iPhone，查询完整
	wifiC.mu.Lock()
	wifiC.m = map[string]wifiClient{"f6:3f:7e:58:e7:a1": {Iface: "phy1-ap0", Band: "5 GHz", Signal: -50}}
	wifiC.at, wifiC.ok = time.Now().Add(time.Hour), true // 不让测试里去调 ubus
	wifiC.mu.Unlock()
	devSeen.Lock()
	devSeen.band["a6:30:19:7a:51:5c"] = "5 GHz" // Mac 上次唤醒时连的 5G
	devSeen.Unlock()
	return d, k
}

func TestDevicesThreeStates(t *testing.T) {
	d, k := setupM6c(t)
	p := &Panel{d: d}
	var dc []devConn
	for _, src := range k.conns {
		dc = append(dc, devConn{src, "direct", "final", ""})
	}
	got := map[string]devView{}
	for _, v := range p.devices(dc, nil) {
		got[v.IP] = v
	}
	if v := got["192.168.1.138"]; v.Online || v.State != "sleep" || v.Conns != 28 || v.LastActive == 0 || v.Conn != "Wi‑Fi · 5 GHz" {
		t.Fatalf("休眠的 Mac 应为 sleep、连接仍计 28：%+v", v)
	}
	if v := got["192.168.1.221"]; !v.Online || v.State != "online" || !v.Wifi || v.Conns != 5 {
		t.Fatalf("iPhone 在 hostapd 应在线：%+v", v)
	}
	if v := got["192.168.1.150"]; !v.Online {
		t.Fatalf("有线设备 REACHABLE 应在线：%+v", v)
	}
	if v := got["192.168.1.160"]; v.State != "offline" {
		t.Fatalf("只有 STALE、没有活动记录的应为离线：%+v", v)
	}
	if v := got["192.168.1.136"]; v.State != "offline" {
		t.Fatalf("3 小时前的旧私有地址应离线：%+v", v)
	}
	if v, ok := got["192.168.1.170"]; ok && v.State != "offline" {
		t.Fatal("INCOMPLETE 不应在线")
	}
	// 排序：在线 → 休眠 → 离线
	list := p.devices(dc, nil)
	last := -1
	for _, v := range list {
		if r := stateRank(v.State); r < last {
			t.Fatalf("排序错：%v", list)
		} else {
			last = r
		}
	}
	// 31 分钟没活动 → 离线
	if devState(false, time.Now().Unix()-31*60, time.Now().Unix()) != "offline" || devState(false, time.Now().Unix()-29*60, time.Now().Unix()) != "sleep" {
		t.Fatal("30 分钟窗口")
	}
}

func TestStaleCleanupOnlyGoneIP(t *testing.T) {
	d, k := setupM6c(t)
	st := newStaleTracker()
	t0 := time.Now()
	if n := d.staleConnRound(st, t0); n != 0 {
		t.Fatalf("第一次只开始计时，不应关连接：%d", n)
	}
	if n := d.staleConnRound(st, t0.Add(90*time.Second)); n != 0 {
		t.Fatalf("不到 2 分钟不应关：%d", n)
	}
	if n := d.staleConnRound(st, t0.Add(121*time.Second)); n != 28 {
		t.Fatalf("应关掉 Mac 的 28 条，实际 %d", n)
	}
	k.mu.Lock()
	for _, id := range k.deleted {
		if !strings.HasPrefix(id, "mac-") {
			t.Fatalf("误关了别的设备的连接 %s", id)
		}
	}
	left := []string{}
	for id := range k.conns {
		left = append(left, id)
	}
	k.mu.Unlock()
	sort.Strings(left)
	// iPhone 5 + NAS 1 + .160（STALE 仍有效，不关）1
	if len(left) != 7 {
		t.Fatalf("剩余连接应为 7：%v", left)
	}
	// 限频：Mac 又冒出残留连接，5 分钟冷却内不再关
	k.mu.Lock()
	k.conns["mac-new"] = "192.168.1.138"
	k.mu.Unlock()
	if n := d.staleConnRound(st, t0.Add(150*time.Second)); n != 0 {
		t.Fatalf("冷却期内不应再关：%d", n)
	}
	// events.log 有一行
	found := false
	for _, e := range d.events.list {
		if e.Kind == "device" && strings.Contains(e.Msg, "Mac（192.168.1.138）") && strings.Contains(e.Msg, "28 条") {
			found = true
		}
	}
	if !found {
		t.Fatalf("events 缺清理记录：%+v", d.events.list)
	}
}

func TestStaleTrackerResetsWhenBack(t *testing.T) {
	st := newStaleTracker()
	t0 := time.Now()
	conns := map[string][]string{"192.168.1.138": {"a", "b"}}
	gone := true
	g := func(string) bool { return gone }
	st.step(t0, conns, g)
	gone = false // 设备 100 秒时回来了
	st.step(t0.Add(100*time.Second), conns, g)
	gone = true
	if k := st.step(t0.Add(130*time.Second), conns, g); len(k) != 0 {
		t.Fatal("中途回来过，计时应重置")
	}
	if k := st.step(t0.Add(251*time.Second), conns, g); len(k["192.168.1.138"]) != 2 {
		t.Fatalf("重新离线满 2 分钟应关：%v", k)
	}
}

func TestNeighParse(t *testing.T) {
	neighSource = func(string) (string, error) {
		return fakeNeigh + "192.168.1.9 lladdr aa:bb:cc:dd:ee:ff router DELAY\n", nil
	}
	neighC.Lock()
	neighC.m = nil
	neighC.Unlock()
	m := readNeigh("br-lan")
	if m["192.168.1.138"].state != "FAILED" || m["192.168.1.221"].mac != "f6:3f:7e:58:e7:a1" || !neighActive(m["192.168.1.9"].state) || neighValid(m["192.168.1.170"].state) || !neighValid(m["192.168.1.160"].state) || neighActive(m["192.168.1.160"].state) {
		t.Fatalf("%+v", m)
	}
	if parseLeaseTime("12h") != 43200 || parseLeaseTime("720m") != 43200 || parseLeaseTime("3600") != 3600 || parseLeaseTime("x") != 0 {
		t.Fatal("leasetime")
	}
}
