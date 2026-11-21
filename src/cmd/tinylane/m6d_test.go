package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

// 内核直连（NAT 到 WAN 192.168.16.5）、经 tproxy（无 NAT）、DNS、非 cn、非 LAN、TIME_WAIT、UDP、无 acct 字段
const fakeCT = `ipv4     2 tcp      6 7431 ESTABLISHED src=192.168.1.221 dst=110.242.68.66 sport=52345 dport=443 packets=10 bytes=1234 src=110.242.68.66 dst=192.168.16.5 sport=443 dport=52345 packets=9 bytes=56789 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 7431 ESTABLISHED src=192.168.1.221 dst=110.242.68.66 sport=52346 dport=443 packets=10 bytes=100 src=110.242.68.66 dst=192.168.1.221 sport=443 dport=52346 packets=9 bytes=200 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 29 src=192.168.1.221 dst=223.5.5.5 sport=5353 dport=53 packets=1 bytes=60 src=223.5.5.5 dst=192.168.1.221 sport=53 dport=5353 packets=1 bytes=90 mark=0 zone=0 use=2
ipv4     2 tcp      6 7431 ESTABLISHED src=192.168.1.138 dst=142.250.1.1 sport=50000 dport=443 packets=10 bytes=100 src=142.250.1.1 dst=192.168.16.5 sport=443 dport=50000 packets=9 bytes=200 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 7431 ESTABLISHED src=192.168.16.5 dst=110.242.68.66 sport=40000 dport=443 packets=10 bytes=100 src=110.242.68.66 dst=192.168.16.5 sport=443 dport=40000 packets=9 bytes=200 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 110 TIME_WAIT src=192.168.1.138 dst=39.156.66.10 sport=51000 dport=80 packets=6 bytes=500 src=39.156.66.10 dst=192.168.16.5 sport=80 dport=51000 packets=5 bytes=3000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 170 src=192.168.1.221 dst=110.242.68.66 sport=60000 dport=443 packets=30 bytes=4000 src=110.242.68.66 dst=192.168.16.5 sport=443 dport=60000 packets=40 bytes=90000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 118 SYN_SENT src=192.168.1.136 dst=110.242.68.67 sport=52000 dport=443 [UNREPLIED] src=110.242.68.67 dst=192.168.16.5 sport=443 dport=52000 mark=0 zone=0 use=2
ipv6     10 tcp      6 7431 ESTABLISHED src=fe80::1 dst=fe80::2 sport=1 dport=2 src=fe80::2 dst=fe80::1 sport=2 dport=1 [ASSURED] mark=0 zone=0 use=2
`

var testCN = []string{"110.242.0.0/16", "39.156.0.0/16", "223.5.5.0/24"}

func newTestKern(t *testing.T) (*KernConns, *Daemon) {
	dir := t.TempDir()
	d := &Daemon{runDir: dir, workDir: dir}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.events = newEventLog(filepath.Join(dir, "events.log"))
	k := newKernConns(d)
	k.setRanges(testCN, []string{"192.168.1.0/24"})
	return k, d
}

func TestParseCT(t *testing.T) {
	e, ok := parseCT([]byte(strings.Split(fakeCT, "\n")[0]))
	if !ok || e.k.proto != 6 || u32ip(e.k.src) != "192.168.1.221" || u32ip(e.k.dst) != "110.242.68.66" || e.k.sport != 52345 || e.k.dport != 443 ||
		e.up != 1234 || e.down != 56789 || u32ip(e.replyDst) != "192.168.16.5" || e.closed {
		t.Fatalf("bad parse %+v ok=%v", e, ok)
	}
	e, ok = parseCT([]byte(strings.Split(fakeCT, "\n")[5]))
	if !ok || !e.closed {
		t.Fatalf("TIME_WAIT 应为 closed: %+v", e)
	}
	e, ok = parseCT([]byte(strings.Split(fakeCT, "\n")[7]))
	if !ok || e.up != 0 || u32ip(e.replyDst) != "192.168.16.5" {
		t.Fatalf("UNREPLIED: %+v %v", e, ok)
	}
	if _, ok := parseCT([]byte(strings.Split(fakeCT, "\n")[8])); ok {
		t.Fatal("ipv6 应跳过")
	}
	for _, bad := range []string{"", "ipv4 2 icmp 1 29 src=1.2.3.4 dst=5.6.7.8", "ipv4 2 tcp 6 1 ESTABLISHED src=999.1.1.1 dst=1.1.1.1 src=1.1.1.1 dst=2.2.2.2"} {
		if _, ok := parseCT([]byte(bad)); ok {
			t.Fatalf("应拒绝 %q", bad)
		}
	}
}

func TestKernScanAggregate(t *testing.T) {
	k, d := newTestKern(t)
	defer d.cancel()
	ips := k.scan(strings.NewReader(fakeCT), 1000)
	// 记录：.221 tcp 443（NAT）、.138 TIME_WAIT（立即标结束）、.221 udp 443、.136 SYN_SENT；不记：tproxy、DNS、非 cn、非 LAN、v6
	if len(k.active) != 4 {
		for kk := range k.active {
			t.Logf("%s:%d -> %s:%d", u32ip(kk.src), kk.sport, u32ip(kk.dst), kk.dport)
		}
		t.Fatalf("active=%d 想要 4", len(k.active))
	}
	if len(ips) != 3 {
		t.Fatalf("新目标 IP %d 想要 3", len(ips))
	}
	cv, dc := k.liveViews()
	if len(cv) != 3 || len(dc) != 3 { // TIME_WAIT 那条已结束，不算活动
		t.Fatalf("live %d/%d", len(cv), len(dc))
	}
	per := map[string]int{}
	for _, x := range dc {
		per[x.src]++
		if x.out != "direct" {
			t.Fatal("内核直连必须算直连")
		}
	}
	if per["192.168.1.221"] != 2 || per["192.168.1.136"] != 1 {
		t.Fatalf("按设备聚合错: %v", per)
	}
	for _, c := range cv {
		if !c.Kern || c.Rule != kernRule || c.Host == "" {
			t.Fatalf("view %+v", c)
		}
	}
	// 第二轮：udp 那条消失 → 进入已结束；tcp 字节更新
	nxt := strings.Replace(fakeCT, "bytes=56789", "bytes=99999", 1)
	lines := strings.Split(nxt, "\n")
	nxt = strings.Join(append(lines[:6:6], lines[7:]...), "\n")
	k.scan(strings.NewReader(nxt), 1005)
	if len(k.active) != 3 || len(k.ended) != 1 || k.ended[0].k.proto != 17 || k.ended[0].end != 1000 {
		t.Fatalf("active=%d ended=%d %+v", len(k.active), len(k.ended), k.ended)
	}
	recs := k.records("192.168.1.221", "", 0)
	if len(recs) != 2 {
		t.Fatalf("records %d", len(recs))
	}
	var down int64
	for _, r := range recs {
		if r.N == "tcp" {
			down = r.D
		}
	}
	if down != 99999 {
		t.Fatalf("字节没更新 %d", down)
	}
	if n := len(k.records("", "baidu", 0)); n != 0 {
		t.Fatalf("q 过滤 %d", n)
	}
}

func TestKernCaps(t *testing.T) {
	k, d := newTestKern(t)
	defer d.cancel()
	var b strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&b, "ipv4 2 tcp 6 7431 ESTABLISHED src=192.168.1.%d dst=110.242.%d.%d sport=%d dport=443 packets=1 bytes=10 src=110.242.%d.%d dst=192.168.16.5 sport=443 dport=%d packets=1 bytes=20 [ASSURED] mark=0 zone=0 use=2\n",
			2+i%200, i/250, i%250, 10000+i, i/250, i%250, 10000+i)
	}
	k.scan(strings.NewReader(b.String()), 1)
	if len(k.active) != kernMaxActive || k.drop != 2000 {
		t.Fatalf("active=%d drop=%d", len(k.active), k.drop)
	}
	for r := 0; r < 3; r++ { // 全部结束 → 环形缓冲最多 1000
		k.scan(strings.NewReader(""), int64(10+r))
		k.scan(strings.NewReader(b.String()), int64(20+r))
	}
	if len(k.ended) != kernMaxEnded || len(k.active) > kernMaxActive {
		t.Fatalf("ended=%d active=%d", len(k.ended), len(k.active))
	}
}

func TestRdnsTableCap(t *testing.T) {
	now := int64(1000)
	tb := newRdnsTable(rdnsMax)
	tb.now = func() int64 { return now }
	for i := 0; i < 10000; i++ {
		tb.add(uint32(i), fmt.Sprintf("h%d.example", i), 300)
	}
	if tb.len() != rdnsMax || len(tb.ring) != rdnsMax {
		t.Fatalf("len=%d ring=%d", tb.len(), len(tb.ring))
	}
	if _, ok := tb.get(0); ok {
		t.Fatal("最早的应被淘汰")
	}
	if n, ok := tb.get(9999); !ok || n != "h9999.example" {
		t.Fatal("最新的应在")
	}
	now += 300 + rdnsGrace + 1
	if _, ok := tb.get(9999); ok {
		t.Fatal("TTL+宽限后应过期")
	}
	// 重复加同一个 IP 不增长
	tb2 := newRdnsTable(8)
	for i := 0; i < 100; i++ {
		tb2.add(7, "a", 10)
	}
	if tb2.len() != 1 || len(tb2.ring) != 1 {
		t.Fatal("重复 IP 不应占多条")
	}
	// DNS 应答：CNAME 链按问题名记
	m := new(mDNS.Msg)
	m.SetQuestion("www.baidu.com.", mDNS.TypeA)
	cn, _ := mDNS.NewRR("www.baidu.com. 300 IN CNAME www.a.shifen.com.")
	a, _ := mDNS.NewRR("www.a.shifen.com. 120 IN A 110.242.68.66")
	m.Answer = []mDNS.RR{cn, a}
	tb3 := newRdnsTable(16)
	tb3.onDNS(m)
	ip, _ := ip4([]byte("110.242.68.66"))
	if n, ok := tb3.get(ip); !ok || n != "www.baidu.com" {
		t.Fatalf("got %q %v", n, ok)
	}
}

func TestRdnsSocket(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)
	tb := startRdns()
	m := new(mDNS.Msg)
	m.SetQuestion("www.baidu.com.", mDNS.TypeA)
	a, _ := mDNS.NewRR("www.baidu.com. 120 IN A 110.242.68.66")
	m.Answer = []mDNS.RR{a}
	tb.onDNS(m)
	ip, _ := ip4([]byte("110.242.68.66"))
	ip2, _ := ip4([]byte("1.2.3.4"))
	got := rdnsQuery(filepath.Join(dir, rdnsSock), []uint32{ip, ip2})
	if got[ip] != "www.baidu.com" || len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

// 压测：10000 条 conntrack（一半命中），每轮耗时与内存
func TestKernStress10000(t *testing.T) {
	k, d := newTestKern(t)
	defer d.cancel()
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		dst := "142.250"
		if i%2 == 0 {
			dst = "110.242"
		}
		fmt.Fprintf(&b, "ipv4     2 tcp      6 7431 ESTABLISHED src=192.168.1.%d dst=%s.%d.%d sport=%d dport=443 packets=10 bytes=%d src=%s.%d.%d dst=192.168.16.5 sport=443 dport=%d packets=9 bytes=%d [ASSURED] mark=0 zone=0 use=2\n",
			2+i%200, dst, i/250%250, i%250, 10000+i, i*7, dst, i/250%250, i%250, 10000+i, i*13)
	}
	data := b.String()
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	t0 := time.Now()
	const rounds = 20
	for r := 0; r < rounds; r++ {
		k.scan(strings.NewReader(data), int64(r))
		k.liveViews()
	}
	el := time.Since(t0) / rounds
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("10000 行 %.1f KB：每轮 %v（含 liveViews），活动 %d、丢弃计数 %d；保留堆增量 %.2f MB；每轮分配 %.2f MB",
		float64(len(data))/1024, el, len(k.active), k.drop, float64(int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1e6, float64(m1.TotalAlloc-m0.TotalAlloc)/rounds/1e6)
	os.WriteFile(filepath.Join(os.Getenv("M6D_OUT"), "m6d-stress.txt"), []byte(fmt.Sprintf("rows=10000 bytes=%d per_round=%v active=%d heap_retained_MB=%.2f alloc_per_round_MB=%.2f\n",
		len(data), el, len(k.active), float64(int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1e6, float64(m1.TotalAlloc-m0.TotalAlloc)/rounds/1e6)), 0o644)
}

func TestKernResolveNames(t *testing.T) {
	k, d := newTestKern(t)
	defer d.cancel()
	old, _ := os.Getwd()
	os.Chdir(d.workDir)
	tb := startRdns()
	os.Chdir(old)
	m := new(mDNS.Msg)
	m.SetQuestion("www.baidu.com.", mDNS.TypeA)
	a, _ := mDNS.NewRR("www.baidu.com. 120 IN A 110.242.68.66")
	m.Answer = []mDNS.RR{a}
	tb.onDNS(m)
	ips := k.scan(strings.NewReader(fakeCT), 1)
	k.resolve(ips)
	cv, _ := k.liveViews()
	hosts := map[string]bool{}
	for _, c := range cv {
		hosts[c.Host] = true
	}
	if !hosts["www.baidu.com"] || !hosts["110.242.68.67"] {
		t.Fatalf("%v", hosts)
	}
}
