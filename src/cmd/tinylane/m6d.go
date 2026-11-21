package main

// M6d：记录「国内 IP 内核直连」的连接（规则模式下 nft `ip daddr @cn4 return`，不进 sing-box）。
//
// 守护进程每 5 秒读一次 /proc/net/nf_conntrack（不装 conntrack 工具），只取：
//   源 IP 在 LAN 网段、目标在 cn4、TCP/UDP、且被 WAN 伪装（回包目标 ≠ 原源 IP；经 tproxy 进 sing-box 的连接不做 NAT，自然排除）。
// 字节数需要 net.netfilter.nf_conntrack_acct=1：启用时设置，原值存 /var/run/tinylane/ct_acct.orig，关闭开关 / 守护进程退出时恢复。
// 域名：内核（tinylane run）在 DNS 应答里建反查表（≤4096 条，TTL+宽限过期，按插入顺序淘汰），
//   守护进程只对新出现的连接经 unix socket 批量查一次；查不到显示 IP。
// 内存：活动 ≤1000 条 + 已结束环形缓冲 ≤1000 条（总 ≤2000）；conntrack 条目 >8000 跳过本轮（只记一次事件）。

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	kernMaxActive = 1000
	kernMaxEnded  = 1000
	kernSkipOver  = 8000
	kernInterval  = 5 * time.Second
	kernRule      = "内核直连 · 国内 IP"
)

var (
	ctPath      = "/proc/net/nf_conntrack"
	ctCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"
	ctAcctPath  = "/proc/sys/net/netfilter/nf_conntrack_acct"
)

type kKey struct {
	src, dst     uint32
	sport, dport uint16
	proto        uint8
}

type kFlow struct {
	k        kKey
	host     string
	up, down int64
	start    int64 // 首次看到（≤5 s 误差）
	last     int64 // 字节最后一次变化
	end      int64 // TCP 进入关闭状态 / 从 conntrack 消失
	seen     uint32
}

type u32r struct{ lo, hi uint32 }

type KernConns struct {
	d      *Daemon
	mu     sync.Mutex
	active map[kKey]*kFlow
	ended  []kFlow
	epos   int
	round  uint32
	base   bool // 第一轮（基线）已过
	skip   bool
	drop   int
	rd     *bufio.Reader

	cnSrc []string
	cn    []u32r
	lanS  string
	lan   []u32r

	acctOn bool
	// 统计（给 /api/state 和测试）
	lastDur  time.Duration
	lastRows int
}

func newKernConns(d *Daemon) *KernConns {
	if dir := os.Getenv("TINYLANE_CT_DIR"); dir != "" { // 只给沙盒测试用：假 conntrack 文件目录
		ctPath, ctCountPath, ctAcctPath = filepath.Join(dir, "nf_conntrack"), filepath.Join(dir, "nf_conntrack_count"), filepath.Join(dir, "nf_conntrack_acct")
	}
	return &KernConns{d: d, active: map[kKey]*kFlow{}}
}

func kernLogOn(c *Config) bool { return c.KernelConnLog == nil || *c.KernelConnLog }

func (k *KernConns) loop() {
	t := time.NewTicker(kernInterval)
	defer t.Stop()
	for {
		select {
		case <-k.d.ctx.Done():
			k.restoreAcct()
			return
		case <-t.C:
		}
		k.tick(time.Now())
	}
}

func (k *KernConns) tick(now time.Time) {
	c := k.d.conf()
	if c == nil {
		return
	}
	if !kernLogOn(c) {
		k.restoreAcct()
		k.mu.Lock()
		k.active, k.ended, k.epos, k.base = map[kKey]*kFlow{}, nil, 0, false
		k.mu.Unlock()
		return
	}
	cn := cnBypassCIDRs(c)
	if !c.Enabled || k.d.fallback.Load() || len(cn) == 0 {
		k.endAll(now.Unix()) // 绕过没生效：没有内核直连，已有的记为结束
		return
	}
	k.ensureAcct()
	if n := readIntFile(ctCountPath); n > kernSkipOver {
		if !k.skip {
			k.d.events.add("system", fmt.Sprintf("内核连接表有 %d 条（>%d），暂停记录内核直连连接（降到 %d 以下自动恢复）", n, kernSkipOver, kernSkipOver))
		}
		k.skip = true
		return
	}
	k.skip = false
	k.setRanges(cn, c.LAN.CIDR)
	f, err := os.Open(ctPath)
	if err != nil {
		return
	}
	t0 := time.Now()
	newIPs := k.scan(f, now.Unix())
	f.Close()
	k.lastDur = time.Since(t0)
	if len(newIPs) > 0 {
		k.resolve(newIPs)
	}
}

func (k *KernConns) setRanges(cn, lan []string) {
	if len(cn) != len(k.cnSrc) || (len(cn) > 0 && (cn[0] != k.cnSrc[0] || cn[len(cn)-1] != k.cnSrc[len(cn)-1])) {
		k.cn, k.cnSrc = cidrRanges(cn), cn
	}
	if s := strings.Join(lan, ","); s != k.lanS {
		k.lan, k.lanS = cidrRanges(lan), s
	}
}

func cidrRanges(list []string) []u32r {
	out := make([]u32r, 0, len(list))
	for _, s := range list {
		pf, err := parsePrefix(s)
		if err != nil || !pf.Addr().Is4() {
			continue
		}
		pf = pf.Masked()
		a := pf.Addr().As4()
		lo := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		hi := lo | uint32(uint64(1)<<(32-pf.Bits())-1)
		out = append(out, u32r{lo, hi})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })
	return out
}

func inRanges(rs []u32r, ip uint32) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= ip })
	return i < len(rs) && rs[i].lo <= ip
}

// scan 解析一遍 conntrack，返回需要反查域名的新目标 IP。
func (k *KernConns) scan(r interface{ Read([]byte) (int, error) }, now int64) []uint32 {
	if k.rd == nil {
		k.rd = bufio.NewReaderSize(r, 32<<10)
	} else {
		k.rd.Reset(r)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.round++
	rows := 0
	var newIPs []uint32
	want := map[uint32]bool{}
	for {
		line, err := k.rd.ReadSlice('\n')
		if len(line) > 0 {
			rows++
			if e, ok := parseCT(line); ok && inRanges(k.lan, e.k.src) && inRanges(k.cn, e.k.dst) && e.replyDst != e.k.src {
				fl := k.active[e.k]
				if fl == nil {
					if len(k.active) >= kernMaxActive {
						k.drop++
						goto next
					}
					fl = &kFlow{k: e.k, start: now, last: now}
					k.active[e.k] = fl
					if !want[e.k.dst] && len(newIPs) < 512 {
						want[e.k.dst] = true
						newIPs = append(newIPs, e.k.dst)
					}
				}
				if e.up != fl.up || e.down != fl.down {
					fl.up, fl.down, fl.last = e.up, e.down, now
				}
				if e.closed && fl.end == 0 {
					fl.end = now
				}
				fl.seen = k.round
			}
		}
	next:
		if err != nil {
			if err == bufio.ErrBufferFull { // 超长行：丢掉剩余部分
				for err == bufio.ErrBufferFull {
					_, err = k.rd.ReadSlice('\n')
				}
				if err == nil {
					continue
				}
			}
			break
		}
	}
	k.lastRows = rows
	for key, fl := range k.active {
		if fl.seen != k.round {
			if fl.end == 0 {
				fl.end = fl.last // UDP / 超时消失：以最后一次有流量的时间为结束
			}
			k.pushEnded(*fl)
			delete(k.active, key)
		}
	}
	k.base = true
	return newIPs
}

func (k *KernConns) pushEnded(f kFlow) {
	if len(k.ended) < kernMaxEnded {
		k.ended = append(k.ended, f)
		return
	}
	k.ended[k.epos] = f
	k.epos = (k.epos + 1) % kernMaxEnded
}

func (k *KernConns) endAll(now int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, fl := range k.active {
		if fl.end == 0 {
			fl.end = now
		}
		k.pushEnded(*fl)
		delete(k.active, key)
	}
}

type ctEntry struct {
	k        kKey
	up, down int64
	replyDst uint32
	closed   bool
}

// parseCT 解析一行 /proc/net/nf_conntrack（不分配内存）：
// ipv4 2 tcp 6 7431 ESTABLISHED src=A dst=B sport=x dport=y [packets=n bytes=n] [UNREPLIED] src=B dst=W sport=y dport=x [packets bytes] [ASSURED] mark=0 zone=0 use=2
func parseCT(line []byte) (e ctEntry, ok bool) {
	if !bytes.HasPrefix(line, []byte("ipv4 ")) {
		return e, false
	}
	tuple, field := 0, 0
	var srcOK, dstOK bool
	for len(line) > 0 {
		for len(line) > 0 && (line[0] == ' ' || line[0] == '\n') {
			line = line[1:]
		}
		i := bytes.IndexByte(line, ' ')
		var tok []byte
		if i < 0 {
			tok, line = bytes.TrimRight(line, "\n"), nil
		} else {
			tok, line = line[:i], line[i+1:]
		}
		if len(tok) == 0 {
			continue
		}
		field++
		if field == 3 {
			switch string(tok) {
			case "tcp":
				e.k.proto = 6
			case "udp":
				e.k.proto = 17
			default:
				return e, false
			}
			continue
		}
		if field == 6 && e.k.proto == 6 && tok[0] >= 'A' && tok[0] <= 'Z' {
			switch string(tok) {
			case "TIME_WAIT", "CLOSE", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK":
				e.closed = true
			}
			continue
		}
		eq := bytes.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		key, val := tok[:eq], tok[eq+1:]
		switch string(key) {
		case "src":
			tuple++
			if tuple == 1 {
				e.k.src, srcOK = ip4(val)
			}
		case "dst":
			if tuple == 1 {
				e.k.dst, dstOK = ip4(val)
			} else if tuple == 2 {
				e.replyDst, _ = ip4(val)
			}
		case "sport":
			if tuple == 1 {
				e.k.sport = uint16(atou(val))
			}
		case "dport":
			if tuple == 1 {
				e.k.dport = uint16(atou(val))
			}
		case "bytes":
			if tuple == 1 {
				e.up = int64(atou(val))
			} else if tuple == 2 {
				e.down = int64(atou(val))
			}
		}
		if tuple > 2 {
			break
		}
	}
	return e, srcOK && dstOK && tuple >= 2
}

func atou(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func ip4(b []byte) (uint32, bool) {
	var ip, part uint32
	dots, digits := 0, 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			part = part*10 + uint32(c-'0')
			digits++
			if part > 255 || digits > 3 {
				return 0, false
			}
		case c == '.':
			if digits == 0 {
				return 0, false
			}
			ip, part, digits = ip<<8|part, 0, 0
			dots++
		default:
			return 0, false
		}
	}
	if dots != 3 || digits == 0 {
		return 0, false
	}
	return ip<<8 | part, true
}

func u32ip(u uint32) string {
	var b [15]byte
	s := strconv.AppendUint(b[:0], uint64(u>>24), 10)
	s = append(s, '.')
	s = strconv.AppendUint(s, uint64(u>>16&255), 10)
	s = append(s, '.')
	s = strconv.AppendUint(s, uint64(u>>8&255), 10)
	s = append(s, '.')
	s = strconv.AppendUint(s, uint64(u&255), 10)
	return string(s)
}

// resolve 经内核的 rdns.sock 批量反查（≤512 个 IP，1.5 s 超时）。
func (k *KernConns) resolve(ips []uint32) {
	names := rdnsQuery(filepath.Join(k.d.workDir, rdnsSock), ips)
	if len(names) == 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, fl := range k.active {
		if fl.host == "" {
			if n, ok := names[fl.k.dst]; ok {
				fl.host = n
			}
		}
	}
}

func rdnsQuery(sock string, ips []uint32) map[uint32]string {
	c, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(u32ip(ip))
		b.WriteByte('\n')
	}
	b.WriteString("\n") // 空行 = 请求结束
	if _, err := c.Write([]byte(b.String())); err != nil {
		return nil
	}
	out := map[uint32]string{}
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" {
			break
		}
		sp := strings.IndexByte(ln, ' ')
		if sp < 0 {
			continue
		}
		if ip, ok := ip4([]byte(ln[:sp])); ok {
			out[ip] = ln[sp+1:]
		}
	}
	return out
}

// ---------- conntrack 字节统计开关 ----------

func (k *KernConns) origPath() string { return filepath.Join(k.d.runDir, "ct_acct.orig") }

func (k *KernConns) ensureAcct() {
	if k.acctOn {
		return
	}
	cur, err := os.ReadFile(ctAcctPath)
	if err != nil {
		return
	}
	if _, err := os.Stat(k.origPath()); err != nil { // 守护进程重启时不覆盖最初的原值
		os.WriteFile(k.origPath(), bytes.TrimSpace(cur), 0o600)
	}
	if string(bytes.TrimSpace(cur)) != "1" {
		os.WriteFile(ctAcctPath, []byte("1\n"), 0o644)
	}
	k.acctOn = true
}

func (k *KernConns) restoreAcct() {
	k.mu.Lock()
	defer k.mu.Unlock()
	orig, err := os.ReadFile(k.origPath())
	if err != nil {
		k.acctOn = false
		return
	}
	v := bytes.TrimSpace(orig)
	if len(v) == 1 && (v[0] == '0' || v[0] == '1') {
		os.WriteFile(ctAcctPath, append(v, '\n'), 0o644)
	}
	os.Remove(k.origPath())
	k.acctOn = false
}

func readIntFile(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(string(bytes.TrimSpace(b)))
	return n
}

// ---------- 给面板 ----------

func protoName(p uint8) string {
	if p == 6 {
		return "tcp"
	}
	return "udp"
}

func (f *kFlow) hostOrIP() string {
	if f.host != "" {
		return f.host
	}
	return u32ip(f.k.dst)
}

func (f *kFlow) id() string {
	return fmt.Sprintf("k%x-%x-%x-%x-%d", f.k.src, f.k.sport, f.k.dst, f.k.dport, f.k.proto)
}

// liveViews：当前活动（未关闭）的内核直连连接，给 /api/conns。
func (k *KernConns) liveViews() ([]connView, []devConn) {
	if k == nil {
		return nil, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	cv := make([]connView, 0, len(k.active))
	dc := make([]devConn, 0, len(k.active))
	for _, f := range k.active {
		if f.end != 0 {
			continue
		}
		src := u32ip(f.k.src)
		cv = append(cv, connView{ID: f.id(), Src: src, Host: f.hostOrIP(), Port: strconv.Itoa(int(f.k.dport)), Net: protoName(f.k.proto),
			Rule: kernRule, Out: "direct", Group: "direct", Up: f.up, Down: f.down,
			Start: time.Unix(f.start, 0).In(cst).Format(time.RFC3339), Kern: true})
		dc = append(dc, devConn{src: src, out: "direct", rule: kernRule}) // start 留空：不拿首次看到时间当设备活动
	}
	return cv, dc
}

// records：活动 + 已结束的内核直连记录（给 24 小时历史），按 ip / 关键字过滤。
func (k *KernConns) records(ip, q string, since int64) []histRec {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []histRec
	add := func(f *kFlow) {
		if f.start < since {
			return
		}
		src := u32ip(f.k.src)
		if ip != "" && src != ip {
			return
		}
		h := f.hostOrIP()
		if q != "" && !strings.Contains(strings.ToLower(h+" direct "+kernRule), q) {
			return
		}
		out = append(out, histRec{T: f.start, S: src, H: h, P: strconv.Itoa(int(f.k.dport)), N: protoName(f.k.proto), O: "direct", G: "direct", R: kernRule,
			U: f.up, D: f.down, K: true, E: f.end})
	}
	for _, f := range k.active {
		add(f)
	}
	for i := range k.ended {
		add(&k.ended[i])
	}
	return out
}

func (k *KernConns) stats() map[string]any {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return map[string]any{"active": len(k.active), "ended": len(k.ended), "skipped": k.skip, "dropped": k.drop,
		"rows": k.lastRows, "scan_ms": float64(k.lastDur.Microseconds()) / 1000, "acct": k.acctOn}
}
