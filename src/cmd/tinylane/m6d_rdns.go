package main

// M6d：内核进程（tinylane run）里的 DNS 反查表 + unix socket 查询口。
// 只读旁路：钩子在 sing-box 记录 DNS 应答时被调用，不改变解析结果和路由。

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	mDNS "github.com/miekg/dns"
	sbdns "github.com/sagernet/sing-box/dns"
)

const (
	rdnsSock  = "rdns.sock"
	rdnsMax   = 4096
	rdnsGrace = 120 // 秒：TTL 到了之后再留一会儿（设备自己也会缓存）
	rdnsMinTT = 60
)

type rdnsEnt struct {
	name string
	exp  int64
}

type rdnsTable struct {
	mu   sync.Mutex
	m    map[uint32]rdnsEnt
	ring []uint32
	pos  int
	cap  int
	now  func() int64
}

func newRdnsTable(n int) *rdnsTable {
	return &rdnsTable{m: make(map[uint32]rdnsEnt, 256), cap: n, now: func() int64 { return time.Now().Unix() }}
}

func (t *rdnsTable) add(ip uint32, name string, ttl uint32) {
	if ttl < rdnsMinTT {
		ttl = rdnsMinTT
	}
	if ttl > 86400 {
		ttl = 86400
	}
	exp := t.now() + int64(ttl) + rdnsGrace
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[ip]; ok {
		if e.name != name {
			e.name = name
		}
		e.exp = exp
		t.m[ip] = e
		return
	}
	if len(t.ring) < t.cap {
		t.ring = append(t.ring, ip)
	} else { // 满了：淘汰最早加入的
		delete(t.m, t.ring[t.pos])
		t.ring[t.pos] = ip
		t.pos = (t.pos + 1) % t.cap
	}
	t.m[ip] = rdnsEnt{name, exp}
}

func (t *rdnsTable) get(ip uint32) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[ip]
	if !ok || e.exp < t.now() {
		return "", false
	}
	return e.name, true
}

func (t *rdnsTable) len() int { t.mu.Lock(); defer t.mu.Unlock(); return len(t.m) }

// onDNS：记 A 记录 → 问题域名（CNAME 链统一记成用户查询的名字，如 www.baidu.com 而不是 shifen）。
func (t *rdnsTable) onDNS(msg *mDNS.Msg) {
	q := ""
	if len(msg.Question) > 0 {
		q = strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	}
	for _, rr := range msg.Answer {
		a, ok := rr.(*mDNS.A)
		if !ok {
			continue
		}
		v4 := a.A.To4()
		if v4 == nil {
			continue
		}
		name := q
		if name == "" {
			name = strings.ToLower(strings.TrimSuffix(a.Hdr.Name, "."))
		}
		if name == "" || len(name) > 253 {
			continue
		}
		t.add(uint32(v4[0])<<24|uint32(v4[1])<<16|uint32(v4[2])<<8|uint32(v4[3]), name, a.Hdr.Ttl)
	}
}

func (t *rdnsTable) serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			sc := bufio.NewScanner(c)
			w := bufio.NewWriter(c)
			n := 0
			for sc.Scan() && n < 512 {
				ln := sc.Text()
				if ln == "" {
					break
				}
				n++
				if ip, ok := ip4([]byte(ln)); ok {
					if name, ok := t.get(ip); ok {
						w.WriteString(ln)
						w.WriteByte(' ')
						w.WriteString(name)
						w.WriteByte('\n')
					}
				}
			}
			w.WriteByte('\n')
			w.Flush()
		}(c)
	}
}

// startRdns：在当前工作目录建 rdns.sock（0600）。失败只是没有域名，不影响内核。
func startRdns() *rdnsTable {
	t := newRdnsTable(rdnsMax)
	os.Remove(rdnsSock)
	l, err := net.Listen("unix", rdnsSock)
	if err != nil {
		return t
	}
	os.Chmod(rdnsSock, 0o600)
	sbdns.SetTinyLaneDNSHook(t.onDNS)
	go t.serve(l)
	return t
}
