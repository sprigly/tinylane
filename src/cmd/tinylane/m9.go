package main

// M9：内核内存软上限（设置里可调）+ 内存/流量曲线（守护进程每分钟采样，内存中保留 48 小时）。

import (
	"fmt"
	"os"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	memLimitDefaultMB = 40
	memLimitMinMB     = 30
	memLimitMaxMB     = 120
	memLimitOffMB     = 96 // 关闭 = 旧版固定 96 MB 兜底
	memLimitFile      = "memlimit"
	memHistMax        = 48 * 60
)

// coreMemLimitMB：0 = 关（回到 96 MB 兜底），nil = 缺省 40。
func coreMemLimitMB(c *Config) int {
	if c == nil || c.CoreMemLimitMB == nil {
		return memLimitDefaultMB
	}
	return *c.CoreMemLimitMB
}

func effMemLimitMB(v int) int {
	if v <= 0 {
		return memLimitOffMB
	}
	return v
}

func validMemLimit(v int) error {
	if v == 0 || (v >= memLimitMinMB && v <= memLimitMaxMB) {
		return nil
	}
	return fmt.Errorf("内核内存上限只能是 0（关）或 %d–%d MB", memLimitMinMB, memLimitMaxMB)
}

// ---- 内核进程（tinylane run）一侧：读 memlimit 文件，变了就改，不用重启 ----

var curMemLimit atomic.Int64

func applyMemLimitFile(dir string) {
	mb := memLimitDefaultMB
	if b, err := os.ReadFile(filepath.Join(dir, memLimitFile)); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			mb = effMemLimitMB(v)
		}
	}
	n := int64(mb) << 20
	if curMemLimit.Swap(n) != n {
		runtimeDebug.SetMemoryLimit(n)
	}
}

var memWatchOnce sync.Once

func startMemLimitWatch(dir string) {
	applyMemLimitFile(dir)
	memWatchOnce.Do(func() {
		go func() {
			for range time.Tick(15 * time.Second) {
				applyMemLimitFile(dir)
			}
		}()
	})
}

// ---- 守护进程一侧 ----

func (d *Daemon) writeMemLimit(c *Config) {
	p := filepath.Join(d.runDir, memLimitFile)
	s := strconv.Itoa(coreMemLimitMB(c))
	if b, _ := os.ReadFile(p); string(b) == s {
		return
	}
	writeFileAtomic(p, []byte(s), 0o600)
}

type memPt struct {
	T     int64 `json:"t"`     // unix 秒
	Core  int32 `json:"core"`  // 内核 VmRSS KB
	Anon  int32 `json:"anon"`  // 内核 RssAnon KB
	Dmn   int32 `json:"dmn"`   // 守护进程 VmRSS KB
	Avail int32 `json:"avail"` // MemAvailable KB
	Down  int64 `json:"down"`  // 这一分钟下行字节（经代理内核）
	Up    int64 `json:"up"`
	G     []gPt `json:"g,omitempty"` // M10：各故障切换组当前节点 / 延迟 / 备用节点延迟
}

type MemHist struct {
	mu           sync.Mutex
	pts          []memPt
	down, up     atomic.Int64 // TrafficRing 每秒累加
	lastD, lastU int64
}

func (m *MemHist) addTraffic(up, down int64) { m.up.Add(up); m.down.Add(down) }

func procKB(pid int, keys ...string) []int32 {
	out := make([]int32, len(keys))
	if pid <= 0 {
		return out
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		for i, k := range keys {
			if strings.HasPrefix(l, k+":") {
				if f := strings.Fields(l); len(f) >= 2 {
					v, _ := strconv.Atoi(f[1])
					out[i] = int32(v)
				}
			}
		}
	}
	return out
}

func memAvailKB() int32 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemAvailable:") {
			if f := strings.Fields(l); len(f) >= 2 {
				v, _ := strconv.Atoi(f[1])
				return int32(v)
			}
		}
	}
	return 0
}

func (m *MemHist) sample(corePid int) { m.sampleG(corePid, nil) }

func (m *MemHist) sampleG(corePid int, gs []gPt) {
	c := procKB(corePid, "VmRSS", "RssAnon")
	dm := procKB(os.Getpid(), "VmRSS")
	dn, up := m.down.Load(), m.up.Load()
	p := memPt{T: time.Now().Unix(), Core: c[0], Anon: c[1], Dmn: dm[0], Avail: memAvailKB(), Down: dn - m.lastD, Up: up - m.lastU, G: gs}
	m.lastD, m.lastU = dn, up
	m.mu.Lock()
	m.pts = append(m.pts, p)
	if len(m.pts) > memHistMax {
		m.pts = append(m.pts[:0:0], m.pts[len(m.pts)-memHistMax:]...)
	}
	m.mu.Unlock()
}

func (m *MemHist) snapshot() []memPt {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]memPt(nil), m.pts...)
}

func (d *Daemon) memHistLoop() {
	d.writeMemLimit(d.conf())
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	d.memh.sampleG(d.corePid(), d.wd.histGroups(d.conf()))
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-t.C:
			d.writeMemLimit(d.conf())
			d.memh.sampleG(d.corePid(), d.wd.histGroups(d.conf()))
		}
	}
}

// memHistView：给面板的曲线数据 + 峰值。
func (d *Daemon) memHistView() map[string]any {
	pts := d.memh.snapshot()
	var peak memPt
	for _, p := range pts {
		if p.Core > peak.Core {
			peak = p
		}
	}
	sw := []switchEv{}
	if d.wd != nil {
		sw = d.wd.switches()
	}
	c := d.conf()
	return map[string]any{"points": pts, "peak": peak, "limit_mb": coreMemLimitMB(c), "interval_s": 60,
		"switches": sw, "main_group": c.MainGroup}
}
