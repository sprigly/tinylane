package main

// 内核国内 IP 绕过（M5）：从 geoip-cn.srs 取 IPv4 网段，生成 nft 集合 cn4。
// 规则模式下 LAN → 国内 IP 的流量在 prerouting 直接 return，不进 tproxy / sing-box（无 5 s 拨号上限，省 CPU）。
// 集合只写进 /var/run（tmpfs）里的 nft 文件，不占闪存。按文件 mtime+size 缓存。

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	"go4.org/netipx"
)

var cnCache struct {
	sync.Mutex
	path  string
	mod   time.Time
	size  int64
	cidrs []string
}

// loadCN4 返回合并后的 IPv4 网段（字符串）；读不到 / 解析失败返回 nil（= 不绕过，安全回退）。
func loadCN4(dir string) []string {
	p := filepath.Join(dir, "geoip-cn.srs")
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	cnCache.Lock()
	defer cnCache.Unlock()
	if cnCache.path == p && cnCache.mod.Equal(st.ModTime()) && cnCache.size == st.Size() {
		return cnCache.cidrs
	}
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	compat, err := srs.Read(f, false)
	if err != nil {
		return nil
	}
	rs, err := compat.Upgrade()
	if err != nil {
		return nil
	}
	var b netipx.IPSetBuilder
	n := 0
	for _, r := range rs.Rules {
		if r.DefaultOptions.IPSet != nil {
			for _, pf := range r.DefaultOptions.IPSet.Prefixes() {
				if pf.Addr().Is4() {
					b.AddPrefix(pf.Masked())
					n++
				}
			}
		}
		for _, s := range r.DefaultOptions.IPCIDR {
			pf, err := netip.ParsePrefix(s)
			if err != nil {
				if a, err2 := netip.ParseAddr(s); err2 == nil {
					pf = netip.PrefixFrom(a, a.BitLen())
				} else {
					continue
				}
			}
			if pf.Addr().Is4() {
				b.AddPrefix(pf.Masked())
				n++
			}
		}
	}
	// 永远不绕过的目标（防御）：私有段本来就在 bypass4 里，这里不用处理
	set, err := b.IPSet()
	if err != nil || n == 0 {
		return nil
	}
	var out []string
	for _, pf := range set.Prefixes() {
		out = append(out, pf.String())
	}
	cnCache.path, cnCache.mod, cnCache.size, cnCache.cidrs = p, st.ModTime(), st.Size(), out
	return out
}
