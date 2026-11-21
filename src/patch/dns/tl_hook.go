package dns

// TinyLane M6d：DNS 应答旁路钩子（只读，不改变解析/路由行为）。
// build.sh 在 recordReverseMapping 开头插入一行调用；钩子为 nil 时零开销。

import mDNS "github.com/miekg/dns"

var tlDNSHook func(*mDNS.Msg)

// SetTinyLaneDNSHook 由 tinylane run 在启动前设置。
func SetTinyLaneDNSHook(f func(*mDNS.Msg)) { tlDNSHook = f }

func tlCallDNSHook(response *mDNS.Msg) {
	if h := tlDNSHook; h != nil && response != nil && len(response.Answer) > 0 {
		h(response)
	}
}
