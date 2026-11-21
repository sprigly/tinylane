package main

import (
	"os"
	"testing"
	"time"
)

func TestUpstreamOK(t *testing.T) {
	os.Setenv("TINYLANE_UPSTREAM_TARGETS", "10.255.255.1:443,10.255.255.2:443")
	t0 := time.Now()
	if upstreamOK() {
		t.Fatal("不可达目标应判定为上游断网")
	}
	if time.Since(t0) > 4*time.Second {
		t.Fatal("判定太慢（并发拨号应 ≤2.5 s）")
	}
	os.Setenv("TINYLANE_UPSTREAM_TARGETS", "10.255.255.1:443,1.1.1.1:443")
	if !upstreamOK() {
		t.Fatal("任意一个可达就算上游正常")
	}
}

func TestParseAcct(t *testing.T) {
	txt := "table inet tinylane_acct {\n\tset up4 {\n\t\telements = { 192.168.1.136 counter packets 24 bytes 2914 expires 1d23h59m45s550ms }\n\t}\n}\ntable inet tinylane_acct {\n\tset down4 {\n\t\telements = { 192.168.1.136 counter packets 17 bytes 6717 expires 1d23h59m45s480ms,\n\t\t\t     192.168.1.138 counter packets 8 bytes 1007 expires 1d23h59m43s890ms }\n\t}\n}\n"
	u, d := parseAcctSet(txt, "up4"), parseAcctSet(txt, "down4")
	if u["192.168.1.136"] != 2914 || len(u) != 1 || d["192.168.1.136"] != 6717 || d["192.168.1.138"] != 1007 {
		t.Fatalf("解析错误 %v %v", u, d)
	}
}

func TestProtect(t *testing.T) {
	old := &Config{Groups: []Group{{Name: "M", Strict: true}}, Rules: []Rule{{Name: "p", Pin: true, Outbound: "M"}}}
	old.AlwaysBypass.CIDR = append([]string{}, builtinBypassCIDR...)
	nw := *old
	nw.Groups = []Group{{Name: "M"}}
	if protectInvariants(old, &nw) != nil {
		t.Fatal("M7：组规则可在面板里改，不应再被保护拦住")
	}
	nw = *old
	nw.Rules = nil
	if protectInvariants(old, &nw) == nil {
		t.Fatal("删除固定规则应被拒绝")
	}
	if protectInvariants(old, old) != nil {
		t.Fatal("不变应通过")
	}
}
