package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 设备「国内直连，国外走某组」：源 IP 规则排在国内直连之后；nft 不把它放进 nobypass_src
func TestDeviceIntlMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	js := `{"clash_api":{"secret":"x"},"nodes":[{"name":"a","outbound":{"type":"vless"}},{"name":"b","outbound":{"type":"vless"}}],
"groups":[{"name":"G1","type":"failover","members":["a"]},{"name":"G2","type":"failover","members":["b"]}],
"devices":[{"name":"p","ip":"192.168.1.20","mode":"intl","group":"G2"},{"name":"q","ip":"192.168.1.21","mode":"global","group":"G2"}]}`
	os.WriteFile(p, []byte(js), 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := buildSingBox(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sb["route"].(M)["rules"])
	s := string(b)
	iIntl := strings.Index(s, `"192.168.1.20"`)
	iCN := strings.Index(s, `"domain_suffix":["cn"]`)
	iGlob := strings.Index(s, `"192.168.1.21"`)
	if iIntl < 0 || iCN < 0 || iGlob < 0 {
		t.Fatalf("规则缺失：%s", s)
	}
	if !(iGlob < iCN && iCN < iIntl) {
		t.Fatalf("顺序不对 global=%d cn=%d intl=%d", iGlob, iCN, iIntl)
	}
	nft := buildNft(c)
	if strings.Contains(nft, "192.168.1.20") && strings.Contains(nft, "nobypass_src") {
		for _, l := range strings.Split(nft, "\n") {
			if strings.Contains(l, "192.168.1.20") {
				t.Fatalf("intl 设备不该进 nobypass_src：%s", l)
			}
		}
	}
	os.WriteFile(p, []byte(strings.Replace(js, `"mode":"intl"`, `"mode":"bogus"`, 1)), 0o600)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("无效 mode 应报错")
	}
}
