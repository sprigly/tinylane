package main

// update-rules：下载 geosite-cn / geoip-cn .srs 到闪存（体积几百 KB）。
// 直连下载（路由器本机流量不经过 tproxy），DNS 直接问国内 DNS，不依赖 dnsmasq / sing-box 是否在跑。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func httpClientDirect(dnsServer string) *http.Client {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dnsServer, "53"))
		},
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver}
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, n, a string) (net.Conn, error) { return dialer.DialContext(ctx, "tcp4", a) },
		TLSHandshakeTimeout: 10 * time.Second,
		Proxy:               nil,
	}
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}
}

// srs 文件头：魔数 "SRS"
func validSRS(b []byte) bool { return len(b) > 16 && bytes.HasPrefix(b, []byte("SRS")) }

func updateRules(c *Config, force bool) error {
	dnsIP := c.DNS.CN[0]
	if ip := net.ParseIP(dnsIP); ip == nil {
		dnsIP = "223.5.5.5"
	}
	cl := httpClientDirect(dnsIP)
	jobs := []struct {
		file string
		urls []string
	}{
		{"geosite-cn.srs", c.RuleSets.GeositeCN},
		{"geoip-cn.srs", c.RuleSets.GeoipCN},
	}
	var firstErr error
	for _, j := range jobs {
		dst := filepath.Join(c.RuleSets.Dir, j.file)
		if !force {
			if st, err := os.Stat(dst); err == nil && time.Since(st.ModTime()) < time.Duration(c.RuleSets.UpdateDays)*24*time.Hour {
				fmt.Printf("%s 未过期（%s），跳过\n", j.file, st.ModTime().Format("2006-01-02"))
				continue
			}
		}
		var ok bool
		for _, u := range j.urls {
			data, err := fetch(cl, u)
			if err != nil {
				fmt.Fprintf(os.Stderr, "下载失败 %s：%v\n", u, err)
				continue
			}
			if !validSRS(data) {
				fmt.Fprintf(os.Stderr, "内容不是 .srs：%s\n", u)
				continue
			}
			if err := writeFileAtomic(dst, data, 0o644); err != nil {
				return err
			}
			fmt.Printf("%s ← %s（%d 字节）\n", j.file, u, len(data))
			ok = true
			break
		}
		if !ok {
			if _, err := os.Stat(dst); err == nil {
				fmt.Fprintf(os.Stderr, "%s 下载全部失败，继续用旧文件\n", j.file)
			} else if firstErr == nil {
				firstErr = fmt.Errorf("%s 下载失败且本地没有旧文件", j.file)
			}
		}
	}
	return firstErr
}

func fetch(cl *http.Client, u string) ([]byte, error) {
	resp, err := cl.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
