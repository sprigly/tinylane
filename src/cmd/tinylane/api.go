package main

// 路由器上没有 python：用这几个小命令通过 clash_api（127.0.0.1）查连接、切节点、切模式，方便部署验证。
//   tinylane conns [-i tinylane.json] [关键词]      当前连接：来源 → 域名 → 命中规则 → 出站链
//   tinylane select [-i ...] <组> [节点]            不给节点 = 列出成员和当前选择
//   tinylane mode [-i ...] [rule|global|direct]     不给参数 = 显示当前模式

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiClient struct {
	base, secret string
	hc           *http.Client
}

func newAPI(cfgPath string) (*apiClient, error) {
	c, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	return &apiClient{base: "http://" + c.ClashAPI.Listen, secret: c.ClashAPI.Secret,
		hc: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}}, nil
}

var clashHTTP = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}}
var streamHTTP = &http.Client{Transport: &http.Transport{Proxy: nil}}

func newReq(ctx context.Context, a *apiClient, method, path string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.secret)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (a *apiClient) do(method, path string, body any, out any) error {
	return a.doCtx(context.Background(), 10*time.Second, method, path, body, out)
}

func (a *apiClient) doCtx(ctx context.Context, timeout time.Duration, method, path string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := newReq(ctx, a, method, path, body)
	if err != nil {
		return err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("clash_api %s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func apiFlags(name string, args []string) (*apiClient, []string, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	fs.Parse(args)
	a, err := newAPI(*in)
	return a, fs.Args(), err
}

func cmdConns(args []string) error {
	a, rest, err := apiFlags("conns", args)
	if err != nil {
		return err
	}
	var r struct {
		Connections []struct {
			Metadata struct {
				Network, Type, SourceIP, SourcePort, Host, DestinationIP, DestinationPort string
			} `json:"metadata"`
			Upload, Download int64
			Rule             string
			Chains           []string
		} `json:"connections"`
	}
	if err := a.do("GET", "/connections", nil, &r); err != nil {
		return err
	}
	kw := strings.Join(rest, " ")
	n := 0
	for _, c := range r.Connections {
		m := c.Metadata
		host := m.Host
		if host == "" {
			host = m.DestinationIP
		}
		chain := make([]string, len(c.Chains))
		for i := range c.Chains {
			chain[len(c.Chains)-1-i] = c.Chains[i]
		}
		line := fmt.Sprintf("%-4s %-15s %-34s → %s  [%s]  ↑%d ↓%d", m.Network, m.SourceIP, host+":"+m.DestinationPort,
			strings.Join(chain, " → "), c.Rule, c.Upload, c.Download)
		if kw == "" || strings.Contains(line, kw) {
			fmt.Println(line)
			n++
		}
	}
	fmt.Printf("共 %d 条\n", n)
	return nil
}

func cmdSelect(args []string) error {
	a, rest, err := apiFlags("select", args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("用法：tinylane select <组> [节点]")
	}
	g := url.PathEscape(rest[0])
	if len(rest) >= 2 {
		node := strings.Join(rest[1:], " ")
		if err := a.do("PUT", "/proxies/"+g, map[string]string{"name": node}, nil); err != nil {
			return err
		}
	}
	var p struct {
		Now string   `json:"now"`
		All []string `json:"all"`
	}
	if err := a.do("GET", "/proxies/"+g, nil, &p); err != nil {
		return err
	}
	for _, m := range p.All {
		mark := "  "
		if m == p.Now {
			mark = "* "
		}
		fmt.Println(mark + m)
	}
	return nil
}

func cmdMode(args []string) error {
	a, rest, err := apiFlags("mode", args)
	if err != nil {
		return err
	}
	if len(rest) == 1 {
		if err := a.do("PATCH", "/configs", map[string]string{"mode": rest[0]}, nil); err != nil {
			return err
		}
	}
	var c struct {
		Mode string `json:"mode"`
	}
	if err := a.do("GET", "/configs", nil, &c); err != nil {
		return err
	}
	fmt.Println("当前模式：", c.Mode)
	return nil
}
