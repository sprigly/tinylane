package main

// M7 命令行：migrate（迁移配置）、members（打印各组实际成员）、parse-sub（离线解析订阅文件，测试/排查用，不打印密码）

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

func cmdMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	out := fs.String("o", "", "输出（默认写回 -i；- = stdout）")
	fs.Parse(args)
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	changed, notes := migrateM7(m)
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, "迁移：", n)
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "已是 M7 配置，无需迁移")
	}
	data := marshal(m)
	tmp := *in + ".m7check"
	if err := writeFileAtomic(tmp, data, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := loadConfig(tmp); err != nil {
		return fmt.Errorf("迁移后配置校验失败：%v", err)
	}
	switch *out {
	case "-":
		os.Stdout.Write(data)
		return nil
	case "":
		if !changed {
			return nil
		}
		return writeFileAtomic(*in, data, 0o600)
	}
	return writeFileAtomic(*out, data, 0o600)
}

func cmdMembers(args []string) error {
	fs := flag.NewFlagSet("members", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	fs.Parse(args)
	c, err := loadConfig(*in)
	if err != nil {
		return err
	}
	for _, g := range c.Groups {
		obs, _ := selectorOutbounds(c, g)
		fmt.Printf("%s\tstrict=%v\t%s\n", g.Name, g.Strict, strings.Join(obs, " | "))
	}
	return nil
}

func cmdParseSub(args []string) error {
	fs := flag.NewFlagSet("parse-sub", flag.ExitOnError)
	f := fs.String("f", "", "订阅内容文件")
	merge := fs.String("merge", "", "合并进这个 tinylane.json（作为订阅 --sub 的节点）")
	sub := fs.String("sub", "测试订阅", "订阅名")
	out := fs.String("o", "", "合并结果输出文件")
	pins := fs.Bool("pins", true, "连服务器确认证书指纹")
	fs.Parse(args)
	data, err := os.ReadFile(*f)
	if err != nil {
		return err
	}
	nodes, warns, format, err := parseSubscription(data)
	if err != nil {
		return err
	}
	excl := defaultImportExclude
	var c *Config
	if *merge != "" {
		if c, err = loadConfig(*merge); err != nil {
			return err
		}
		excl = c.importExclude()
	}
	nodes, dropped := filterInfoNodes(nodes, excl)
	if *pins {
		var prev []Node
		dns := "223.5.5.5"
		if c != nil {
			prev, dns = c.Nodes, c.DNS.CN[0]
		}
		warns = append(warns, resolvePins(nodes, prev, dns)...)
	}
	types := map[string]int{}
	pinned := 0
	for _, n := range nodes {
		types[n.Type()]++
		if t, _ := n.Outbound["tls"].(M); t != nil && t["certificate_public_key_sha256"] != nil {
			pinned++
		}
	}
	var tk []string
	for k, v := range types {
		tk = append(tk, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(tk)
	fmt.Printf("格式 %s；导入 %d 个（%s）；证书已固定 %d；过滤 %d 个信息条目：%s\n", format, len(nodes), strings.Join(tk, " "), pinned, len(dropped), strings.Join(dropped, "、"))
	for _, w := range warns {
		fmt.Println("提示：", w)
	}
	if *merge == "" || *out == "" {
		return nil
	}
	raw, _ := os.ReadFile(*merge)
	var m map[string]any
	json.Unmarshal(raw, &m)
	idx := -1
	for i, s := range c.Subs {
		if s.Name == *sub {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("配置里没有订阅 %q", *sub)
	}
	for i := range nodes {
		nodes[i].Source = "sub:" + *sub
	}
	merged := mergeSub(c.Nodes, nodes, subOwner(idx, *sub), *sub)
	m["nodes"] = merged
	return writeFileAtomic(*out, marshal(m), 0o600)
}
