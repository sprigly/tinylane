package main

// tinylane = 精简 sing-box 1.14.4 内核 + TinyLane 配置生成器。
//   tinylane run    -c config.json [-D workdir]
//   tinylane check  -c config.json
//   tinylane gen    [-i /etc/tinylane/tinylane.json] [-o /var/run/tinylane/config.json] [--nft F] [--env F]
//   tinylane import-clash -f clash.yaml [--merge tinylane.json] [-o out.json]
//   tinylane update-rules [-i tinylane.json] [--force]
//   tinylane version

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sbjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

const tlVersion = "0.4.5"

func usage() {
	fmt.Fprintf(os.Stderr, `tinylane %s (sing-box %s)
用法：
  tinylane run -c config.json [-D dir]      运行内核（SIGHUP 重新加载）
  tinylane check -c config.json             校验 sing-box 配置
  tinylane gen [-i tinylane.json] [-o config.json] [--nft file] [--env file]
  tinylane import-clash -f clash.yaml [--merge tinylane.json] [-o out.json]
  tinylane migrate [-i tinylane.json] [-o out|-]  把旧配置（禁止出口 / 出口标签）迁移成 M7 通用组规则
  tinylane members [-i tinylane.json]             打印各组实际成员（手选 + 名称筛选 − 排除）
  tinylane parse-sub -f 订阅文件 [--merge tinylane.json -o out.json]   离线解析订阅（不打印密码）
  tinylane update-rules [-i tinylane.json] [--force]
  tinylane conns [-i tinylane.json] [关键词]     查看当前连接（经 clash_api）
  tinylane select [-i ...] <组> [节点]           查看/切换组的当前节点
  tinylane mode [-i ...] [rule|global|direct]    查看/切换运行模式（不重启）
  tinylane daemon [-i tinylane.json] [-c config.json] [-D dir]   守护进程：内核看护 + 面板 + 看门狗 + 订阅（procd 用这个）
  tinylane passwd [-i tinylane.json] [--random | --hash H]      设置面板密码（只存哈希）
  tinylane group-type [-i tinylane.json] <组> select|failover    设置组类型（failover = 看门狗自动切换）
  tinylane version
`, tlVersion, C.Version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args, false)
	case "check":
		err = cmdRun(args, true)
	case "gen":
		err = cmdGen(args)
	case "import-clash":
		err = cmdImport(args)
	case "update-rules":
		err = cmdUpdateRules(args)
	case "conns":
		err = cmdConns(args)
	case "select":
		err = cmdSelect(args)
	case "mode":
		err = cmdMode(args)
	case "daemon":
		err = cmdDaemon(args)
	case "passwd":
		err = cmdPasswd(args)
	case "group-type":
		err = cmdGroupType(args)
	case "config-set":
		err = cmdConfigSet(args)
	case "migrate":
		err = cmdMigrate(args)
	case "members":
		err = cmdMembers(args)
	case "parse-sub":
		err = cmdParseSub(args)
	case "version", "-v", "--version":
		fmt.Printf("tinylane %s, sing-box %s\n", tlVersion, C.Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}

func readSB(ctx context.Context, path string) (option.Options, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return option.Options{}, err
	}
	return sbjson.UnmarshalExtendedContext[option.Options](ctx, data)
}

var rdnsOnce sync.Once

func cmdRun(args []string, checkOnly bool) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfg := fs.String("c", "/var/run/tinylane/config.json", "sing-box 配置")
	dir := fs.String("D", "", "工作目录")
	fs.Parse(args)
	if *dir != "" {
		os.MkdirAll(*dir, 0o700)
		if err := os.Chdir(*dir); err != nil {
			return err
		}
	}
	baseCtx := include.Context(context.Background())
	for {
		opts, err := readSB(baseCtx, *cfg)
		if err != nil {
			return fmt.Errorf("解析配置: %w", err)
		}
		if opts.Log == nil {
			opts.Log = &option.LogOptions{}
		}
		opts.Log.DisableColor = true // procd → logd，不要 ANSI 颜色
		ctx, cancel := context.WithCancel(service.ExtendContext(baseCtx))
		instance, err := box.New(box.Options{Context: ctx, Options: opts})
		if err != nil {
			cancel()
			return err
		}
		if checkOnly {
			instance.Close()
			cancel()
			fmt.Println("配置检查通过")
			return nil
		}
		// 256 MB 路由器：更积极地 GC
		runtimeDebug.SetGCPercent(50)
		startMemLimitWatch(filepath.Dir(*cfg)) // M9：上限来自设置（runDir/memlimit），缺省 40 MB
		rdnsOnce.Do(func() { startRdns() }) // M6d：DNS 反查表（SIGHUP 重载时保留）
		if err := instance.Start(); err != nil {
			instance.Close()
			cancel()
			return fmt.Errorf("启动失败: %w", err)
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		s := <-sig
		signal.Stop(sig)
		done := make(chan struct{})
		go func() { instance.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			fmt.Fprintln(os.Stderr, "关闭超时，强制退出")
			os.Exit(1)
		}
		cancel()
		if s != syscall.SIGHUP {
			return nil
		}
		fmt.Fprintln(os.Stderr, "收到 SIGHUP，重新加载配置")
	}
}

func cmdGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	out := fs.String("o", "/var/run/tinylane/config.json", "生成的 sing-box 配置")
	nft := fs.String("nft", "", "生成的 nftables 规则文件（空 = 不写）")
	env := fs.String("env", "", "给 shell 脚本用的变量文件（空 = 不写）")
	noCheck := fs.Bool("no-check", false, "不调用 sing-box 解析校验")
	fs.Parse(args)
	c, err := loadConfig(*in)
	if err != nil {
		return err
	}
	if c.ClashAPI.Secret == "" {
		// 首次生成：随机密钥写回配置（只此一次）
		c.ClashAPI.Secret = randomSecret()
		if err := persistSecret(*in, c.ClashAPI.Secret); err != nil {
			return fmt.Errorf("写回 clash_api.secret: %w", err)
		}
		fmt.Fprintln(os.Stderr, "已生成 clash_api.secret 并写回", *in)
	}
	sb, err := buildSingBox(c)
	if err != nil {
		return err
	}
	data := marshal(sb)
	if !*noCheck {
		if err := parseCheckSB(data); err != nil {
			return fmt.Errorf("生成的配置 sing-box 解析不通过: %w", err)
		}
	}
	if err := writeFileAtomic(*out, data, 0o600); err != nil {
		return err
	}
	if *nft != "" {
		if err := writeFileAtomic(*nft, []byte(buildNft(c)), 0o600); err != nil {
			return err
		}
	}
	if *env != "" {
		if err := writeFileAtomic(*env, []byte(buildEnv(c)), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("已生成 %s（节点 %d，组 %d，自定义规则 %d，模式 %s，总开关 %v）\n", *out, len(c.Nodes), len(c.Groups), len(c.Rules), c.Mode, c.Enabled)
	return nil
}

// 只改 clash_api.secret，其他字段原样保留
func persistSecret(path, secret string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	ca, _ := m["clash_api"].(map[string]any)
	if ca == nil {
		ca = map[string]any{}
	}
	ca["secret"] = secret
	m["clash_api"] = ca
	return writeFileAtomic(path, marshal(m), 0o600)
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import-clash", flag.ExitOnError)
	f := fs.String("f", "", "Clash YAML 文件")
	merge := fs.String("merge", "", "合并进这个 tinylane.json（替换 source=clash 的节点，保留手动节点）")
	out := fs.String("o", "", "输出文件（默认：--merge 时写回该文件，否则 stdout）")
	fs.Parse(args)
	if *f == "" {
		return fmt.Errorf("缺少 -f")
	}
	nodes, warns, err := importClash(*f)
	if err != nil {
		return err
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "警告：", w)
	}
	for _, n := range nodes {
		s, _ := n.Outbound["server"].(string)
		_ = s
		fmt.Fprintf(os.Stderr, "  %-34s %-11s\n", n.Name, n.Type())
	}
	var data []byte
	target := *out
	if *merge != "" {
		raw, err := os.ReadFile(*merge)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		var old []Node
		if b, err := json.Marshal(m["nodes"]); err == nil {
			json.Unmarshal(b, &old)
		}
		m["nodes"] = mergeNodes(old, nodes)
		data = marshal(m)
		if target == "" {
			target = *merge
		}
	} else {
		data = marshal(nodes)
	}
	if target == "" {
		os.Stdout.Write(data)
		return nil
	}
	fmt.Fprintf(os.Stderr, "导入 %d 个节点 → %s\n", len(nodes), target)
	return writeFileAtomic(target, data, 0o600)
}

func cmdUpdateRules(args []string) error {
	fs := flag.NewFlagSet("update-rules", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	force := fs.Bool("force", false, "不管是否过期都重新下载")
	fs.Parse(args)
	c, err := loadConfig(*in)
	if err != nil {
		return err
	}
	return updateRules(c, *force)
}

func parseCheckSB(data []byte) error {
	ctx := include.Context(context.Background())
	_, err := sbjson.UnmarshalExtendedContext[option.Options](ctx, data)
	return err
}
