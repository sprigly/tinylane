package main

// tinylane daemon：procd 只管这个进程。它
//   1. 把内核（tinylane run，子进程）拉起并看护：崩溃自动重启；2 分钟内崩 3 次 → 撤 nft + DNS，局域网回到直连（自保），
//      内核稳定 60 s 后再恢复透明代理；clash_api 连续 1 分钟无响应 → 杀掉重启。
//   2. 跑面板（HTTP，LAN IP）+ 看门狗（自动切换）+ 订阅定时更新。
//   3. 改配置走 applyEdit：校验（含组规则，fail-closed）→ sing-box check → 必要时重载 nft → SIGHUP 内核热重载（不 stop/start，不撤 nft）。
// 内核和面板分进程：内核 Go panic 不会带走面板/看门狗，自保逻辑才可靠。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var cst = time.FixedZone("CST", 8*3600) // 路由器通常没有 zoneinfo；上海时间写死

type Daemon struct {
	cfgPath, sbPath, workDir, runDir, nftScript, leases, self string
	shadowPath, ubusPath, sqmScript                           string
	noPanel, noWatchdog                                       bool

	mu    sync.Mutex // 配置修改串行
	sqmMu sync.Mutex
	cfg   atomic.Pointer[Config]
	api   atomic.Pointer[apiClient]

	coreMu       sync.Mutex
	core         *exec.Cmd
	coreStart    time.Time
	crashes      []time.Time
	reloadAt     time.Time // 最近一次 SIGHUP 热重载
	expectExit   atomic.Bool
	stopping     atomic.Bool
	fallback     atomic.Bool
	coreUp       atomic.Bool
	coreRestarts atomic.Int64

	events      *EventLog
	traffic     *TrafficRing
	memh        *MemHist
	wd          *Watchdog
	subs        *SubManager
	panel       *Panel
	hist        *History
	rsm         *RuleSetManager
	imp         *ImportManager
	acct        *Acct
	kern        *KernConns
	egress      *EgressMgr      // M7
	cerr        *coreErrCounter // M10 内核超时报错计数
	upd         *Updater        // M11 检查更新 / 一键更新
	coreErrOnce sync.Once
	raw         RawPending
	gjob        guestJob
	ctx         context.Context
	cancel      context.CancelFunc
}

func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	d := &Daemon{}
	fs.StringVar(&d.cfgPath, "i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	fs.StringVar(&d.sbPath, "c", "/var/run/tinylane/config.json", "生成的 sing-box 配置")
	fs.StringVar(&d.workDir, "D", "/tmp/tinylane", "内核工作目录")
	fs.StringVar(&d.runDir, "run-dir", "/var/run/tinylane", "运行时目录（nft/env/pid）")
	fs.StringVar(&d.nftScript, "nft-script", "/usr/libexec/tinylane/tinylane-nft.sh", "nft/DNS 脚本（up|down|dns-on|dns-off）")
	fs.StringVar(&d.sqmScript, "sqm-script", "/usr/libexec/tinylane/tinylane-sqm.sh", "WAN 整形脚本（up|down|status|measure）")
	fs.StringVar(&d.leases, "leases", "/tmp/dhcp.leases", "dnsmasq 租约文件")
	fs.StringVar(&d.shadowPath, "shadow", "/etc/shadow", "面板兜底登录校验 root 密码用的 shadow 文件")
	fs.StringVar(&d.ubusPath, "ubus", "ubus", "ubus 命令（校验 LuCI 会话）")
	fs.BoolVar(&d.noPanel, "no-panel", false, "不启动面板")
	fs.BoolVar(&d.noWatchdog, "no-watchdog", false, "不启动看门狗")
	fs.Parse(args)
	runtimeDebug.SetGCPercent(50)
	runtimeDebug.SetMemoryLimit(24 << 20)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	d.self = self
	os.MkdirAll(d.runDir, 0o700)
	os.MkdirAll(d.workDir, 0o700)
	d.events = newEventLog(filepath.Join(d.workDir, "events.log"))
	d.memh = &MemHist{}
	d.traffic = &TrafficRing{mh: d.memh}
	d.ctx, d.cancel = context.WithCancel(context.Background())

	migNotes := d.migrateOnStart()
	c, err := loadConfig(d.cfgPath)
	if err != nil {
		return err
	}
	if c.ClashAPI.Secret == "" {
		return fmt.Errorf("clash_api.secret 为空：先运行 tinylane gen")
	}
	if err := d.writeGenerated(c, true); err != nil {
		return err
	}
	d.setConfig(c)
	go d.applySQM(c, true)
	d.killStaleCore()

	go d.memHistLoop()
	go d.superviseCore()
	go d.healthLoop()
	go d.traffic.run(d.ctx, d)
	d.hist = newHistory(d.workDir)
	go d.historyLoop(d.hist)
	d.subs = newSubManager(d)
	go d.subs.scheduler()
	d.rsm = newRuleSetManager(d)
	go d.rsm.scheduler()
	d.imp = newImportManager()
	d.acct = newAcct(d)
	go d.acct.loop()
	go d.newDeviceLoop()
	go d.staleConnLoop()
	d.kern = newKernConns(d)
	go d.kern.loop()
	if !d.noWatchdog {
		d.wd = newWatchdog(d)
		go d.wd.run()
	}
	d.egress = newEgressMgr(d)
	d.egress.sync(c)
	go d.egress.loop()
	if !d.noPanel && !c.Panel.Disabled {
		d.panel = newPanel(d)
		go d.panel.serve()
	}
	d.events.add("system", "TinyLane 守护进程启动（"+tlVersion+"）")
	d.upd = newUpdater(d)
	go d.upd.loop(d.ctx)
	for _, n := range migNotes {
		d.events.add("config", "配置迁移（M7）："+n)
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			if err := d.reloadFromDisk(); err != nil {
				d.events.add("error", "重新加载失败："+err.Error())
			}
			continue
		}
		break
	}
	d.stopping.Store(true)
	d.cancel()
	d.kern.restoreAcct() // M6d：恢复 nf_conntrack_acct 原值
	d.stopCore()
	return nil
}

func (d *Daemon) setConfig(c *Config) {
	d.cfg.Store(c)
	if d.egress != nil {
		d.egress.sync(c)
	}
	d.api.Store(&apiClient{base: "http://" + c.ClashAPI.Listen, secret: c.ClashAPI.Secret, hc: clashHTTP})
}

func (d *Daemon) conf() *Config     { return d.cfg.Load() }
func (d *Daemon) clash() *apiClient { return d.api.Load() }

// ---------------- 生成文件 ----------------

func (d *Daemon) nftPath() string { return filepath.Join(d.runDir, "tinylane.nft") }
func (d *Daemon) envPath() string { return filepath.Join(d.runDir, "env") }

// writeGenerated 写 config.json / nft / env。startup=true 时不比较、直接写。
func (d *Daemon) writeGenerated(c *Config, startup bool) error {
	sb, err := genSB(c)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(d.sbPath, sb, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(d.nftPath(), []byte(buildNft(c)), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(d.envPath(), []byte(buildEnv(c)), 0o600)
}

func genSB(c *Config) ([]byte, error) {
	sb, err := buildSingBox(c)
	if err != nil {
		return nil, err
	}
	data := marshal(sb)
	if err := parseCheckSB(data); err != nil {
		return nil, fmt.Errorf("生成的配置 sing-box 解析不通过: %w", err)
	}
	return data, nil
}

// ---------------- 内核看护 ----------------

func (d *Daemon) corePidFile() string { return filepath.Join(d.runDir, "core.pid") }

func (d *Daemon) killStaleCore() {
	b, err := os.ReadFile(d.corePidFile())
	if err != nil {
		return
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		return
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if bytes.Contains(cmdline, []byte("tinylane")) && bytes.Contains(cmdline, []byte("run")) {
		syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 50; i++ {
			if syscall.Kill(pid, 0) != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	}
}

// M7b：内存紧张时让内核（-800）和守护进程（-500）排在 curl 等外部进程之后被杀；不设 -1000（仍可被杀，防死锁）。
const (
	coreOOMAdj   = -800
	daemonOOMAdj = -500
)

func setOOMAdj(pid, v int) {
	p := "/proc/self/oom_score_adj"
	if pid > 0 {
		p = fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	}
	if err := os.WriteFile(p, []byte(strconv.Itoa(v)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "oom_score_adj %s: %v\n", p, err)
	}
}

// memAvailableMB：/proc/meminfo 的 MemAvailable（MB），读不到返回 -1。
func memAvailableMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return -1
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "MemAvailable:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				kb, _ := strconv.Atoi(f[1])
				return kb / 1024
			}
		}
	}
	return -1
}

const measureMinAvailMB = 40

func (d *Daemon) superviseCore() {
	setOOMAdj(0, daemonOOMAdj)
	backoff := time.Second
	for !d.stopping.Load() {
		d.writeMemLimit(d.conf())
		cmd := exec.Command(d.self, "run", "-c", d.sbPath, "-D", d.workDir)
		// M10：内核输出经旁路原样转发（logread 里照旧是 daemon.err），同时数超时类报错
		cmd.Stdout, cmd.Stderr = &lineTap{out: os.Stdout, cnt: d.coreErrs()}, &lineTap{out: os.Stderr, cnt: d.coreErrs()}
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		if err := cmd.Start(); err != nil {
			d.events.add("error", "内核启动失败："+err.Error())
			time.Sleep(5 * time.Second)
			continue
		}
		d.coreMu.Lock()
		d.core, d.coreStart = cmd, time.Now()
		d.coreMu.Unlock()
		os.WriteFile(d.corePidFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		setOOMAdj(cmd.Process.Pid, coreOOMAdj) // M7b：内存耗尽时内核最后才被杀
		err := cmd.Wait()
		d.coreUp.Store(false)
		d.coreMu.Lock()
		d.core = nil
		up := time.Since(d.coreStart)
		reloadRecent := !d.reloadAt.IsZero() && time.Since(d.reloadAt) < 20*time.Second
		d.coreMu.Unlock()
		if d.stopping.Load() {
			return
		}
		if d.expectExit.Swap(false) {
			backoff = time.Second
			continue
		}
		code := "?"
		if err != nil {
			code = err.Error()
		}
		d.coreRestarts.Add(1)
		d.events.add("error", fmt.Sprintf("内核退出（%s，运行了 %s）", code, up.Round(time.Second)))
		if reloadRecent {
			d.restorePrevSB()
		}
		now := time.Now()
		d.coreMu.Lock()
		d.crashes = append(d.crashes, now)
		var keep []time.Time
		for _, t := range d.crashes {
			if now.Sub(t) < 2*time.Minute {
				keep = append(keep, t)
			}
		}
		d.crashes = keep
		n := len(keep)
		d.coreMu.Unlock()
		if n >= 3 && !d.fallback.Load() {
			d.enterFallback(fmt.Sprintf("内核 2 分钟内崩溃 %d 次", n))
		}
		if up > 2*time.Minute {
			backoff = time.Second
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (d *Daemon) corePid() int {
	d.coreMu.Lock()
	defer d.coreMu.Unlock()
	if d.core != nil && d.core.Process != nil {
		return d.core.Process.Pid
	}
	return 0
}

func (d *Daemon) stopCore() {
	pid := d.corePid()
	if pid == 0 {
		return
	}
	syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
}

// 健康检查：每 15 s 问 clash_api /version；连续 4 次失败（约 1 分钟）且内核已跑 30 s → 杀掉（计入崩溃）。
// 内核稳定 60 s 且处于自保状态 → 恢复透明代理。
func (d *Daemon) healthLoop() {
	fails := 0
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	first := time.NewTimer(2 * time.Second)
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-first.C:
		case <-t.C:
		}
		pid := d.corePid()
		if pid == 0 {
			continue
		}
		var v struct{ Version string }
		err := d.clash().doCtx(d.ctx, 3*time.Second, "GET", "/version", nil, &v)
		if err == nil {
			fails = 0
			d.coreUp.Store(true)
			d.coreMu.Lock()
			stable := time.Since(d.coreStart) > 60*time.Second
			d.coreMu.Unlock()
			if stable && d.fallback.Load() {
				d.leaveFallback()
			}
			d.syncMode()
			continue
		}
		d.coreUp.Store(false)
		d.coreMu.Lock()
		age := time.Since(d.coreStart)
		d.coreMu.Unlock()
		if age < 30*time.Second {
			continue
		}
		fails++
		if fails >= 4 {
			d.events.add("error", "clash_api 连续 1 分钟无响应，强制重启内核")
			syscall.Kill(pid, syscall.SIGKILL)
			fails = 0
		}
	}
}

// applySQM：写 sqm.env；变了（或 startup）就执行 tinylane-sqm.sh up（ENABLED=0 时脚本自己撤销）。
// 只碰 WAN qdisc，失败不影响代理；脚本不存在（沙盒 / 旧安装）就跳过。
func (d *Daemon) applySQM(c *Config, startup bool) {
	d.sqmMu.Lock()
	defer d.sqmMu.Unlock()
	if _, err := os.Stat(d.sqmScript); err != nil {
		return
	}
	p := filepath.Join(d.runDir, "sqm.env")
	env := []byte(buildSQMEnv(c))
	old, _ := os.ReadFile(p)
	if !startup && bytes.Equal(env, old) {
		return
	}
	if !startup && len(old) == 0 && !c.SQM.Enabled {
		writeFileAtomic(p, env, 0o600)
		return
	}
	writeFileAtomic(p, env, 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.sqmScript, "up")
	cmd.Env = append(os.Environ(), "RUN="+d.runDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		d.events.add("error", "WAN 整形设置失败："+strings.TrimSpace(string(out)))
		return
	}
	if !startup || c.SQM.Enabled {
		q := c.SQM
		if q.Enabled {
			d.events.add("config", fmt.Sprintf("WAN 整形已启用：↓%d/%d/%d ↑%d/%d/%d Mbit", q.DLMin, q.DLBase, q.DLMax, q.ULMin, q.ULBase, q.ULMax))
		} else {
			d.events.add("config", "WAN 整形已关闭")
		}
	}
}

// sqmMeasure：暂停整形测一次上下行（约 30 s），返回 Mbit。
func (d *Daemon) sqmMeasure() (map[string]any, error) {
	d.sqmMu.Lock()
	defer d.sqmMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if a := memAvailableMB(); a >= 0 && a < measureMinAvailMB {
		return nil, fmt.Errorf("路由器可用内存只有 %d MB（低于 %d MB），为保护代理内核已拒绝测速，请稍后再试", a, measureMinAvailMB)
	}
	cmd := exec.CommandContext(ctx, d.sqmScript, "measure")
	cmd.Env = append(os.Environ(), "RUN="+d.runDir, fmt.Sprintf("MIN_AVAIL_MB=%d", measureMinAvailMB))
	out, err := cmd.Output()
	var r struct {
		Down  int    `json:"down_mbit"`
		Up    int    `json:"up_mbit"`
		Error string `json:"error"`
		Avail int    `json:"avail_mb"`
	}
	jerr := json.Unmarshal(lastLine(out), &r)
	if jerr == nil && r.Error == "low_mem" {
		return nil, fmt.Errorf("路由器可用内存只有 %d MB（低于 %d MB），为保护代理内核已拒绝测速，请稍后再试", r.Avail, measureMinAvailMB)
	}
	if err != nil {
		return nil, fmt.Errorf("测速失败：%v", err)
	}
	if jerr != nil || r.Down <= 0 {
		return nil, fmt.Errorf("测速结果无效")
	}
	sug := func(m int, f float64) int {
		v := int(float64(m)*f + 0.5)
		if v < 1 {
			v = 1
		}
		return v
	}
	return map[string]any{"down_mbit": r.Down, "up_mbit": r.Up,
		"suggest": map[string]int{"dl_min": sug(r.Down, .4), "dl_base": sug(r.Down, .85), "dl_max": sug(r.Down, .95),
			"ul_min": sug(r.Up, .3), "ul_base": sug(r.Up, .85), "ul_max": sug(r.Up, .95)}}, nil
}

func lastLine(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// syncMode：模式被外部切换（tinylane mode / clash 面板直接 PATCH）时，落盘并重载 nft（国内 IP 绕过只在规则模式下开）。
func (d *Daemon) syncMode() {
	var cfgs struct{ Mode string }
	if err := d.clash().doCtx(d.ctx, 3*time.Second, "GET", "/configs", nil, &cfgs); err != nil {
		return
	}
	mode := strings.ToLower(cfgs.Mode)
	if mode != "rule" && mode != "global" && mode != "direct" {
		return
	}
	if c := d.conf(); c == nil || c.Mode == mode {
		return
	}
	if err := d.applyEdit(applyOpts{hot: true, desc: "运行模式（外部切换）→ " + modeCN(mode)}, func(m map[string]any) error { m["mode"] = mode; return nil }); err != nil && err != errNoChange {
		d.events.add("error", "同步运行模式失败："+err.Error())
	}
}

// syncNft：重新生成 nft（如规则集更新后 cn4 变了），有变化且代理开着就重载。
func (d *Daemon) syncNft() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.conf()
	nftText := []byte(buildNft(c))
	oldNft, _ := os.ReadFile(d.nftPath())
	if bytes.Equal(nftText, oldNft) {
		return nil
	}
	writeFileAtomic(d.nftPath()+".prev", oldNft, 0o600)
	if err := writeFileAtomic(d.nftPath(), nftText, 0o600); err != nil {
		return err
	}
	if c.Enabled && !d.fallback.Load() {
		if err := d.runScript("up"); err != nil {
			writeFileAtomic(d.nftPath(), oldNft, 0o600)
			d.runScript("up")
			return fmt.Errorf("nft 重载失败，已回滚：%v", err)
		}
	}
	return nil
}

// waitCoreUp 轮询 clash_api，最多 timeout。
func (d *Daemon) waitCoreUp(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var v struct{ Version string }
		if d.clash().doCtx(d.ctx, 2*time.Second, "GET", "/version", nil, &v) == nil {
			d.coreUp.Store(true)
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func (d *Daemon) enterFallback(why string) {
	d.fallback.Store(true)
	d.runScript("down")
	d.runScript("dns-off")
	d.events.add("error", why+"：已撤销透明代理和 DNS 接管，局域网临时直连上网；内核恢复稳定后自动重新启用")
}

func (d *Daemon) leaveFallback() {
	d.fallback.Store(false)
	if d.conf().Enabled {
		if err := d.runScript("up"); err != nil {
			d.events.add("error", "恢复透明代理失败："+err.Error())
			d.fallback.Store(true)
			return
		}
		d.runScript("dns-on")
	}
	d.events.add("system", "内核已稳定运行 60 秒，透明代理已恢复")
}

func (d *Daemon) runScript(arg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.nftScript, arg)
	cmd.Env = append(os.Environ(), "RUN="+d.runDir, "NFT_FILE="+d.nftPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", filepath.Base(d.nftScript), arg, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------- 配置修改 ----------------

var errNoChange = errors.New("没有变化")

type applyOpts struct {
	hot  bool   // 已经经 clash_api 热生效（如模式），只落盘，不重载内核
	desc string // 事件描述（空 = 不记）
}

// applyEdit：读原始 JSON（保留未知字段）→ mutate → 校验（loadConfig，含组规则）→ 生成 + sing-box check
// → 落盘 → nft 有变化才重载 → sing-box JSON 有变化才 SIGHUP 内核热重载。任何一步失败都回滚到原文件。
func (d *Daemon) applyEdit(o applyOpts, mutate func(m map[string]any) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	orig, err := os.ReadFile(d.cfgPath)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(orig, &m); err != nil {
		return err
	}
	if err := mutate(m); err != nil {
		return err
	}
	newRaw := marshal(m)
	tmp := d.cfgPath + ".new"
	if err := writeFileAtomic(tmp, newRaw, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	c, err := loadConfig(tmp)
	if err != nil {
		return err
	}
	if c.ClashAPI.Secret == "" {
		return fmt.Errorf("clash_api.secret 不能为空")
	}
	sbData, err := genSB(c)
	if err != nil {
		return err
	}
	oldSB, _ := os.ReadFile(d.sbPath)
	needReload := !bytes.Equal(sbData, oldSB) && !o.hot
	if needReload {
		if err := d.checkSB(sbData); err != nil {
			return err
		}
	}
	nftText := []byte(buildNft(c))
	oldNft, _ := os.ReadFile(d.nftPath())
	nftChanged := !bytes.Equal(nftText, oldNft)
	old := d.conf()

	// 落盘
	if err := writeFileAtomic(d.cfgPath+".prev", orig, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(d.cfgPath, newRaw, 0o600); err != nil {
		return err
	}
	rollbackCfg := func() {
		writeFileAtomic(d.cfgPath, orig, 0o600)
	}
	writeFileAtomic(d.envPath(), []byte(buildEnv(c)), 0o600)
	if nftChanged {
		writeFileAtomic(d.nftPath()+".prev", oldNft, 0o600)
		if err := writeFileAtomic(d.nftPath(), nftText, 0o600); err != nil {
			rollbackCfg()
			return err
		}
		if c.Enabled && !d.fallback.Load() {
			if err := d.runScript("up"); err != nil {
				writeFileAtomic(d.nftPath(), oldNft, 0o600)
				d.runScript("up")
				rollbackCfg()
				return fmt.Errorf("nft 重载失败，已回滚：%v", err)
			}
		}
	}
	if needReload || o.hot {
		writeFileAtomic(d.sbPath+".prev", oldSB, 0o600)
		if err := writeFileAtomic(d.sbPath, sbData, 0o600); err != nil {
			rollbackCfg()
			return err
		}
	}
	d.setConfig(c)
	go d.applySQM(c, false)
	if needReload {
		if err := d.hotReload(); err != nil {
			rollbackCfg()
			d.setConfig(old)
			if nftChanged {
				writeFileAtomic(d.nftPath(), oldNft, 0o600)
				if old.Enabled && !d.fallback.Load() {
					d.runScript("up")
				}
			}
			return err
		}
	}
	if o.desc != "" {
		d.events.add("config", o.desc)
	}
	return nil
}

// checkSB：子进程跑 tinylane check（完整 box.New，不监听端口），确保内核真能加载。
func (d *Daemon) checkSB(data []byte) error {
	tmp := filepath.Join(d.runDir, "config.check.json")
	if err := writeFileAtomic(tmp, data, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.self, "check", "-c", tmp)
	cmd.Dir = d.workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box 校验不通过：%s", lastLines(string(out), 3))
	}
	return nil
}

// hotReload：SIGHUP 内核（进程不退出，nft/DNS 不动，LAN 不断，只是现有连接重建）。
func (d *Daemon) hotReload() error {
	pid := d.corePid()
	if pid == 0 {
		return nil // 内核没在跑（自保/重启中），下次启动自然用新配置
	}
	d.coreMu.Lock()
	d.reloadAt = time.Now()
	d.coreMu.Unlock()
	d.coreUp.Store(false)
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	if !d.waitCoreUp(15 * time.Second) {
		d.restorePrevSB()
		return fmt.Errorf("内核热重载后 15 秒内没有恢复，已回滚到上一份配置")
	}
	return nil
}

func (d *Daemon) restorePrevSB() {
	prev, err := os.ReadFile(d.sbPath + ".prev")
	if err != nil || len(prev) == 0 {
		return
	}
	cur, _ := os.ReadFile(d.sbPath)
	if bytes.Equal(cur, prev) {
		return
	}
	writeFileAtomic(d.sbPath, prev, 0o600)
	d.events.add("error", "新配置让内核起不来，已恢复上一份 sing-box 配置")
	if pid := d.corePid(); pid != 0 {
		syscall.Kill(pid, syscall.SIGHUP)
	}
}

// reloadFromDisk：SIGHUP 守护进程 = 有人手改了 tinylane.json 或规则集更新了：重新生成并热重载。
func (d *Daemon) reloadFromDisk() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, err := loadConfig(d.cfgPath)
	if err != nil {
		return err
	}
	sbData, err := genSB(c)
	if err != nil {
		return err
	}
	if err := d.checkSB(sbData); err != nil {
		return err
	}
	oldSB, _ := os.ReadFile(d.sbPath)
	writeFileAtomic(d.sbPath+".prev", oldSB, 0o600)
	writeFileAtomic(d.sbPath, sbData, 0o600)
	nftText := []byte(buildNft(c))
	oldNft, _ := os.ReadFile(d.nftPath())
	writeFileAtomic(d.envPath(), []byte(buildEnv(c)), 0o600)
	if !bytes.Equal(nftText, oldNft) {
		writeFileAtomic(d.nftPath(), nftText, 0o600)
		if c.Enabled && !d.fallback.Load() {
			if err := d.runScript("up"); err != nil {
				return err
			}
		}
	}
	d.setConfig(c)
	go d.applySQM(c, false)
	if err := d.hotReload(); err != nil {
		return err
	}
	d.events.add("config", "已重新加载配置（SIGHUP）")
	return nil
}

// setEnabled：总开关。关 = 撤 nft + DNS（内核继续跑，面板可用）；开 = 加回。
func (d *Daemon) setEnabled(on bool) error {
	err := d.applyEdit(applyOpts{hot: true}, func(m map[string]any) error { m["enabled"] = on; return nil })
	if err != nil {
		return err
	}
	if d.fallback.Load() {
		return nil
	}
	if on {
		if err := d.runScript("up"); err != nil {
			return err
		}
		d.runScript("dns-on")
		d.events.add("config", "代理已启用")
	} else {
		d.runScript("down")
		d.runScript("dns-off")
		d.events.add("config", "代理已停用：全部直连")
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// ---------------- 事件日志 ----------------

type Event struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"` // switch | error | config | sub | system
	Msg  string `json:"msg"`
}

type EventLog struct {
	mu   sync.Mutex
	list []Event
	path string
}

func newEventLog(path string) *EventLog {
	l := &EventLog{path: path}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var e Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				l.list = append(l.list, e)
			}
		}
		f.Close()
		if len(l.list) > 300 {
			l.list = l.list[len(l.list)-300:]
		}
	}
	return l
}

func (l *EventLog) add(kind, msg string) {
	e := Event{T: time.Now().Unix(), Kind: kind, Msg: msg}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", kind, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, e)
	if len(l.list) > 300 {
		l.list = l.list[len(l.list)-300:]
	}
	// tmpfs，上限 128 KB：超了就只留内存里的 300 条
	if st, err := os.Stat(l.path); err == nil && st.Size() > 128<<10 {
		var b bytes.Buffer
		for _, x := range l.list {
			j, _ := json.Marshal(x)
			b.Write(j)
			b.WriteByte('\n')
		}
		writeFileAtomic(l.path, b.Bytes(), 0o600)
		return
	}
	if f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		j, _ := json.Marshal(e)
		f.Write(append(j, '\n'))
		f.Close()
	}
}

func (l *EventLog) recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []Event{}
	for i := len(l.list) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, l.list[i])
	}
	return out
}

// ---------------- 实时流量（clash_api /traffic 长连接，每秒一条）----------------

type TrafficRing struct {
	mu   sync.Mutex
	pts  [][2]int64 // up, down（字节/秒）
	last time.Time
	mh   *MemHist
}

func (t *TrafficRing) push(up, down int64) {
	t.mu.Lock()
	t.pts = append(t.pts, [2]int64{up, down})
	if len(t.pts) > 90 {
		t.pts = t.pts[len(t.pts)-90:]
	}
	t.last = time.Now()
	t.mu.Unlock()
	if t.mh != nil {
		t.mh.addTraffic(up, down)
	}
}

func (t *TrafficRing) snapshot() ([][2]int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][2]int64, len(t.pts))
	copy(out, t.pts)
	return out, time.Since(t.last) < 5*time.Second
}

func (t *TrafficRing) run(ctx context.Context, d *Daemon) {
	for ctx.Err() == nil {
		a := d.clash()
		req, _ := newReq(ctx, a, "GET", "/traffic", nil)
		resp, err := streamHTTP.Do(req)
		if err == nil {
			dec := json.NewDecoder(resp.Body)
			for {
				var p struct{ Up, Down int64 }
				if err := dec.Decode(&p); err != nil {
					break
				}
				t.push(p.Up, p.Down)
			}
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// ---------------- 内存 ----------------

func procRSS(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				v, _ := strconv.ParseInt(f[1], 10, 64)
				return v * 1024
			}
		}
	}
	return 0
}

// migrateOnStart：M6d 及更早的配置（禁止出口 / 出口标签）→ M7 通用组规则。只在需要时写一次，原文件存 .prev。
func (d *Daemon) migrateOnStart() []string {
	raw, err := os.ReadFile(d.cfgPath)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	changed, notes := migrateM7(m)
	if !changed {
		return nil
	}
	tmp := d.cfgPath + ".m7check"
	data := marshal(m)
	if writeFileAtomic(tmp, data, 0o600) != nil {
		return nil
	}
	defer os.Remove(tmp)
	if _, err := loadConfig(tmp); err != nil {
		return []string{"迁移后校验失败，保持原配置：" + err.Error()}
	}
	if writeFileAtomic(d.cfgPath+".prev", raw, 0o600) != nil || writeFileAtomic(d.cfgPath, data, 0o600) != nil {
		return []string{"迁移写入失败，保持原配置"}
	}
	if len(notes) == 0 {
		notes = []string{"已更新到 M7 格式"}
	}
	return notes
}
