package main

// M11 只测改动：版本比较、签名、空间计算、更新流程（真实辅助脚本 + 假文件系统 + 假 Release 服务器）、
// 自检失败回滚、通过后保留规则、24 小时 / 低内存清理、跳过版本、试运行中断后开机恢复。不连外网。

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestM11VersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.4.5-m10", "0.4.5", -1}, {"0.4.5", "0.4.5-m10", 1}, {"0.4.5-m10", "0.4.5-m9", 1}, {"0.4.5-m10", "0.4.4", 1},
		{"0.4.6", "0.4.5-m11", 1}, {"0.4.10", "0.4.9", 1}, {"v0.4.5", "0.4.5", 0}, {"0.4.5-rc1", "0.4.5-m11", 1},
		{"0.4.5-rc2", "0.4.5-rc10", -1}, {"1.0.0", "0.99.99", 1}, {"0.4.5-m11", "0.4.5-m11", 0}, {"bad", "0.0.1", -1},
	}
	for _, c := range cases {
		if got := cmpVer(c.a, c.b); got != c.want {
			t.Errorf("cmpVer(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	for tag, want := range map[string]bool{"v0.4.6": true, "v1.2.3": true, "v0.4.6-m1": false, "v0.4.6-rc1": false, "0.4.6": false, "v0.4": false} {
		if isFormalTag(tag) != want {
			t.Errorf("isFormalTag(%q) != %v", tag, want)
		}
	}
}

func TestM11Signature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte("abc  tinylane-0.4.6-linux-arm64\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
	if err := verifySums(sums, sig, pub); err != nil {
		t.Fatal("正确签名应通过:", err)
	}
	if verifySums(append([]byte("x"), sums...), sig, pub) == nil {
		t.Fatal("清单被改应失败")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if verifySums(sums, sig, pub2) == nil {
		t.Fatal("别的公钥应失败")
	}
	if verifySums(sums, []byte("not-base64!!"), pub) == nil {
		t.Fatal("格式不对应失败")
	}
	// 内置公钥格式正确
	if len(updPubKey) != ed25519.PublicKeySize {
		t.Fatal("内置公钥长度不对")
	}
}

func TestM11SpacePlan(t *testing.T) {
	MB := int64(1 << 20)
	// 真机数字：闪存剩 29 MB，程序 26 MB → 换版时旧版被删，闪存够
	p := planSpace(spaceIn{FlashFree: 29 * MB, CurBin: 26 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 11 * MB, MemAvail: 75 * MB})
	if p.Mode != "flash" || p.Msg != "" {
		t.Fatalf("闪存够：%+v", p)
	}
	// 闪存只够放新版 → 上一版放内存
	p = planSpace(spaceIn{FlashFree: 5 * MB, CurBin: 26 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 11 * MB, MemAvail: 75 * MB})
	if p.Mode != "mem" || !strings.Contains(p.Msg, "旧版只在内存里临时保留") || p.NeedMem != 61*MB {
		t.Fatalf("放内存：%+v", p)
	}
	// 闪存不够 + 内存也不够 → 拒绝，写明还差多少
	p = planSpace(spaceIn{FlashFree: 5 * MB, CurBin: 26 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 11 * MB, MemAvail: 55 * MB})
	if p.Mode != "none" || p.ShortMB != 6 || !strings.Contains(p.Msg, "还差 6 MB") {
		t.Fatalf("都不够：%+v", p)
	}
	// 闪存够但内存不够（下载前可用 < 新包 + 40 MB）→ 拒绝
	p = planSpace(spaceIn{FlashFree: 29 * MB, CurBin: 26 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 11 * MB, MemAvail: 45 * MB})
	if p.Mode != "none" || p.ShortMB != 5 {
		t.Fatalf("内存不够：%+v", p)
	}
	// 闪存连新版都放不下
	p = planSpace(spaceIn{FlashFree: 0, CurBin: 20 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 9 * MB, MemAvail: 200 * MB})
	if p.Mode != "none" || !strings.Contains(p.Msg, "闪存空间不够放新版") {
		t.Fatalf("闪存放不下新版：%+v", p)
	}
	// 闪存里旧的上一版会被替换，算进可用空间
	p = planSpace(spaceIn{FlashFree: 2 * MB, CurBin: 26 * MB, OldPrev: 11 * MB, NewRaw: 26 * MB, NewGz: 10 * MB, OldGzEst: 11 * MB, MemAvail: 75 * MB})
	if p.Mode != "flash" {
		t.Fatalf("替换旧的上一版后应够：%+v", p)
	}
}

// ---------------- 假环境 ----------------

func fakeELF(ver string) []byte {
	b := make([]byte, 200<<10)
	rand.Read(b)
	copy(b, "\x7fELF")
	m := elfMachine(runtime.GOARCH)
	b[18], b[19] = byte(m), byte(m>>8)
	copy(b[150<<10:], "tinylane version "+ver+"\x00")
	return b
}

func gz(b []byte) []byte {
	var w bytes.Buffer
	zw := gzip.NewWriter(&w)
	zw.Write(b)
	zw.Close()
	return w.Bytes()
}

func hexSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type fakeGH struct {
	srv   *httptest.Server
	mu    sync.Mutex
	rels  map[string][]byte // ver → 原始程序
	priv  ed25519.PrivateKey
	tamp  bool // 篡改 gz
	noTag map[string]bool
	hits  int
}

func newFakeGH(t *testing.T) *fakeGH {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	old := updPubKey
	updPubKey = pub
	t.Cleanup(func() { updPubKey = old })
	f := &fakeGH{rels: map[string][]byte{}, priv: priv, noTag: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGH) rel(ver string) map[string]any {
	raw := f.rels[ver]
	base := "tinylane-" + ver + "-linux-" + runtime.GOARCH
	a := func(n string, size int) map[string]any {
		return map[string]any{"name": n, "size": size, "browser_download_url": f.srv.URL + "/dl/" + ver + "/" + n}
	}
	return map[string]any{"tag_name": "v" + ver, "name": "v" + ver, "body": "更新说明 " + ver, "draft": false, "prerelease": strings.Contains(ver, "-"),
		"published_at": "2026-11-23T00:00:00Z", "html_url": f.srv.URL + "/r/" + ver,
		"assets": []any{a(base, len(raw)), a(base+".gz", len(gz(raw))), a("SHA256SUMS-"+runtime.GOARCH+".txt", 200), a("SHA256SUMS-"+runtime.GOARCH+".txt.sig", 90)}}
}

func (f *fakeGH) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	p := r.URL.Path
	js := func(v any) { json.NewEncoder(w).Encode(v) }
	switch {
	case p == "/repos/sprigly/tinylane/releases/latest":
		var best string
		for v := range f.rels {
			if isFormalTag("v"+v) && (best == "" || cmpVer(v, best) > 0) {
				best = v
			}
		}
		if best == "" {
			http.NotFound(w, r)
			return
		}
		js(f.rel(best))
	case p == "/repos/sprigly/tinylane/releases":
		var l []any
		for v := range f.rels {
			l = append(l, f.rel(v))
		}
		js(l)
	case strings.HasPrefix(p, "/repos/sprigly/tinylane/releases/tags/v"):
		v := strings.TrimPrefix(p, "/repos/sprigly/tinylane/releases/tags/v")
		if _, ok := f.rels[v]; !ok || f.noTag[v] {
			http.NotFound(w, r)
			return
		}
		js(f.rel(v))
	case strings.HasPrefix(p, "/dl/"):
		parts := strings.SplitN(strings.TrimPrefix(p, "/dl/"), "/", 2)
		raw, ok := f.rels[parts[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		base := "tinylane-" + parts[0] + "-linux-" + runtime.GOARCH
		z := gz(raw)
		sums := []byte(fmt.Sprintf("%s  %s\n%s  %s\n", hexSHA(raw), base, hexSHA(z), base+".gz"))
		switch parts[1] {
		case base + ".gz":
			if f.tamp {
				z = append([]byte(nil), z...)
				z[len(z)/2] ^= 0xff
			}
			w.Write(z)
		case base:
			w.Write(raw)
		case "SHA256SUMS-" + runtime.GOARCH + ".txt":
			w.Write(sums)
		case "SHA256SUMS-" + runtime.GOARCH + ".txt.sig":
			w.Write([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, sums)) + "\n"))
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

type fakeEnv struct {
	t      *testing.T
	root   string
	gh     *fakeGH
	mu     sync.Mutex
	cmds   []*exec.Cmd
	spawns []string
	flash  int64
	mem    int64
	boot   string
	now    time.Time
	nowSet bool
}

func newFakeEnv(t *testing.T, curVer string) *fakeEnv {
	e := &fakeEnv{t: t, root: t.TempDir(), gh: newFakeGH(t), flash: 200 << 20, mem: 200 << 20, boot: "boot-1"}
	for _, d := range []string{"/usr/bin", "/etc/tinylane", "/etc/init.d", "/tmp", "/usr/libexec/tinylane"} {
		os.MkdirAll(e.root+d, 0o755)
	}
	os.WriteFile(e.root+"/usr/bin/tinylane", fakeELF(curVer), 0o755)
	os.WriteFile(e.root+"/etc/tinylane/tinylane.json", []byte(`{"ver":"`+curVer+`"}`), 0o600)
	os.WriteFile(e.root+"/etc/init.d/tinylane", []byte("#!/bin/sh\necho \"$1\" >> "+e.root+"/init.log\n"), 0o755)
	t.Cleanup(e.waitHelpers)
	return e
}

func (e *fakeEnv) updater(ver string, fns checkFns) *Updater {
	u := &Updater{root: e.root, api: e.gh.srv.URL, repo: "sprigly/tinylane", arch: runtime.GOARCH, ver: ver,
		pollEvery: 150 * time.Millisecond, checkS: 1, graceS: 20}
	u.init = e.root + "/etc/init.d/tinylane"
	u.cfgP = e.root + "/etc/tinylane/tinylane.json"
	u.now = func() time.Time {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.nowSet {
			return e.now
		}
		return time.Now()
	}
	u.memAvail = func() int64 { e.mu.Lock(); defer e.mu.Unlock(); return e.mem }
	u.flashFree = func() int64 { e.mu.Lock(); defer e.mu.Unlock(); return e.flash }
	u.bootID = func() string { e.mu.Lock(); defer e.mu.Unlock(); return e.boot }
	u.helperUp = func(pid string) bool {
		var n int
		if _, err := fmt.Sscan(pid, &n); err != nil || n <= 0 {
			return false
		}
		if syscall.Kill(n, 0) != nil {
			return false
		}
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", n))
		return !bytes.Contains(b, []byte(") Z ")) // 僵尸进程不算
	}
	u.proxy = func() string { return "" }
	u.fns = fns
	u.spawn = func(mode, marker string) error {
		if err := u.installHelper(); err != nil {
			return err
		}
		sh := "sh" // TL_TEST_SH=/path/busybox-sh + TL_TEST_PATH=busybox 工具目录：用 busybox ash 跑（接近路由器）
		if v := os.Getenv("TL_TEST_SH"); v != "" {
			sh = v
		}
		cmd := exec.Command(sh, u.helperP(), mode, marker)
		cmd.Env = os.Environ()
		if v := os.Getenv("TL_TEST_PATH"); v != "" {
			cmd.Env = append(cmd.Env, "PATH="+v+":"+os.Getenv("PATH"))
		}
		cmd.Env = append(cmd.Env, "TL_UPD_LOG="+e.root+"/helper.log", "TL_UPD_CGROUP=none", "TL_UPD_POLL=0.1", "TL_UPD_DELAY=0")
		if err := cmd.Start(); err != nil {
			return err
		}
		e.mu.Lock()
		e.cmds = append(e.cmds, cmd)
		e.spawns = append(e.spawns, mode)
		e.mu.Unlock()
		return nil
	}
	u.loadState()
	return u
}

func (e *fakeEnv) waitHelpers() {
	e.mu.Lock()
	cs := e.cmds
	e.cmds = nil
	e.mu.Unlock()
	for _, c := range cs {
		done := make(chan struct{})
		go func() { c.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			c.Process.Kill()
			e.t.Error("辅助脚本 30 秒没退出")
		}
	}
}

func okFns() checkFns {
	ok := func(context.Context) error { return nil }
	return checkFns{core: ok, panel: ok, cn: ok, intl: ok, wg: func() (bool, int64, error) { return true, 30, nil }}
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// 旧版守护进程：检查 → 开始更新 → 辅助脚本换版、启动；返回辅助脚本进入「自检」状态时的标记
func (e *fakeEnv) startUpdate(t *testing.T, old *Updater, ver string) kvFile {
	if err := old.Check(context.Background()); err != nil {
		t.Fatal("检查更新:", err)
	}
	if b := old.brief(); b["latest"] != ver || b["popup"] != true || b["dot"] != true {
		t.Fatalf("brief：%v", b)
	}
	if err := old.Start(ver, false); err != nil {
		t.Fatal("开始更新:", err)
	}
	var m kvFile
	waitFor(t, "辅助脚本换版并进入自检", 15*time.Second, func() bool {
		old.mu.Lock()
		j := *old.job
		old.mu.Unlock()
		if j.Phase == "error" {
			t.Fatal("更新出错：", j.Err)
		}
		m = readKV(old.markerP())
		return m != nil && m["STATE"] == "check"
	})
	if got, _ := os.ReadFile(e.root + "/usr/bin/tinylane"); !bytes.Equal(got, e.gh.rels[ver]) {
		t.Fatal("新版没写进 /usr/bin/tinylane")
	}
	if fileExists(m["NEW_GZ"]) {
		t.Fatal("换版后 /tmp 里的新包应删除")
	}
	return m
}

func readFile(p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestM11UpdatePassFlash(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	oldBin := fakeELF("0.4.5-m11")
	os.WriteFile(e.root+"/usr/bin/tinylane", oldBin, 0o755)
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	e.gh.rels["0.4.4"] = fakeELF("0.4.4")
	e.gh.rels["0.5.0-m1"] = fakeELF("0.5.0-m1") // 测试版不该被选中
	old := e.updater("0.4.5-m11", okFns())
	m := e.startUpdate(t, old, "0.4.6")
	if m["WHERE"] != "flash" || !strings.HasPrefix(m["PREV_DIR"], e.root+"/etc/tinylane/prev") {
		t.Fatalf("上一版应在闪存：%v", m)
	}
	if got, _ := gunzipSHA(m["PREV_BIN"]); got != hexSHA(oldBin) {
		t.Fatal("闪存上一版内容不对")
	}
	// 新版守护进程启动
	nu := e.updater("0.4.6", okFns())
	nu.Resume(context.Background())
	waitFor(t, "自检通过", 15*time.Second, func() bool { return readKV(nu.resultP())["RESULT"] == "ok" })
	e.waitHelpers()
	if fileExists(nu.markerP()) {
		t.Fatal("通过后标记应删除")
	}
	if pc := nu.prevCopy(); pc == nil || pc.Where != "flash" || pc.Ver != "0.4.5-m11" {
		t.Fatalf("闪存上一版应保留到下次更新：%+v", pc)
	}
	if s := readFile(e.root + "/init.log"); s != "stop\nstart\n" {
		t.Fatalf("init 调用：%q", s)
	}
	st := nu.Status()
	if st["result"].(map[string]any)["result"] != "ok" || st["result"].(map[string]any)["acked"] != false {
		t.Fatalf("status result：%v", st["result"])
	}
	nu.ack()
	if nu.Status()["result"].(map[string]any)["acked"] != true {
		t.Fatal("ack 后应标记已读")
	}
	if b := nu.brief(); b["result"] != nil || b["busy"] != false {
		t.Fatalf("ack 后 brief：%v", b)
	}
}

func TestM11UpdateFailRollback(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	oldBin, _ := os.ReadFile(e.root + "/usr/bin/tinylane")
	oldCfg := readFile(e.root + "/etc/tinylane/tinylane.json")
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	old := e.updater("0.4.5-m11", okFns())
	e.startUpdate(t, old, "0.4.6")
	// 新版改了配置（如迁移），自检时国外网站不通
	os.WriteFile(e.root+"/etc/tinylane/tinylane.json", []byte(`{"migrated":true}`), 0o600)
	fns := okFns()
	fns.intl = func(context.Context) error { return errors.New("HTTP 502") }
	nu := e.updater("0.4.6", fns)
	nu.Resume(context.Background())
	waitFor(t, "退回旧版", 20*time.Second, func() bool { return readKV(nu.resultP())["RESULT"] == "rolled_back" })
	e.waitHelpers()
	r := readKV(nu.resultP())
	if !strings.Contains(r["REASON"], "国外网站（经代理）") || !strings.Contains(r["REASON"], "HTTP 502") || r["TO"] != "0.4.5-m11" || r["FROM"] != "0.4.6" {
		t.Fatalf("结果：%v", r)
	}
	if got, _ := os.ReadFile(e.root + "/usr/bin/tinylane"); !bytes.Equal(got, oldBin) {
		t.Fatal("旧版程序没写回")
	}
	if readFile(e.root+"/etc/tinylane/tinylane.json") != oldCfg {
		t.Fatal("配置没恢复")
	}
	if fileExists(nu.markerP()) || nu.prevCopy() != nil {
		t.Fatal("退回后标记和上一版应清掉")
	}
	if s := readFile(e.root + "/init.log"); s != "stop\nstart\nstop\nstart\n" {
		t.Fatalf("init 调用：%q", s)
	}
	// 旧版守护进程重新启动后把结果记进事件（只记一次）
	o2 := e.updater("0.4.5-m11", okFns())
	o2.Resume(context.Background())
	if readKV(o2.resultP())["LOGGED"] != "1" {
		t.Fatal("结果应标记已记录")
	}
}

// 新版起不来（不跑自检）→ 辅助脚本超时自己退回
func TestM11DeadmanTimeout(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	oldBin, _ := os.ReadFile(e.root + "/usr/bin/tinylane")
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	old := e.updater("0.4.5-m11", okFns())
	old.graceS = 1
	e.startUpdate(t, old, "0.4.6")
	waitFor(t, "超时退回", 15*time.Second, func() bool { return readKV(old.resultP())["RESULT"] == "rolled_back" })
	e.waitHelpers()
	if !strings.Contains(readKV(old.resultP())["REASON"], "没有完成自检") {
		t.Fatal(readKV(old.resultP()))
	}
	if got, _ := os.ReadFile(e.root + "/usr/bin/tinylane"); !bytes.Equal(got, oldBin) {
		t.Fatal("旧版没写回")
	}
}

func TestM11SignatureBlocksUpdate(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	oldBin, _ := os.ReadFile(e.root + "/usr/bin/tinylane")
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	e.gh.tamp = true
	u := e.updater("0.4.5-m11", okFns())
	u.Check(context.Background())
	if err := u.Start("0.4.6", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "下载校验失败", 10*time.Second, func() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.job.Phase == "error" })
	if !strings.Contains(u.job.Err, "不一致") || fileExists(u.markerP()) || len(e.spawns) != 0 {
		t.Fatalf("应拒绝：%v marker=%v spawns=%v", u.job.Err, fileExists(u.markerP()), e.spawns)
	}
	if got, _ := os.ReadFile(e.root + "/usr/bin/tinylane"); !bytes.Equal(got, oldBin) {
		t.Fatal("旧版不该动")
	}
	// 签名用别的私钥 → 验签失败
	e.gh.tamp = false
	_, e.gh.priv, _ = ed25519.GenerateKey(rand.Reader)
	u.ack()
	u.Start("0.4.6", false)
	waitFor(t, "验签失败", 10*time.Second, func() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.job.Phase == "error" })
	if !strings.Contains(u.job.Err, "签名校验没通过") {
		t.Fatal(u.job.Err)
	}
}

func TestM11MemModeKeepAndCleanup(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	e.flash = 2202009 // 闪存只够放新版（+2 MB 余量）：上一版只能放内存
	old := e.updater("0.4.5-m11", okFns())
	old.Check(context.Background())
	if sp := old.Status()["space"].(spacePlan); sp.Mode != "mem" || !strings.Contains(sp.Msg, "内存") {
		t.Fatalf("应提示放内存：%+v", sp)
	}
	// 自动更新（4:00）在内存模式下不更新
	if err := old.Start("0.4.6", true); err == nil || !strings.Contains(err.Error(), "自动更新跳过") {
		t.Fatal("内存模式不应自动更新：", err)
	}
	m := e.startUpdate(t, old, "0.4.6")
	if m["WHERE"] != "mem" || !strings.HasPrefix(m["PREV_DIR"], e.root+"/tmp/tinylane-prev") {
		t.Fatalf("上一版应在内存：%v", m)
	}
	nu := e.updater("0.4.6", okFns())
	nu.Resume(context.Background())
	waitFor(t, "自检通过", 15*time.Second, func() bool { return readKV(nu.resultP())["RESULT"] == "ok" })
	e.waitHelpers()
	pc := nu.prevCopy()
	if pc == nil || pc.Where != "mem" || pc.Until-time.Now().Unix() < 86000 {
		t.Fatalf("内存上一版应保留 24 小时：%+v", pc)
	}
	nu.st.LastCheck = time.Now().Unix() + 86400*10 // 别触发检查
	// 23 小时后、内存充足：保留
	e.mu.Lock()
	e.now, e.nowSet = time.Now().Add(23*time.Hour), true
	e.mu.Unlock()
	nu.tick(context.Background())
	if nu.prevCopy() == nil {
		t.Fatal("24 小时内不该删")
	}
	// 内存低于 40 MB：提前删
	e.mu.Lock()
	e.mem = 39 << 20
	e.mu.Unlock()
	nu.tick(context.Background())
	if nu.prevCopy() != nil {
		t.Fatal("低内存应提前删")
	}
	// 重新放一份，满 24 小时删
	os.MkdirAll(nu.memPrev(), 0o700)
	os.WriteFile(nu.memPrev()+"/tinylane.gz", gz([]byte("x")), 0o600)
	writeKV(nu.memPrev()+"/meta", kvFile{"VER": "0.4.5-m11", "UNTIL": fmt.Sprint(time.Now().Add(time.Hour).Unix())})
	e.mu.Lock()
	e.mem, e.now = 200<<20, time.Now().Add(2*time.Hour)
	e.mu.Unlock()
	nu.tick(context.Background())
	if nu.prevCopy() != nil {
		t.Fatal("满 24 小时应删")
	}
}

func TestM11SkipSeen(t *testing.T) {
	e := newFakeEnv(t, "0.4.5-m11")
	e.gh.rels["0.4.6"] = fakeELF("0.4.6")
	u := e.updater("0.4.5-m11", okFns())
	u.Check(context.Background())
	if b := u.brief(); b["popup"] != true || b["dot"] != true {
		t.Fatal(b)
	}
	u.setSeen("0.4.6") // 弹过一次（点了「稍后」）
	if b := u.brief(); b["popup"] != false || b["dot"] != true {
		t.Fatal("稍后：不再弹、留红点", b)
	}
	u.setSkip("0.4.6")
	u2 := e.updater("0.4.5-m11", okFns()) // 重启后仍记得
	if b := u2.brief(); b["popup"] != false || b["dot"] != false {
		t.Fatal("跳过：红点也消失", b)
	}
	e.gh.rels["0.4.7"] = fakeELF("0.4.7")
	u2.Check(context.Background())
	if b := u2.brief(); b["latest"] != "0.4.7" || b["popup"] != true || b["dot"] != true {
		t.Fatal("下一版应再提醒", b)
	}
	// 当前已经是最新：没有提示
	u3 := e.updater("0.4.7", okFns())
	if b := u3.brief(); b["latest"] != nil || b["dot"] != nil {
		t.Fatal(b)
	}
	// /releases/latest 404 时从列表挑最大正式版，测试版不算
	delete(e.gh.rels, "0.4.6")
	delete(e.gh.rels, "0.4.7")
	e.gh.rels["0.4.8-m2"] = fakeELF("0.4.8-m2")
	u2.Check(context.Background())
	if u2.st.Latest != nil {
		t.Fatal("只有测试版时不该有新版本", u2.st.Latest)
	}
}

// 试运行中重启路由器：内存里的旧版丢了 → 从 GitHub 下载标记里的旧版，重新自检
func TestM11BootRecovery(t *testing.T) {
	for _, haveOld := range []bool{true, false} {
		t.Run(fmt.Sprint("github有旧版=", haveOld), func(t *testing.T) {
			e := newFakeEnv(t, "0.4.6")
			e.gh.rels["0.4.5"] = fakeELF("0.4.5")
			if !haveOld {
				e.gh.noTag["0.4.5"] = true
			}
			u := e.updater("0.4.6", okFns())
			writeKV(u.markerP(), kvFile{"STATE": "check", "KIND": "update", "NEW_VER": "0.4.6", "OLD_VER": "0.4.5", "WHERE": "mem",
				"PREV_DIR": u.memPrev(), "PREV_BIN": u.memPrev() + "/tinylane.gz", "PREV_CONF": u.memPrev() + "/tinylane.json",
				"BIN": u.binP(), "CONF": u.cfgP, "INIT": u.init, "RES": u.resultP(), "CHECK_START": "1", "CHECK_S": "1", "GRACE_S": "20",
				"BOOT_ID": "boot-0", "HELPER_PID": "999999"})
			fns := okFns()
			fns.cn = func(context.Context) error { return errors.New("国内不通") }
			u.fns = fns
			u.Resume(context.Background())
			m := readKV(u.markerP())
			if haveOld {
				if m == nil || m["BOOT_ID"] != "boot-1" || m["NOROLLBACK"] == "1" || !fileExists(m["PREV_BIN"]) || m["PREV_CONF"] != "" {
					t.Fatalf("应下载旧版并重新计时：%v", m)
				}
				if len(e.spawns) != 1 || e.spawns[0] != "watch" {
					t.Fatal("应重启死人开关", e.spawns)
				}
				waitFor(t, "自检失败后退回", 20*time.Second, func() bool { return readKV(u.resultP())["RESULT"] == "rolled_back" })
				e.waitHelpers()
				if got, _ := os.ReadFile(u.binP()); !bytes.Equal(got, e.gh.rels["0.4.5"]) {
					t.Fatal("应写回从 GitHub 下载的旧版")
				}
			} else {
				if m == nil || m["NOROLLBACK"] != "1" {
					t.Fatalf("下载不到应标记无法退回：%v", m)
				}
				if tr := u.Status()["trial"].(map[string]any); tr["no_rollback"] != true {
					t.Fatal("面板应显示无法退回", tr)
				}
				waitFor(t, "自检失败但保持现状", 20*time.Second, func() bool { return readKV(u.resultP())["RESULT"] == "rollback_failed" })
				e.waitHelpers()
				if !strings.Contains(readKV(u.resultP())["REASON"], "保持现状") || fileExists(u.markerP()) {
					t.Fatal(readKV(u.resultP()))
				}
				if got, _ := os.ReadFile(u.binP()); !bytes.Equal(got, fakeELF("0.4.6")[:0]) && !strings.Contains(string(got), "0.4.6") {
					t.Fatal("当前程序不该被删")
				}
			}
		})
	}
}

// 换版时断电（程序被删了还没写完）→ init 启动前 boot 修复用旧版补回
func TestM11HelperBootRepair(t *testing.T) {
	e := newFakeEnv(t, "0.4.6")
	u := e.updater("0.4.6", okFns())
	oldBin := fakeELF("0.4.5")
	os.MkdirAll(u.flashPrev(), 0o700)
	os.WriteFile(u.flashPrev()+"/tinylane.gz", gz(oldBin), 0o600)
	os.Remove(u.binP())
	writeKV(u.markerP(), kvFile{"STATE": "swap", "NEW_VER": "0.4.6", "OLD_VER": "0.4.5", "PREV_DIR": u.flashPrev(), "PREV_BIN": u.flashPrev() + "/tinylane.gz",
		"PREV_SHA": hexSHA(oldBin), "BIN": u.binP(), "CONF": u.cfgP, "INIT": u.init, "RES": u.resultP()})
	u.spawn("boot", u.markerP())
	e.waitHelpers()
	if got, _ := os.ReadFile(u.binP()); !bytes.Equal(got, oldBin) {
		t.Fatal("应补回旧版")
	}
	if readKV(u.resultP())["RESULT"] != "rolled_back" || fileExists(u.markerP()) || readFile(e.root+"/init.log") != "stop\n" {
		t.Fatal(readKV(u.resultP()), readFile(e.root+"/init.log"))
	}
}

// 手动「退回上一版」：闪存里有上一版时直接用，不连 GitHub
func TestM11Revert(t *testing.T) {
	e := newFakeEnv(t, "0.4.6")
	u := e.updater("0.4.6", okFns())
	oldBin := fakeELF("0.4.5")
	os.MkdirAll(u.flashPrev(), 0o700)
	os.WriteFile(u.flashPrev()+"/tinylane.gz", gz(oldBin), 0o600)
	os.WriteFile(u.flashPrev()+"/tinylane.json", []byte(`{"old":1}`), 0o600)
	writeKV(u.flashPrev()+"/meta", kvFile{"VER": "0.4.5", "SHA": hexSHA(oldBin), "T": "1"})
	info, err := u.RevertInfo(context.Background())
	if err != nil || info["source"] != "flash" || info["ver"] != "0.4.5" {
		t.Fatal(info, err)
	}
	hits := e.gh.hits
	if err := u.Revert("0.4.5"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "退回完成", 15*time.Second, func() bool { return readKV(u.resultP())["RESULT"] == "reverted" })
	e.waitHelpers()
	if got, _ := os.ReadFile(u.binP()); !bytes.Equal(got, oldBin) || readFile(u.cfgP) != `{"old":1}` || e.gh.hits != hits {
		t.Fatal("退回结果不对")
	}
	if !fileExists(u.cfgP+".before-revert") || u.prevCopy() != nil || u.st.Skip != "0.4.6" {
		t.Fatal("应保存退回前配置、清掉上一版、跳过 0.4.6")
	}
	// 没有上一版：查 GitHub 上比当前旧的最新正式版
	e.gh.rels["0.4.4"] = fakeELF("0.4.4")
	e.gh.rels["0.4.3"] = fakeELF("0.4.3")
	e.gh.rels["0.4.9"] = fakeELF("0.4.9")
	u2 := e.updater("0.4.5", okFns())
	if info, err := u2.RevertInfo(context.Background()); err != nil || info["source"] != "github" || info["ver"] != "0.4.4" {
		t.Fatal(info, err)
	}
}
