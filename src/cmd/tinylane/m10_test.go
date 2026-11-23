package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 假 clash_api：GET /proxies/<组> 返回当前节点，PUT 切换，GET /proxies/<节点>/delay 按 ok[节点] 返回。
type fakeClash struct {
	mu  sync.Mutex
	now map[string]string
	ok  map[string]bool
	n   map[string]int // delay 请求次数
}

func (f *fakeClash) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/proxies/")
	if strings.HasSuffix(p, "/delay") {
		name := strings.TrimSuffix(p, "/delay")
		f.n[name]++
		if f.ok[name] {
			json.NewEncoder(w).Encode(map[string]int{"delay": 120})
		} else {
			w.WriteHeader(504)
			w.Write([]byte(`{"message":"Timeout"}`))
		}
		return
	}
	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(map[string]any{"now": f.now[p]})
	case "PUT":
		var b struct{ Name string }
		json.NewDecoder(r.Body).Decode(&b)
		f.now[p] = b.Name
		w.WriteHeader(204)
	}
}

func (f *fakeClash) set(node string, ok bool) { f.mu.Lock(); f.ok[node] = ok; f.mu.Unlock() }
func (f *fakeClash) cur(g string) string      { f.mu.Lock(); defer f.mu.Unlock(); return f.now[g] }

const m10Cfg = `{"clash_api":{"secret":"x"},"nodes":[{"name":"a","outbound":{"type":"vless"}},{"name":"b","outbound":{"type":"vless"}},{"name":"c","outbound":{"type":"vless"}}],
"groups":[{"name":"G","type":"failover","members":["a","b","c"]},{"name":"S","type":"failover","members":["a"],"strict":true}],
"watchdog":WD}`

func m10Setup(t *testing.T, wd string) (*Watchdog, *fakeClash, *Config) {
	t.Helper()
	if wd == "" {
		wd = "{}"
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(strings.Replace(m10Cfg, "WD", wd, 1)), 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	c.ProbeListen = "" // 不做吞吐探测
	f := &fakeClash{now: map[string]string{"G": "a", "S": "a"}, ok: map[string]bool{"a": true, "b": true, "c": true}, n: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	d := &Daemon{events: newEventLog(filepath.Join(dir, "ev.log"))}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	t.Cleanup(d.cancel)
	d.cfg.Store(c)
	d.api.Store(&apiClient{base: srv.URL, secret: "x", hc: &http.Client{Timeout: 5 * time.Second}})
	w := newWatchdog(d)
	d.wd = w
	old := upstreamCheck
	upstreamCheck = func() bool { return true }
	t.Cleanup(func() { upstreamCheck = old })
	return w, f, c
}

func (w *Watchdog) gs(g string) groupState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return *w.gstate(g)
}

// 间歇失败（失败/成功/失败）：窗口内过半 → 快速切到 b，S 组（strict，只有 a）不动
func TestM10IntermittentSwitch(t *testing.T) {
	w, f, c := m10Setup(t, "")
	f.set("a", false)
	w.round(c)
	if f.cur("G") != "a" || w.gs("G").FastStart == 0 || w.gs("G").FastFail != 1 {
		t.Fatalf("首次失败应进入快速复测、不切：now=%s st=%+v", f.cur("G"), w.gs("G"))
	}
	f.set("a", true)
	w.fastRound(c, false)
	if f.cur("G") != "a" {
		t.Fatal("成功一次不该切")
	}
	f.set("a", false)
	w.fastRound(c, false)
	if f.cur("G") != "b" {
		t.Fatalf("失败过半应切到 b，现在 %s，%+v", f.cur("G"), w.gs("G"))
	}
	if f.cur("S") != "a" {
		t.Fatal("strict 组不该切到组外")
	}
	sw := w.switches()
	if len(sw) != 1 || !sw[0].Fast || sw[0].To != "b" {
		t.Fatalf("切换记录 %+v", sw)
	}
	if st := w.gs("G"); st.FastStart != 0 || st.BackAfter <= time.Now().Unix() {
		t.Fatalf("切换后应清掉复测并设冷却 %+v", st)
	}
	if !strings.Contains(sw[0].Why, "快速复测") {
		t.Fatal(sw[0].Why)
	}
}

// 单次失败后恢复：窗口到了按实际次数判定，不切，复测结束
func TestM10SingleFailRecover(t *testing.T) {
	w, f, c := m10Setup(t, "")
	f.set("a", false)
	w.round(c)
	f.set("a", true)
	w.fastRound(c, false)
	w.mu.Lock()
	w.gstate("G").FastStart -= 31
	w.gstate("S").FastStart -= 31
	w.mu.Unlock()
	w.fastRound(c, false)
	if f.cur("G") != "a" || w.gs("G").FastStart != 0 || w.fastActive() {
		t.Fatalf("不该切、复测应结束：%s %+v", f.cur("G"), w.gs("G"))
	}
	if len(w.switches()) != 0 {
		t.Fatal("不该有切换")
	}
}

// 上游全断：不切、不计数、不进入快速复测
func TestM10UpstreamDown(t *testing.T) {
	w, f, c := m10Setup(t, "")
	upstreamCheck = func() bool { return false }
	for _, n := range []string{"a", "b", "c"} {
		f.set(n, false)
	}
	for i := 0; i < 4; i++ {
		w.round(c)
		w.fastRound(c, true)
	}
	if f.cur("G") != "a" || w.fastActive() {
		t.Fatalf("上游断网不该切/复测：%s %+v", f.cur("G"), w.gs("G"))
	}
	w.mu.Lock()
	fs := w.health("a").FailStreak
	w.mu.Unlock()
	if fs != 0 {
		t.Fatalf("上游断网不该计数 FailStreak=%d", fs)
	}
}

// strict 组：只会在组内切，组里没别的节点就保持
func TestM10StrictStaysInGroup(t *testing.T) {
	w, f, c := m10Setup(t, "")
	f.set("a", false)
	w.round(c)
	w.fastRound(c, false)
	w.fastRound(c, false)
	if f.cur("S") != "a" {
		t.Fatalf("strict 组被切到 %s", f.cur("S"))
	}
	// 最后一道闸：直接让 switchTo 切到组外也会被拒
	g, _ := findGroup(c, "S")
	if w.switchTo(g, "a", "b", "test") || f.cur("S") != "a" {
		t.Fatal("switchTo 应拒绝组外节点")
	}
}

// 关掉快速切换：与 m9 一致——交替失败永远不切；连续 3 次失败才切；没有快速复测状态；KickFast 无效
func TestM10FastOffSameAsM9(t *testing.T) {
	w, f, c := m10Setup(t, `{"fast_switch":false}`)
	if fastOn(c) || coreKickOn(c) {
		t.Fatal("应为关")
	}
	for i := 0; i < 6; i++ {
		f.set("a", i%2 == 1)
		w.round(c)
		if w.fastActive() {
			t.Fatal("关掉后不该有快速复测")
		}
	}
	if f.cur("G") != "a" {
		t.Fatal("交替失败在 m9 规则下不该切")
	}
	w.KickFast()
	if w.fastReq.Load() {
		t.Fatal("关掉时 KickFast 不该生效")
	}
	f.set("a", false)
	w.round(c)
	w.round(c)
	if f.cur("G") != "a" {
		t.Fatal("2 次失败不该切")
	}
	w.round(c)
	if f.cur("G") != "b" {
		t.Fatal("连续 3 次失败应切到 b")
	}
	if sw := w.switches(); len(sw) != 1 || sw[0].Fast {
		t.Fatalf("%+v", sw)
	}
	if w.gs("G").BackAfter != 0 {
		t.Fatal("普通切换不设冷却")
	}
}

// 冷却：快速切走后冷却期内 a 恢复也不切回；冷却过了 + 连续 recover 次正常才切回
func TestM10Cooldown(t *testing.T) {
	w, f, c := m10Setup(t, `{"switch_back_min":5}`)
	f.set("a", false)
	w.round(c)
	w.fastRound(c, false)
	if f.cur("G") != "b" {
		t.Fatal("应快速切到 b")
	}
	f.set("a", true)
	for i := 0; i < 5; i++ {
		w.round(c)
	}
	if f.cur("G") != "b" {
		t.Fatal("冷却期内不该切回")
	}
	if !strings.Contains(w.gs("G").Note, "之前不切回") {
		t.Fatal(w.gs("G").Note)
	}
	w.mu.Lock()
	w.gstate("G").BackAfter = time.Now().Unix() - 1
	w.mu.Unlock()
	w.round(c)
	if f.cur("G") != "a" {
		t.Fatal("冷却过后应切回 a")
	}
}

// 备用节点也测：当前 a 时也测 b（结果进 health、进 memhist 点）；关掉就不测
func TestM10ProbeBackup(t *testing.T) {
	w, f, c := m10Setup(t, "")
	w.round(c)
	if f.n["b"] == 0 || w.gs("G").Backup != "b" {
		t.Fatalf("应测备用 b：%v %+v", f.n, w.gs("G"))
	}
	if f.n["c"] != 0 {
		t.Fatal("只测第一个备用")
	}
	gp := w.histGroups(c)
	if len(gp) != 2 || gp[0].G != "G" || gp[0].N != "a" || gp[0].D != 120 || gp[0].B != "b" || gp[0].BD != 120 {
		t.Fatalf("%+v", gp)
	}
	m := &MemHist{}
	m.sampleG(os.Getpid(), gp)
	b, _ := json.Marshal(m.snapshot())
	if !bytes.Contains(b, []byte(`"g":[{"g":"G","n":"a","d":120,"b":"b","bd":120}`)) {
		t.Fatal(string(b))
	}
	w2, f2, c2 := m10Setup(t, `{"probe_backup":false}`)
	w2.round(c2)
	if f2.n["b"] != 0 {
		t.Fatal("关掉不该测备用")
	}
}

// 内核超时报错计数：20 秒内 ≥N 条触发一次 KickFast；30 秒内不重复；跨 Write 的半行也能识别
func TestM10CoreErrKick(t *testing.T) {
	w, _, c := m10Setup(t, `{"core_err_count":5}`)
	var kicks int
	now := time.Unix(1700000000, 0)
	cnt := &coreErrCounter{now: func() time.Time { return now }, limit: func() int { return coreErrN(c) },
		onKick: func(n int) { kicks++; w.KickFast() }}
	var out bytes.Buffer
	tap := &lineTap{out: &out, cnt: cnt}
	line := "ERROR [123 1.2s] connection: open outbound connection: connection upload handshake: timeout: no recent network activity\n"
	for i := 0; i < 4; i++ {
		tap.Write([]byte(line))
	}
	tap.Write([]byte("INFO inbound/tproxy: normal line\n"))
	if kicks != 0 || w.fastReq.Load() {
		t.Fatal("4 条不该触发")
	}
	tap.Write([]byte("ERROR stream 12 canceled by re"))
	tap.Write([]byte("mote with error code 0\n"))
	if kicks != 1 || !w.fastReq.Load() {
		t.Fatalf("第 5 条（跨两次写）应触发 kicks=%d", kicks)
	}
	if out.Len() == 0 || !strings.Contains(out.String(), "canceled by remote") {
		t.Fatal("要原样转发")
	}
	now = now.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		tap.Write([]byte(line))
	}
	if kicks != 1 {
		t.Fatal("30 秒内不重复触发")
	}
	now = now.Add(25 * time.Second) // 距上次 35 秒；窗口里前面的都过期了
	for i := 0; i < 4; i++ {
		tap.Write([]byte(line))
	}
	if kicks != 1 {
		t.Fatal("窗口外的旧报错不该算")
	}
	tap.Write([]byte(line))
	if kicks != 2 {
		t.Fatalf("kicks=%d", kicks)
	}
	// Kick 只触发复测，不直接切换：kicked 快速轮里 a 正常 → 不进复测、不切
	w.fastRound(c, true)
	if w.fastActive() || len(w.switches()) != 0 {
		t.Fatal("触发只复测")
	}
}

// 设置范围校验 + 配置缺省/夹取
func TestM10SettingsValidate(t *testing.T) {
	ip := func(i int) *int { return &i }
	good := autoIn{FastSwitch: bptr(false), FastRetestS: ip(5), FastWindowS: ip(180), CoreErrKick: bptr(true), CoreErrCount: ip(50), ProbeBackup: bptr(false), SwitchBackMin: ip(0)}
	kv, err := validAuto(good)
	if err != nil || kv["fast_switch"] != false || kv["switch_back_min"] != 0 || kv["fast_window_s"] != 180 {
		t.Fatal(err, kv)
	}
	bad := []autoIn{{FastRetestS: ip(4)}, {FastRetestS: ip(61)}, {FastWindowS: ip(14)}, {FastWindowS: ip(181)},
		{CoreErrCount: ip(2)}, {CoreErrCount: ip(51)}, {SwitchBackMin: ip(-1)}, {SwitchBackMin: ip(61)},
		{FastRetestS: ip(60), FastWindowS: ip(30)}}
	for _, b := range bad {
		if _, err := validAuto(b); err == nil {
			t.Fatalf("应拒绝 %+v", b)
		}
	}
	_, _, c := m10Setup(t, "")
	if !fastOn(c) || !coreKickOn(c) || !probeBackupOn(c) || fastRetest(c) != 15 || fastWindow(c) != 30 || coreErrN(c) != 5 || backMin(c) != 5 {
		t.Fatalf("缺省值不对 %+v", c.Watchdog)
	}
	_, _, c2 := m10Setup(t, `{"fast_retest_s":1,"fast_window_s":999,"core_err_count":1,"switch_back_min":99}`)
	if fastRetest(c2) != 5 || fastWindow(c2) != 180 || coreErrN(c2) != 3 || backMin(c2) != 60 {
		t.Fatalf("手改越界应夹到范围 %+v", c2.Watchdog)
	}
	var zero Config
	if !fastOn(&zero) || backMin(&zero) != 5 || fastRetest(&zero) != 15 {
		t.Fatal("nil 缺省")
	}
	// 判定规则本身
	cases := []struct {
		n, f int
		el   int64
		bad  bool
		done bool
	}{{1, 1, 0, false, false}, {2, 2, 15, true, true}, {3, 2, 30, true, true}, {2, 1, 15, false, false}, {3, 1, 31, false, true}, {1, 1, 31, false, true}}
	for _, x := range cases {
		b, d := fastVerdict(x.n, x.f, x.el, 15, 30)
		if b != x.bad || d != x.done {
			t.Fatalf("%+v → %v %v", x, b, d)
		}
	}
}
