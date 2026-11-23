package main

// M11：检查更新 + 一键更新 + 自检失败自动退回。
//
// 检查：每天查一次 GitHub Releases（经内核 mixed 代理，失败退直连），只认正式版 vX.Y.Z；semver 比较，
//       当前版本带 -mN（测试版）/-rcN 也能比较：X.Y.Z-mN < X.Y.Z-rcN < X.Y.Z，同类按 N 数字比。
// 签名：Release 附 SHA256SUMS-<arch>.txt 和它的 ed25519 签名 .sig（base64）；公钥编在程序里。
//       先验签名，再按 SUMS 校验 .gz 和解压后的程序（sha256 + ELF 架构 + 含版本号）。
// 更新：下载 .gz 到 /tmp → 校验 → 旧版程序压缩 + 配置存到「上一版」（闪存 /etc/tinylane/prev，放不下就 /tmp/tinylane-prev）
//       → 写试运行标记 → 启动辅助脚本（独立会话）：停服务、删旧版、写新版、启动 → 新版守护进程 3 分钟自检
//       → 通过：删标记；不过：标记改 rollback_req，辅助脚本删新版、写回旧版和配置、启动。
//       辅助脚本兼做死人开关：新版 3 分钟 + 90 秒宽限内没给结果（起不来 / 卡住）就自己退回。
// 全程不碰 wg0、不改 /etc/config/network。

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed tinylane-update.sh
var updHelperScript []byte

// 更新签名公钥（ed25519，原始 32 字节 base64）。私钥只在沙盒 secret/update-signing.key 和 Actions Secret TINYLANE_SIGN_KEY。
const updPubKeyB64 = "vhFLnHxnQ4g3mnGRf8Yjw/mB7myftoeGWXyyasc2eKI="

var updPubKey = func() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(updPubKeyB64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("updPubKey")
	}
	return ed25519.PublicKey(b)
}()

const (
	updCheckS     = 180      // 自检时长
	updGraceS     = 90       // 辅助脚本等结果的宽限
	updMargin     = 2 << 20  // 闪存余量
	updMemReserve = 40 << 20 // 更新时至少留给系统的可用内存
	updMemKeep    = 24 * time.Hour
	updGzRatio    = 0.42 // 估算旧版压缩后大小（实测 0.38）
	updNotesMax   = 6000 // 更新说明最多字符
	updCheckEvery = 24 * time.Hour
)

type UpdateConf struct {
	Auto bool `json:"auto"` // 自动更新：只在 4:00 更新正式版；上一版只能放内存时不自动更新
}

// ---------------- 版本比较 ----------------

var verRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?$`)
var formalTagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
var preRe = regexp.MustCompile(`^(m|rc)(\d+)$`)

type semver struct {
	n    [3]int
	pre  string
	kind int // 3 正式版 · 2 rcN · 1 mN · 0 其他预发布
	pn   int
}

func parseVer(s string) (semver, bool) {
	m := verRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := 0; i < 3; i++ {
		v.n[i], _ = strconv.Atoi(m[i+1])
	}
	v.pre = m[4]
	switch pm := preRe.FindStringSubmatch(v.pre); {
	case v.pre == "":
		v.kind = 3
	case pm != nil && pm[1] == "rc":
		v.kind, v.pn = 2, atoiSafe(pm[2])
	case pm != nil:
		v.kind, v.pn = 1, atoiSafe(pm[2])
	}
	return v, true
}

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }

// cmpVer：a<b → -1，a==b → 0，a>b → 1；解析不了的版本算最旧。
func cmpVer(a, b string) int {
	va, oka := parseVer(a)
	vb, okb := parseVer(b)
	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return -1
	case !okb:
		return 1
	}
	for i := 0; i < 3; i++ {
		if va.n[i] != vb.n[i] {
			return sign(va.n[i] - vb.n[i])
		}
	}
	if va.kind != vb.kind {
		return sign(va.kind - vb.kind)
	}
	if va.kind == 0 {
		return strings.Compare(va.pre, vb.pre)
	}
	return sign(va.pn - vb.pn)
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	}
	return 0
}

func isFormalTag(t string) bool { return formalTagRe.MatchString(t) }

// ---------------- 签名 / 校验 ----------------

func verifySums(sums, sig []byte, pub ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("签名文件格式不对")
	}
	if !ed25519.Verify(pub, sums, raw) {
		return errors.New("签名校验没通过（文件可能被篡改，或不是官方发布的）")
	}
	return nil
}

func parseSums(b []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && len(f[0]) == 64 {
			m[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return m
}

func elfMachine(arch string) uint16 {
	switch arch {
	case "arm64":
		return 183
	case "amd64":
		return 62
	case "arm":
		return 40
	case "mips", "mipsle":
		return 8
	case "riscv64":
		return 243
	}
	return 0
}

// checkBinary：边解压边算 sha256，检查 ELF 架构和版本号字符串。返回原始大小。
func checkBinary(gzPath, wantSHA, ver, arch string) (int64, error) {
	f, err := os.Open(gzPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("压缩包损坏：%v", err)
	}
	h := sha256.New()
	var head [20]byte
	n0, _ := io.ReadFull(zr, head[:])
	h.Write(head[:n0])
	if n0 < 20 || string(head[:4]) != "\x7fELF" {
		return 0, errors.New("不是可执行程序")
	}
	if m := elfMachine(arch); m != 0 && uint16(head[18])|uint16(head[19])<<8 != m {
		return 0, fmt.Errorf("程序架构不对（需要 %s）", arch)
	}
	needle := []byte(ver)
	found := false
	var tail []byte
	buf := make([]byte, 64<<10)
	total := int64(n0)
	for {
		n, err := zr.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
			if !found && len(needle) > 0 {
				chunk := append(tail, buf[:n]...)
				if bytes.Contains(chunk, needle) {
					found = true
				}
				k := len(needle) - 1
				if len(chunk) < k {
					k = len(chunk)
				}
				tail = append(tail[:0], chunk[len(chunk)-k:]...)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("解压失败：%v", err)
		}
	}
	if wantSHA != "" && hex.EncodeToString(h.Sum(nil)) != wantSHA {
		return 0, errors.New("程序 sha256 和签名清单不一致")
	}
	if len(needle) > 0 && !found {
		return 0, fmt.Errorf("程序里找不到版本号 %s", ver)
	}
	return total, nil
}

func fileSHA(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func gunzipSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, zr); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// gzipFile：压缩 src → dst（先写 .tmp），返回 src 的 sha256 和 dst 大小；写完再解压校验一遍。
func gzipFile(src, dst string) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	zw, _ := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	_, err = io.Copy(zw, io.TeeReader(in, h))
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if got, err := gunzipSHA(tmp); err != nil || got != sum {
		os.Remove(tmp)
		return "", 0, fmt.Errorf("备份校验失败：%v", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	st, _ := os.Stat(dst)
	return sum, st.Size(), nil
}

// ---------------- 空间计算 ----------------

type spaceIn struct {
	FlashFree int64 // /etc/tinylane 所在分区可用
	CurBin    int64 // 当前 /usr/bin/tinylane（换版时会删掉）
	OldPrev   int64 // 闪存里已有的上一版（会被替换）
	NewRaw    int64
	NewGz     int64
	OldGzEst  int64
	MemAvail  int64
}

type spacePlan struct {
	Mode      string `json:"mode"` // flash | mem | none
	NeedMem   int64  `json:"need_mem"`
	NeedFlash int64  `json:"need_flash"`
	ShortMB   int    `json:"short_mb"`
	Msg       string `json:"msg"`
}

func ceilMB(b int64) int {
	if b <= 0 {
		return 0
	}
	return int((b + (1 << 20) - 1) >> 20)
}

// planSpace：闪存够 = 上一版（旧版压缩）+ 新版原始 + 2 MB 余量 放得下。可算进去的：现在的可用空间
// + 当前程序（换版时先停服务再删，空间才真正释放）+ 闪存里旧的上一版（每次更新都替换掉）。
// 不够就把上一版放内存；内存要留 40 MB 给系统：闪存模式 新包 + 40 MB，内存模式再加上一版的压缩包。
func planSpace(s spaceIn) spacePlan {
	p := spacePlan{NeedFlash: s.NewRaw + s.OldGzEst + updMargin}
	flashAll := s.FlashFree + s.CurBin + s.OldPrev
	if s.FlashFree+s.OldPrev >= s.OldGzEst+updMargin && flashAll >= p.NeedFlash {
		p.Mode = "flash"
		p.NeedMem = s.NewGz + updMemReserve
	} else {
		p.Mode = "mem"
		if flashAll < s.NewRaw+updMargin {
			p.Mode, p.ShortMB = "none", ceilMB(s.NewRaw+updMargin-flashAll)
			p.Msg = fmt.Sprintf("闪存空间不够放新版，还差 %d MB，暂时不能更新", p.ShortMB)
			return p
		}
		p.NeedMem = s.NewGz + s.OldGzEst + updMemReserve
		p.Msg = "闪存空间不足，旧版只在内存里临时保留（重启路由器后就没了）"
	}
	if s.MemAvail < p.NeedMem {
		p.Mode, p.ShortMB = "none", ceilMB(p.NeedMem-s.MemAvail)
		p.Msg = fmt.Sprintf("路由器可用内存不够，还差 %d MB，暂时不能更新", p.ShortMB)
	}
	return p
}

// ---------------- 键值文件（试运行标记 / 结果）----------------

type kvFile map[string]string

func readKV(p string) kvFile {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	m := kvFile{}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if !ok || k == "" {
			continue
		}
		m[k] = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
	}
	return m
}

func kvClean(v string) string { return strings.NewReplacer("'", `"`, "\n", " ", "\r", " ").Replace(v) }

func writeKV(p string, m kvFile) error {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b bytes.Buffer
	for _, k := range ks {
		fmt.Fprintf(&b, "%s='%s'\n", k, kvClean(m[k]))
	}
	return writeFileAtomic(p, b.Bytes(), 0o600)
}

func (m kvFile) i64(k string) int64 { n, _ := strconv.ParseInt(m[k], 10, 64); return n }

// ---------------- GitHub Release ----------------

type relInfo struct {
	Tag       string `json:"tag"`
	Ver       string `json:"ver"`
	Name      string `json:"name"`
	Notes     string `json:"notes"`
	Published string `json:"published"`
	URL       string `json:"url"`
	GzURL     string `json:"gz_url"`
	SumsURL   string `json:"sums_url"`
	SigURL    string `json:"sig_url"`
	GzSize    int64  `json:"gz_size"`
	RawSize   int64  `json:"raw_size"`
	Missing   string `json:"missing,omitempty"` // 缺少的构件（不能自动更新）
}

type ghRelease struct {
	Tag        string `json:"tag_name"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Published  string `json:"published_at"`
	HTML       string `json:"html_url"`
	Assets     []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func relFromGH(g ghRelease, arch string) relInfo {
	ver := strings.TrimPrefix(g.Tag, "v")
	r := relInfo{Tag: g.Tag, Ver: ver, Name: g.Name, Published: g.Published, URL: g.HTML}
	notes := []rune(strings.TrimSpace(g.Body))
	if len(notes) > updNotesMax {
		notes = append(notes[:updNotesMax], []rune("…")...)
	}
	r.Notes = string(notes)
	base := "tinylane-" + ver + "-linux-" + arch
	var miss []string
	for _, a := range g.Assets {
		switch a.Name {
		case base + ".gz":
			r.GzURL, r.GzSize = a.URL, a.Size
		case base:
			r.RawSize = a.Size
		case "SHA256SUMS-" + arch + ".txt":
			r.SumsURL = a.URL
		case "SHA256SUMS-" + arch + ".txt.sig":
			r.SigURL = a.URL
		}
	}
	if r.GzURL == "" {
		miss = append(miss, base+".gz")
	}
	if r.SumsURL == "" {
		miss = append(miss, "SHA256SUMS")
	}
	if r.SigURL == "" {
		miss = append(miss, "签名 .sig")
	}
	if r.RawSize == 0 && r.GzSize > 0 {
		r.RawSize = int64(float64(r.GzSize) / 0.37) // 没附原始程序时按压缩比估
	}
	r.Missing = strings.Join(miss, "、")
	return r
}

// ---------------- 更新器 ----------------

type updState struct {
	LastCheck int64    `json:"last_check"`
	CheckErr  string   `json:"check_err,omitempty"`
	Latest    *relInfo `json:"latest,omitempty"`
	Skip      string   `json:"skip,omitempty"`
	Seen      string   `json:"seen,omitempty"`
	Sched     string   `json:"scheduled,omitempty"` // 「今晚 4:00 更新」的版本
	SchedAt   int64    `json:"scheduled_at,omitempty"`
	AutoDay   string   `json:"auto_day,omitempty"` // 当天已经尝试过自动更新（CST 日期）
	Acked     int64    `json:"acked,omitempty"`    // 已看过的结果时间
}

type updJob struct {
	Kind   string `json:"kind"`  // update | revert
	Phase  string `json:"phase"` // download | verify | backup | restart | error
	Ver    string `json:"ver"`
	Done   int64  `json:"done"`
	Total  int64  `json:"total"`
	Err    string `json:"err,omitempty"`
	Start  int64  `json:"start"`
	Where  string `json:"where,omitempty"` // 上一版位置 flash | mem
	Detail string `json:"detail,omitempty"`
}

type trialItem struct {
	K      string `json:"k"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Skip   bool   `json:"skip,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type checkFns struct {
	core, panel, cn, intl func(ctx context.Context) error
	wg                    func() (exists bool, ageS int64, err error)
}

type Updater struct {
	d              *Daemon
	root           string
	api            string
	repo           string
	arch           string
	init           string
	cfgP           string
	cnURL, intlURL string

	mu      sync.Mutex
	st      updState
	job     *updJob
	cancel  context.CancelFunc
	items   []trialItem
	trial   bool
	checkMu sync.Mutex

	// 测试替身
	now       func() time.Time
	memAvail  func() int64
	flashFree func() int64
	spawn     func(mode, marker string) error
	bootID    func() string
	helperUp  func(pid string) bool
	fns       checkFns
	proxy     func() string
	ver       string
	pollEvery time.Duration
	checkS    int // 自检时长（秒）
	graceS    int
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newUpdater(d *Daemon) *Updater {
	u := &Updater{d: d,
		root:    envOr("TINYLANE_UPD_ROOT", "/"),
		api:     strings.TrimRight(envOr("TINYLANE_UPD_API", "https://api.github.com"), "/"),
		repo:    envOr("TINYLANE_UPD_REPO", "sprigly/tinylane"),
		arch:    runtime.GOARCH,
		cnURL:   envOr("TINYLANE_UPD_CHECK_CN", "https://www.baidu.com/"),
		intlURL: envOr("TINYLANE_UPD_CHECK_INTL", "http://www.gstatic.com/generate_204"),
		ver:     tlVersion, pollEvery: 15 * time.Second, checkS: updCheckS, graceS: updGraceS,
	}
	u.init = envOr("TINYLANE_UPD_INIT", u.p("/etc/init.d/tinylane"))
	if d != nil {
		u.cfgP = d.cfgPath
	} else {
		u.cfgP = u.p("/etc/tinylane/tinylane.json")
	}
	u.now = time.Now
	u.memAvail = func() int64 { return int64(memAvailMBf()) << 20 }
	u.flashFree = func() int64 { return diskFree(u.p("/etc/tinylane")) }
	u.bootID = func() string {
		b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
		return strings.TrimSpace(string(b))
	}
	u.helperUp = func(pid string) bool {
		if pid == "" {
			return false
		}
		b, err := os.ReadFile("/proc/" + pid + "/cmdline")
		return err == nil && bytes.Contains(b, []byte("tinylane-update"))
	}
	u.spawn = u.spawnHelper
	u.proxy = func() string {
		if u.d != nil && u.d.conf() != nil {
			return u.d.conf().MixedListen
		}
		return ""
	}
	if d != nil {
		u.fns = u.realChecks()
	}
	u.loadState()
	return u
}

func memAvailMBf() int { return memAvailableMB() }

func diskFree(p string) int64 {
	var s syscall.Statfs_t
	if err := syscall.Statfs(p, &s); err != nil {
		return 0
	}
	return int64(s.Bavail) * int64(s.Bsize)
}

func (u *Updater) p(s string) string { return filepath.Join(u.root, s) }
func (u *Updater) binP() string      { return u.p("/usr/bin/tinylane") }
func (u *Updater) markerP() string   { return u.p("/etc/tinylane/.update-trial") }
func (u *Updater) resultP() string   { return u.p("/etc/tinylane/.update-result") }
func (u *Updater) stateP() string    { return u.p("/etc/tinylane/update.json") }
func (u *Updater) flashPrev() string {
	return u.p("/etc/tinylane/prev")
}
func (u *Updater) memPrev() string { return u.p("/tmp/tinylane-prev") }
func (u *Updater) dlDir() string   { return u.p("/tmp/tinylane-update") }
func (u *Updater) helperP() string { return u.p("/usr/libexec/tinylane/tinylane-update.sh") }

func (u *Updater) event(kind, msg string) {
	if u.d != nil && u.d.events != nil {
		u.d.events.add(kind, msg)
	}
}

func (u *Updater) loadState() {
	if b, err := os.ReadFile(u.stateP()); err == nil {
		json.Unmarshal(b, &u.st)
	}
}

func (u *Updater) saveState() { // 调用方持锁
	os.MkdirAll(filepath.Dir(u.stateP()), 0o700)
	b, _ := json.MarshalIndent(u.st, "", " ")
	writeFileAtomic(u.stateP(), b, 0o600)
}

func (u *Updater) autoOn() bool {
	return u.d != nil && u.d.conf() != nil && u.d.conf().Update.Auto
}

// ---------------- HTTP（先经代理，失败退直连）----------------

func (u *Updater) get(ctx context.Context, rawURL string, timeout time.Duration, fn func(*http.Response) error) error {
	var routes []string
	if px := u.proxy(); px != "" {
		routes = append(routes, px)
	}
	routes = append(routes, "")
	var last error
	for _, px := range routes {
		tr := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 5 * time.Second}
		if px != "" {
			pu, _ := url.Parse("http://" + px)
			tr.Proxy = http.ProxyURL(pu)
		}
		cx, cancel := context.WithTimeout(ctx, timeout)
		req, _ := http.NewRequestWithContext(cx, "GET", rawURL, nil)
		req.Header.Set("User-Agent", "tinylane/"+u.ver)
		if strings.Contains(rawURL, "/repos/") {
			req.Header.Set("Accept", "application/vnd.github+json")
		}
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err == nil {
			if resp.StatusCode/100 != 2 {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
				if resp.StatusCode == 404 {
					err = errNotFound
				}
			} else {
				err = fn(resp)
			}
			resp.Body.Close()
		}
		cancel()
		tr.CloseIdleConnections()
		if err == nil || errors.Is(err, errNotFound) || errors.Is(err, errBadFile) || ctx.Err() != nil {
			return err
		}
		last = err
	}
	return last
}

var errNotFound = errors.New("没有找到")
var errBadFile = errors.New("文件校验没通过")

func (u *Updater) getJSON(ctx context.Context, path string, v any) error {
	return u.get(ctx, u.api+path, 20*time.Second, func(r *http.Response) error {
		return json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(v)
	})
}

func (u *Updater) getSmall(ctx context.Context, rawURL string) ([]byte, error) {
	var b []byte
	err := u.get(ctx, rawURL, 30*time.Second, func(r *http.Response) error {
		var e error
		b, e = io.ReadAll(io.LimitReader(r.Body, 64<<10))
		return e
	})
	return b, err
}

// fetchLatest：/releases/latest；若它不是 vX.Y.Z（或拿不到）就列出最近 30 个挑最大的正式版。
func (u *Updater) fetchLatest(ctx context.Context) (*relInfo, error) {
	var g ghRelease
	err := u.getJSON(ctx, "/repos/"+u.repo+"/releases/latest", &g)
	if err == nil && isFormalTag(g.Tag) && !g.Draft && !g.Prerelease {
		r := relFromGH(g, u.arch)
		return &r, nil
	}
	if err != nil && !errors.Is(err, errNotFound) {
		return nil, err
	}
	return u.pickFormal(ctx, func(string) bool { return true })
}

func (u *Updater) pickFormal(ctx context.Context, ok func(ver string) bool) (*relInfo, error) {
	var list []ghRelease
	if err := u.getJSON(ctx, "/repos/"+u.repo+"/releases?per_page=30", &list); err != nil {
		return nil, err
	}
	var best *ghRelease
	for i := range list {
		g := &list[i]
		if g.Draft || g.Prerelease || !isFormalTag(g.Tag) || !ok(strings.TrimPrefix(g.Tag, "v")) {
			continue
		}
		if best == nil || cmpVer(g.Tag, best.Tag) > 0 {
			best = g
		}
	}
	if best == nil {
		return nil, errNotFound
	}
	r := relFromGH(*best, u.arch)
	return &r, nil
}

func (u *Updater) fetchTag(ctx context.Context, ver string) (*relInfo, error) {
	var g ghRelease
	if err := u.getJSON(ctx, "/repos/"+u.repo+"/releases/tags/v"+ver, &g); err != nil {
		return nil, err
	}
	r := relFromGH(g, u.arch)
	return &r, nil
}

// Check：立刻查一次（面板按钮 / 每天一次）。
func (u *Updater) Check(ctx context.Context) error {
	u.checkMu.Lock()
	defer u.checkMu.Unlock()
	r, err := u.fetchLatest(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.st.LastCheck = u.now().Unix()
	if err != nil {
		if errors.Is(err, errNotFound) {
			u.st.CheckErr, u.st.Latest = "", nil
			u.saveState()
			return nil
		}
		u.st.CheckErr = "连不上 GitHub：" + updShortErr(err)
		u.saveState()
		return errors.New(u.st.CheckErr)
	}
	u.st.CheckErr = ""
	old := u.st.Latest
	u.st.Latest = r
	if cmpVer(r.Ver, u.ver) > 0 && (old == nil || old.Ver != r.Ver) {
		go u.event("system", "发现新版本 v"+r.Ver+"（当前 "+u.ver+"）")
	}
	u.saveState()
	return nil
}

func updShortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 80 {
		s = s[i+2:]
	}
	if r := []rune(s); len(r) > 60 {
		s = string(r[:60])
	}
	return s
}

// ---------------- 下载 + 校验 ----------------

// download：拿签名清单 → 验签 → 下载 .gz（边下边算 sha256）→ 校验解压后的程序。返回 gz 路径、原始 sha、原始大小。
func (u *Updater) download(ctx context.Context, r *relInfo, name string, prog func(done, total int64), phase func(string)) (string, string, int64, error) {
	if r.Missing != "" {
		return "", "", 0, fmt.Errorf("v%s 缺少 %s，不能自动更新", r.Ver, r.Missing)
	}
	sums, err := u.getSmall(ctx, r.SumsURL)
	if err != nil {
		return "", "", 0, fmt.Errorf("下载签名清单失败：%s", updShortErr(err))
	}
	sig, err := u.getSmall(ctx, r.SigURL)
	if err != nil {
		return "", "", 0, fmt.Errorf("下载签名失败：%s", updShortErr(err))
	}
	if err := verifySums(sums, sig, updPubKey); err != nil {
		return "", "", 0, err
	}
	sm := parseSums(sums)
	base := "tinylane-" + r.Ver + "-linux-" + u.arch
	gzSHA, rawSHA := sm[base+".gz"], sm[base]
	if gzSHA == "" || rawSHA == "" {
		return "", "", 0, errors.New("签名清单里没有这个程序")
	}
	os.MkdirAll(u.dlDir(), 0o700)
	dst := filepath.Join(u.dlDir(), name)
	err = u.get(ctx, r.GzURL, 20*time.Minute, func(resp *http.Response) error {
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		total := resp.ContentLength
		if total <= 0 {
			total = r.GzSize
		}
		var done int64
		buf := make([]byte, 32<<10)
		lim := r.GzSize + 1<<20
		if lim < 2<<20 {
			lim = 64 << 20
		}
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := f.Write(buf[:n]); werr != nil {
					return werr
				}
				h.Write(buf[:n])
				done += int64(n)
				if done > lim {
					return errBadFile
				}
				prog(done, total)
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
		if hex.EncodeToString(h.Sum(nil)) != gzSHA {
			return errBadFile
		}
		return nil
	})
	if err != nil {
		os.Remove(dst)
		if errors.Is(err, errBadFile) {
			return "", "", 0, errors.New("下载的文件和签名清单不一致，已删除")
		}
		return "", "", 0, fmt.Errorf("下载失败：%s", updShortErr(err))
	}
	phase("verify")
	size, err := checkBinary(dst, rawSHA, r.Ver, u.arch)
	if err != nil {
		os.Remove(dst)
		return "", "", 0, err
	}
	return dst, rawSHA, size, nil
}

// ---------------- 状态 / 空间 ----------------

func fsize(p string) int64 {
	if st, err := os.Stat(p); err == nil {
		return st.Size()
	}
	return 0
}

func (u *Updater) space(r *relInfo) spacePlan {
	cur := fsize(u.binP())
	return planSpace(spaceIn{FlashFree: u.flashFree(), CurBin: cur, OldPrev: fsize(filepath.Join(u.flashPrev(), "tinylane.gz")) + fsize(filepath.Join(u.flashPrev(), "tinylane.json")),
		NewRaw: r.RawSize, NewGz: r.GzSize, OldGzEst: int64(float64(cur)*updGzRatio) + 64<<10, MemAvail: u.memAvail()})
}

type prevInfo struct {
	Where string `json:"where"` // flash | mem
	Ver   string `json:"ver"`
	T     int64  `json:"t"`
	Until int64  `json:"until,omitempty"`
	dir   string
}

func (u *Updater) prevCopy() *prevInfo {
	for _, x := range []struct{ w, d string }{{"flash", u.flashPrev()}, {"mem", u.memPrev()}} {
		m := readKV(filepath.Join(x.d, "meta"))
		if m == nil || !fileExists(filepath.Join(x.d, "tinylane.gz")) {
			continue
		}
		return &prevInfo{Where: x.w, Ver: m["VER"], T: m.i64("T"), Until: m.i64("UNTIL"), dir: x.d}
	}
	return nil
}

// Status：面板 /api/update/status。
func (u *Updater) Status() map[string]any {
	u.mu.Lock()
	st := u.st
	var job *updJob
	if u.job != nil {
		j := *u.job
		job = &j
	}
	items := append([]trialItem(nil), u.items...)
	u.mu.Unlock()
	out := map[string]any{"cur": u.ver, "last_check": st.LastCheck, "check_err": st.CheckErr, "skip": st.Skip, "seen": st.Seen,
		"scheduled": st.Sched, "auto": u.autoOn(), "job": job}
	if r := st.Latest; r != nil {
		out["latest"] = r
		newer := cmpVer(r.Ver, u.ver) > 0
		out["newer"] = newer
		if newer {
			out["space"] = u.space(r)
		}
	}
	if pc := u.prevCopy(); pc != nil {
		out["prev"] = pc
	}
	if m := readKV(u.markerP()); m != nil {
		cs := m.i64("CHECK_START")
		out["trial"] = map[string]any{"state": m["STATE"], "new": m["NEW_VER"], "old": m["OLD_VER"], "start": cs, "deadline": cs + int64(u.checkS),
			"now": u.now().Unix(), "items": items, "kind": m["KIND"], "no_rollback": m["NOROLLBACK"] == "1"}
	}
	if r := readKV(u.resultP()); r != nil {
		res := map[string]any{"result": r["RESULT"], "from": r["FROM"], "to": r["TO"], "reason": r["REASON"], "t": r.i64("T"), "kind": r["KIND"]}
		res["acked"] = r.i64("T") <= st.Acked
		out["result"] = res
	}
	return out
}

// brief：放进 /api/state，前端据此画红点 / 决定是否弹窗。
func (u *Updater) brief() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	b := map[string]any{"cur": u.ver}
	if r := u.st.Latest; r != nil && cmpVer(r.Ver, u.ver) > 0 {
		b["latest"] = r.Ver
		b["dot"] = r.Ver != u.st.Skip
		b["popup"] = r.Ver != u.st.Skip && r.Ver != u.st.Seen
	}
	b["busy"] = u.job != nil && u.job.Phase != "error" || fileExists(u.markerP())
	if r := readKV(u.resultP()); r != nil && r.i64("T") > u.st.Acked {
		b["result"] = r["RESULT"]
	}
	return b
}

func (u *Updater) setSeen(ver string) {
	u.mu.Lock()
	u.st.Seen = ver
	u.saveState()
	u.mu.Unlock()
}

func (u *Updater) setSkip(ver string) {
	u.mu.Lock()
	u.st.Skip, u.st.Seen = ver, ver
	if u.st.Sched == ver {
		u.st.Sched = ""
	}
	u.saveState()
	u.mu.Unlock()
	u.event("system", "已跳过 v"+ver+"，下一个版本再提醒")
}

func (u *Updater) ack() {
	u.mu.Lock()
	if r := readKV(u.resultP()); r != nil {
		u.st.Acked = r.i64("T")
	}
	if u.job != nil && u.job.Phase == "error" {
		u.job = nil
	}
	u.saveState()
	u.mu.Unlock()
}

func (u *Updater) schedule(ver string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Latest == nil || u.st.Latest.Ver != ver || cmpVer(ver, u.ver) <= 0 {
		return errors.New("没有这个新版本，请先检查更新")
	}
	u.st.Sched, u.st.SchedAt, u.st.Seen = ver, u.now().Unix(), ver
	u.saveState()
	return nil
}

func (u *Updater) unschedule() {
	u.mu.Lock()
	u.st.Sched = ""
	u.saveState()
	u.mu.Unlock()
}

// ---------------- 开始更新 ----------------

func (u *Updater) busyErr() error {
	if fileExists(u.markerP()) {
		return errors.New("正在更新 / 试运行中，请稍候")
	}
	if u.job != nil && u.job.Phase != "error" {
		return errors.New("正在更新，请稍候")
	}
	return nil
}

// Start：立即更新到 ver（必须是最近一次检查到的新版本）。auto=true 时（4:00 自动）上一版只能放内存就不更新。
func (u *Updater) Start(ver string, auto bool) error {
	u.mu.Lock()
	if err := u.busyErr(); err != nil {
		u.mu.Unlock()
		return err
	}
	r := u.st.Latest
	if r == nil || r.Ver != ver || cmpVer(ver, u.ver) <= 0 {
		u.mu.Unlock()
		return errors.New("没有这个新版本，请先检查更新")
	}
	rr := *r
	u.mu.Unlock()
	if rr.Missing != "" {
		return fmt.Errorf("v%s 缺少 %s，不能自动更新", rr.Ver, rr.Missing)
	}
	plan := u.space(&rr)
	if plan.Mode == "none" {
		return errors.New(plan.Msg)
	}
	if auto && plan.Mode != "flash" {
		return errors.New("闪存不够，上一版只能放内存，自动更新跳过（可以在面板里手动更新）")
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.mu.Lock()
	if err := u.busyErr(); err != nil {
		u.mu.Unlock()
		cancel()
		return err
	}
	u.job = &updJob{Kind: "update", Phase: "download", Ver: rr.Ver, Total: rr.GzSize, Start: u.now().Unix(), Where: plan.Mode}
	u.cancel = cancel
	if u.st.Sched == rr.Ver {
		u.st.Sched = ""
	}
	u.st.Seen = rr.Ver
	u.saveState()
	u.mu.Unlock()
	how := "手动"
	if auto {
		how = "自动（4:00）"
	}
	u.event("system", fmt.Sprintf("开始%s更新到 v%s", how, rr.Ver))
	go func() {
		err := u.runUpdate(ctx, &rr, plan)
		if err != nil {
			u.fail(err)
		}
	}()
	return nil
}

func (u *Updater) setPhase(ph string) {
	u.mu.Lock()
	if u.job != nil {
		u.job.Phase = ph
	}
	u.mu.Unlock()
}

func (u *Updater) fail(err error) {
	u.mu.Lock()
	if u.job != nil {
		u.job.Phase, u.job.Err = "error", err.Error()
	}
	u.mu.Unlock()
	os.RemoveAll(u.dlDir())
	u.event("error", "更新没完成："+err.Error())
}

func (u *Updater) runUpdate(ctx context.Context, r *relInfo, plan spacePlan) error {
	gz, rawSHA, rawSize, err := u.download(ctx, r, "tinylane-new.gz", func(done, total int64) {
		u.mu.Lock()
		if u.job != nil {
			u.job.Done, u.job.Total = done, total
		}
		u.mu.Unlock()
	}, u.setPhase)
	if err != nil {
		return err
	}
	// 解压后大小和 Release 标的不同：按实际大小重算一次空间
	if rawSize != r.RawSize {
		r.RawSize = rawSize
		if p2 := u.space(r); p2.Mode == "none" || (plan.Mode == "flash" && p2.Mode != "flash") {
			os.Remove(gz)
			if p2.Mode == "none" {
				return errors.New(p2.Msg)
			}
			plan = p2
		}
	}
	u.setPhase("backup")
	prevDir := u.flashPrev()
	if plan.Mode == "mem" {
		prevDir = u.memPrev()
	}
	// 只留一份上一版：旧的（闪存 / 内存）都替换掉
	os.RemoveAll(u.flashPrev())
	os.RemoveAll(u.memPrev())
	if err := os.MkdirAll(prevDir, 0o700); err != nil {
		return err
	}
	oldSHA, _, err := gzipFile(u.binP(), filepath.Join(prevDir, "tinylane.gz"))
	if err != nil {
		os.RemoveAll(prevDir)
		os.Remove(gz)
		return fmt.Errorf("备份旧版失败：%v", err)
	}
	cfgB, err := os.ReadFile(u.cfgP)
	if err == nil {
		err = writeFileAtomic(filepath.Join(prevDir, "tinylane.json"), cfgB, 0o600)
	}
	if err != nil {
		os.RemoveAll(prevDir)
		os.Remove(gz)
		return fmt.Errorf("备份配置失败：%v", err)
	}
	now := u.now().Unix()
	writeKV(filepath.Join(prevDir, "meta"), kvFile{"VER": u.ver, "SHA": oldSHA, "T": strconv.FormatInt(now, 10)})
	wgBefore := "none"
	if u.fns.wg != nil {
		if ex, age, err := u.fns.wg(); ex {
			wgBefore = "ok"
			if err != nil || age > 300 {
				wgBefore = "stale"
			}
		}
	}
	m := kvFile{"STATE": "ready", "KIND": "update", "NEW_VER": r.Ver, "OLD_VER": u.ver, "NEW_GZ": gz, "NEW_SHA": rawSHA,
		"PREV_DIR": prevDir, "PREV_BIN": filepath.Join(prevDir, "tinylane.gz"), "PREV_CONF": filepath.Join(prevDir, "tinylane.json"), "PREV_SHA": oldSHA,
		"WHERE": plan.Mode, "BIN": u.binP(), "CONF": u.cfgP, "INIT": u.init, "RES": u.resultP(),
		"START": strconv.FormatInt(now, 10), "CHECK_S": strconv.Itoa(u.checkS), "GRACE_S": strconv.Itoa(u.graceS), "BOOT_ID": u.bootID(), "WG_BEFORE": wgBefore}
	if err := writeKV(u.markerP(), m); err != nil {
		return fmt.Errorf("写试运行标记失败：%v", err)
	}
	os.Remove(u.resultP())
	u.setPhase("restart")
	u.saveSessions()
	if err := u.spawn("apply", u.markerP()); err != nil {
		os.Remove(u.markerP())
		return fmt.Errorf("启动更新脚本失败：%v", err)
	}
	return nil
}

// spawnHelper：把内置脚本写到 /usr/libexec/tinylane/，独立会话启动（服务停止也不会结束它）。
func (u *Updater) spawnHelper(mode, marker string) error {
	if err := u.installHelper(); err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", u.helperP(), mode, marker)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

func (u *Updater) installHelper() error {
	p := u.helperP()
	if b, err := os.ReadFile(p); err == nil && bytes.Equal(b, updHelperScript) {
		return nil
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	return writeFileAtomic(p, updHelperScript, 0o755)
}

// ---------------- 退回上一版 ----------------

// RevertInfo：退回会用哪一份（闪存/内存里的上一版，或 GitHub 上比当前旧的最新正式版）。
func (u *Updater) RevertInfo(ctx context.Context) (map[string]any, error) {
	if pc := u.prevCopy(); pc != nil && pc.Ver != "" && pc.Ver != u.ver {
		return map[string]any{"source": pc.Where, "ver": pc.Ver}, nil
	}
	r, err := u.pickFormal(ctx, func(v string) bool { return cmpVer(v, u.ver) < 0 })
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, errors.New("路由器上没有上一版，GitHub 上也没有比当前更旧的正式版")
		}
		return nil, fmt.Errorf("路由器上没有上一版，查 GitHub 失败：%s", updShortErr(err))
	}
	return map[string]any{"source": "github", "ver": r.Ver, "gz_size": r.GzSize}, nil
}

func (u *Updater) Revert(ver string) error {
	u.mu.Lock()
	if err := u.busyErr(); err != nil {
		u.mu.Unlock()
		return err
	}
	u.job = &updJob{Kind: "revert", Phase: "backup", Ver: ver, Start: u.now().Unix()}
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.mu.Unlock()
	go func() {
		if err := u.runRevert(ctx, ver); err != nil {
			u.fail(err)
		}
	}()
	return nil
}

func (u *Updater) runRevert(ctx context.Context, ver string) error {
	cur := fsize(u.binP())
	need := int64(float64(cur)*updGzRatio) + updMemReserve
	pc := u.prevCopy()
	var prevBin, prevConf, prevSHA string
	if pc != nil && pc.Ver == ver {
		m := readKV(filepath.Join(pc.dir, "meta"))
		prevBin, prevConf, prevSHA = filepath.Join(pc.dir, "tinylane.gz"), filepath.Join(pc.dir, "tinylane.json"), m["SHA"]
	} else {
		r, err := u.fetchTag(ctx, ver)
		if err != nil {
			return fmt.Errorf("查 v%s 失败：%s", ver, updShortErr(err))
		}
		need += r.GzSize
		if av := u.memAvail(); av < need {
			return fmt.Errorf("路由器可用内存不够，还差 %d MB", ceilMB(need-av))
		}
		u.setPhase("download")
		u.mu.Lock()
		u.job.Total = r.GzSize
		u.mu.Unlock()
		gz, sha, _, err := u.download(ctx, r, "tinylane-prev.gz", func(done, total int64) {
			u.mu.Lock()
			if u.job != nil {
				u.job.Done, u.job.Total = done, total
			}
			u.mu.Unlock()
		}, u.setPhase)
		if err != nil {
			return err
		}
		prevBin, prevSHA = gz, sha
	}
	if av := u.memAvail(); av < need {
		return fmt.Errorf("路由器可用内存不够，还差 %d MB", ceilMB(need-av))
	}
	u.setPhase("backup")
	os.MkdirAll(u.dlDir(), 0o700)
	curGz := filepath.Join(u.dlDir(), "tinylane-cur.gz")
	curSHA, _, err := gzipFile(u.binP(), curGz)
	if err != nil {
		return fmt.Errorf("临时备份当前版失败：%v", err)
	}
	m := kvFile{"STATE": "revert", "KIND": "revert", "OLD_VER": ver, "CUR_VER": u.ver, "PREV_BIN": prevBin, "PREV_SHA": prevSHA, "PREV_CONF": prevConf,
		"CUR_GZ": curGz, "CUR_SHA": curSHA, "BIN": u.binP(), "CONF": u.cfgP, "INIT": u.init, "RES": u.resultP(), "START": strconv.FormatInt(u.now().Unix(), 10)}
	if pc != nil && pc.Ver == ver {
		m["PREV_DIR"] = pc.dir
	}
	if err := writeKV(u.markerP(), m); err != nil {
		return err
	}
	// 退回后不再弹这个版本（正式版才记）
	u.mu.Lock()
	if isFormalTag("v" + u.ver) {
		u.st.Skip, u.st.Seen = u.ver, u.ver
	}
	u.saveState()
	u.mu.Unlock()
	u.event("system", fmt.Sprintf("手动退回：%s → v%s", u.ver, ver))
	u.setPhase("restart")
	u.saveSessions()
	if err := u.spawn("revert", u.markerP()); err != nil {
		os.Remove(u.markerP())
		return err
	}
	return nil
}

// ---------------- 新版启动后：试运行 / 自检 ----------------

// Resume：守护进程启动时调用。处理试运行标记和上次的结果。
func (u *Updater) Resume(ctx context.Context) {
	u.installHelper()
	u.loadSessions()
	u.logResult()
	m := readKV(u.markerP())
	if m == nil {
		return
	}
	alive := u.helperUp(m["HELPER_PID"])
	switch m["STATE"] {
	case "check", "swap":
		if m["NEW_VER"] != u.ver {
			if alive {
				return // 辅助脚本正在处理（例如正在退回）
			}
			// 旧版在跑、辅助脚本不在：更新被中断
			writeKV(u.resultP(), kvFile{"RESULT": "interrupted", "FROM": m["NEW_VER"], "TO": u.ver, "KIND": "update",
				"REASON": "更新被中断，仍在用 " + u.ver, "T": strconv.FormatInt(u.now().Unix(), 10)})
			os.Remove(u.markerP())
			os.RemoveAll(u.dlDir())
			u.logResult()
			return
		}
		if m["BOOT_ID"] != u.bootID() || !alive {
			u.rearm(ctx, m)
		}
		go u.selfCheck(ctx)
	case "rollback", "rollback_req":
		if !alive {
			u.spawn("rollback", u.markerP())
		}
	case "ready", "revert":
		// 写了标记但辅助脚本没跑起来（守护进程中途被杀）
		if !alive && m["NEW_VER"] != u.ver {
			os.Remove(u.markerP())
			os.RemoveAll(u.dlDir())
		}
	}
}

// rearm：开机后（或辅助脚本不在了）重新开始试运行：确保有旧版可退，重新计时，重启死人开关。
func (u *Updater) rearm(ctx context.Context, m kvFile) {
	why := "开机时发现未完成的更新试运行，重新自检 3 分钟"
	if m["BOOT_ID"] == u.bootID() {
		why = "更新辅助进程不在了，重新自检 3 分钟"
	}
	if !fileExists(m["PREV_BIN"]) {
		// 内存里的旧版随重启丢了：从 GitHub 下载标记里记的旧版
		ok := false
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if r, err := u.fetchTag(ctx, m["OLD_VER"]); err == nil {
			if gz, sha, _, err := u.download(ctx, r, "tinylane-old.gz", func(int64, int64) {}, func(string) {}); err == nil {
				dir := u.memPrev()
				os.MkdirAll(dir, 0o700)
				dst := filepath.Join(dir, "tinylane.gz")
				if os.Rename(gz, dst) == nil {
					writeKV(filepath.Join(dir, "meta"), kvFile{"VER": m["OLD_VER"], "SHA": sha, "T": strconv.FormatInt(u.now().Unix(), 10)})
					m["PREV_DIR"], m["PREV_BIN"], m["PREV_SHA"], m["PREV_CONF"] = dir, dst, sha, ""
					ok = true
					why += "；内存里的旧版已丢失，已从 GitHub 重新下载 v" + m["OLD_VER"]
				}
			}
		}
		if !ok {
			m["NOROLLBACK"] = "1"
			why += "；内存里的旧版已丢失，GitHub 上也下载不到 v" + m["OLD_VER"] + "，自检不过也无法自动退回"
		}
	}
	m["STATE"], m["CHECK_START"], m["BOOT_ID"], m["HELPER_PID"] = "check", strconv.FormatInt(u.now().Unix(), 10), u.bootID(), ""
	writeKV(u.markerP(), m)
	u.event("system", why)
	u.spawn("watch", u.markerP())
}

func (u *Updater) setItems(it []trialItem) {
	u.mu.Lock()
	u.items = it
	u.trial = true
	u.mu.Unlock()
}

// runChecks：跑一轮自检，返回各项结果。
func (u *Updater) runChecks(ctx context.Context, m kvFile) []trialItem {
	type c struct {
		k, n string
		f    func(context.Context) error
	}
	list := []c{{"core", "代理内核运行", u.fns.core}, {"panel", "面板能打开", u.fns.panel}, {"cn", "国内网站（百度）", u.fns.cn}, {"intl", "国外网站（经代理）", u.fns.intl}}
	out := make([]trialItem, 0, 5)
	var wg sync.WaitGroup
	res := make([]trialItem, len(list))
	for i, x := range list {
		res[i] = trialItem{K: x.k, Name: x.n}
		if x.f == nil {
			res[i].OK, res[i].Skip = true, true
			continue
		}
		wg.Add(1)
		go func(i int, f func(context.Context) error) {
			defer wg.Done()
			cx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := f(cx); err != nil {
				res[i].Detail = updShortErr(err)
			} else {
				res[i].OK = true
			}
		}(i, x.f)
	}
	wg.Wait()
	out = append(out, res...)
	w := trialItem{K: "wg", Name: "wg0 远程链路"}
	switch {
	case u.fns.wg == nil:
		w.OK, w.Skip, w.Detail = true, true, "没有 wg0"
	default:
		ex, age, err := u.fns.wg()
		switch {
		case !ex:
			w.OK, w.Skip, w.Detail = true, true, "这台路由器没有 wg0"
		case m["WG_BEFORE"] == "stale":
			w.OK, w.Skip, w.Detail = true, true, "更新前就没有握手，跳过"
		case err != nil:
			w.Detail = updShortErr(err)
		case age > 300:
			w.Detail = fmt.Sprintf("最近握手 %d 秒前，已过期", age)
		default:
			w.OK, w.Detail = true, fmt.Sprintf("最近握手 %d 秒前", age)
		}
	}
	return append(out, w)
}

func failedNames(it []trialItem) []string {
	var f []string
	for _, x := range it {
		if !x.OK {
			s := x.Name
			if x.Detail != "" {
				s += "（" + x.Detail + "）"
			}
			f = append(f, s)
		}
	}
	return f
}

// selfCheck：3 分钟试运行。期间每 15 秒一轮（给面板看进度），到点时最后判一次：没过的项再试 2 次（间隔 5 秒）。
func (u *Updater) selfCheck(ctx context.Context) {
	m := readKV(u.markerP())
	if m == nil {
		return
	}
	deadline := time.Unix(m.i64("CHECK_START")+int64(u.checkS), 0)
	// 先等内核和面板起来（最多 2 轮间隔），免得第一轮全是「连不上」
	for warm := u.now().Add(2 * u.pollEvery); u.now().Before(warm) && u.now().Before(deadline); {
		if u.fns.core == nil || u.fns.core(ctx) == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(u.pollEvery / 5):
		}
	}
	var last []trialItem
	for {
		last = u.runChecks(ctx, m)
		u.setItems(last)
		if !u.now().Before(deadline) || ctx.Err() != nil {
			break
		}
		wait := deadline.Sub(u.now())
		if wait > u.pollEvery {
			wait = u.pollEvery
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if readKV(u.markerP()) == nil {
			return
		}
	}
	for try := 0; try < 2 && len(failedNames(last)) > 0; try++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(u.pollEvery / 3):
		}
		again := u.runChecks(ctx, m)
		for i := range last {
			if !last[i].OK && again[i].OK {
				last[i] = again[i]
			}
		}
		u.setItems(last)
	}
	u.finishTrial(m, last)
}

func (u *Updater) finishTrial(m kvFile, items []trialItem) {
	now := strconv.FormatInt(u.now().Unix(), 10)
	bad := failedNames(items)
	if len(bad) == 0 {
		writeKV(u.resultP(), kvFile{"RESULT": "ok", "FROM": m["OLD_VER"], "TO": u.ver, "KIND": "update", "REASON": "", "T": now, "LOGGED": "1"})
		if m["WHERE"] == "mem" || strings.HasPrefix(m["PREV_DIR"], u.memPrev()) {
			pm := readKV(filepath.Join(u.memPrev(), "meta"))
			if pm != nil {
				pm["UNTIL"] = strconv.FormatInt(u.now().Add(updMemKeep).Unix(), 10)
				writeKV(filepath.Join(u.memPrev(), "meta"), pm)
			}
		}
		os.Remove(u.markerP())
		os.RemoveAll(u.dlDir())
		u.event("system", "已更新到 v"+u.ver+"，自检通过")
		return
	}
	why := "自检没通过：" + strings.Join(bad, "；")
	u.event("error", why)
	if m["NOROLLBACK"] == "1" || !fileExists(m["PREV_BIN"]) {
		writeKV(u.resultP(), kvFile{"RESULT": "rollback_failed", "FROM": u.ver, "TO": m["OLD_VER"], "KIND": "update",
			"REASON": why + "；旧版已丢失，无法自动退回，保持现状", "T": now})
		os.Remove(u.markerP())
		return
	}
	cur := readKV(u.markerP())
	if cur == nil {
		return
	}
	cur["STATE"], cur["REASON"] = "rollback_req", why
	writeKV(u.markerP(), cur)
	if !u.helperUp(cur["HELPER_PID"]) {
		u.spawn("rollback", u.markerP())
	}
}

// logResult：把辅助脚本写的结果（退回 / 手动退回）记进事件，只记一次。
func (u *Updater) logResult() {
	r := readKV(u.resultP())
	if r == nil || r["LOGGED"] == "1" {
		return
	}
	switch r["RESULT"] {
	case "rolled_back":
		u.event("error", fmt.Sprintf("自检没通过，已退回 v%s：%s", r["TO"], strings.TrimPrefix(r["REASON"], "自检没通过：")))
	case "rollback_failed":
		u.event("error", "更新后退回失败："+r["REASON"])
	case "reverted":
		u.event("system", fmt.Sprintf("已退回 v%s", r["TO"]))
	case "revert_failed", "interrupted":
		u.event("error", r["REASON"])
	case "ok":
		u.event("system", "已更新到 v"+r["TO"]+"，自检通过")
	}
	r["LOGGED"] = "1"
	writeKV(u.resultP(), r)
}

// ---------------- 定时：每天检查 / 4:00 更新 / 清理内存里的上一版 ----------------

func (u *Updater) tick(ctx context.Context) {
	now := u.now()
	// 内存里的上一版：通过后保留 24 小时；可用内存低于 40 MB 提前删（试运行中不删）
	if !fileExists(u.markerP()) {
		if pm := readKV(filepath.Join(u.memPrev(), "meta")); pm != nil {
			until := pm.i64("UNTIL")
			if until == 0 {
				pm["UNTIL"] = strconv.FormatInt(now.Add(updMemKeep).Unix(), 10)
				writeKV(filepath.Join(u.memPrev(), "meta"), pm)
			} else if now.Unix() >= until {
				os.RemoveAll(u.memPrev())
				u.event("system", "内存里临时保留的上一版（v"+pm["VER"]+"）已满 24 小时，已删除")
			} else if u.memAvail() < updMemReserve {
				os.RemoveAll(u.memPrev())
				u.event("system", "可用内存低于 40 MB，提前删除内存里的上一版（v"+pm["VER"]+"）")
			}
		}
		u.mu.Lock()
		idle := u.job == nil || u.job.Phase == "error"
		u.mu.Unlock()
		if idle && fileExists(u.dlDir()) {
			os.RemoveAll(u.dlDir())
		}
		if st, err := os.Stat(u.sessFile()); err == nil && now.Sub(st.ModTime()) > 30*time.Minute {
			os.Remove(u.sessFile())
		}
	}
	u.mu.Lock()
	last := u.st.LastCheck
	u.mu.Unlock()
	if now.Sub(time.Unix(last, 0)) >= updCheckEvery {
		u.Check(ctx)
	}
	// 4:00（上海时间）更新：「今晚 4:00 更新」点过的版本，或开了自动更新
	cst := now.In(cst)
	if cst.Hour() == 4 && cst.Minute() < 30 {
		day := cst.Format("2006-01-02")
		u.mu.Lock()
		done := u.st.AutoDay == day
		sched := u.st.Sched
		u.mu.Unlock()
		if done || (sched == "" && !u.autoOn()) {
			return
		}
		u.mu.Lock()
		u.st.AutoDay = day
		u.saveState()
		u.mu.Unlock()
		u.Check(ctx)
		u.mu.Lock()
		r := u.st.Latest
		skip := u.st.Skip
		u.mu.Unlock()
		if r == nil || cmpVer(r.Ver, u.ver) <= 0 {
			u.unschedule()
			return
		}
		if sched == r.Ver {
			if err := u.Start(r.Ver, false); err != nil {
				u.event("error", "4:00 更新没开始："+err.Error())
			}
			return
		}
		if u.autoOn() && r.Ver != skip {
			if err := u.Start(r.Ver, true); err != nil {
				u.event("system", "自动更新跳过："+err.Error())
			}
		}
	}
}

func (u *Updater) loop(ctx context.Context) {
	u.Resume(ctx)
	// 启动 3 分钟后再做第一次检查（别和试运行 / 开机抢网络）
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Minute):
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		u.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------- 真实自检项 ----------------

func (u *Updater) realChecks() checkFns {
	d := u.d
	httpOK := func(ctx context.Context, raw, proxy string, want func(int) bool) error {
		tr := &http.Transport{Proxy: nil}
		if proxy != "" {
			pu, _ := url.Parse("http://" + proxy)
			tr.Proxy = http.ProxyURL(pu)
		}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
		req.Header.Set("User-Agent", "tinylane-selfcheck")
		cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if !want(resp.StatusCode) {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
	return checkFns{
		core: func(ctx context.Context) error {
			if d.fallback.Load() {
				return errors.New("内核多次崩溃，已自保直连")
			}
			if !d.coreUp.Load() {
				return errors.New("内核没有响应")
			}
			var v map[string]any
			return d.clash().doCtx(ctx, 5*time.Second, "GET", "/version", nil, &v)
		},
		panel: func(ctx context.Context) error {
			if d.panel == nil {
				return nil
			}
			ls := d.panel.listenAddrs()
			if len(ls) == 0 {
				return errors.New("面板没有监听地址")
			}
			return httpOK(ctx, "http://"+ls[0]+"/", "", func(c int) bool { return c == 200 })
		},
		cn: func(ctx context.Context) error {
			return httpOK(ctx, u.cnURL, "", func(c int) bool { return c < 400 })
		},
		intl: func(ctx context.Context) error {
			if px := d.conf().MixedListen; px != "" {
				return httpOK(ctx, u.intlURL, px, func(c int) bool { return c == 204 || c == 200 })
			}
			g := d.conf().MainGroup
			var r map[string]any
			return d.clash().doCtx(ctx, 8*time.Second, "GET", "/group/"+url.PathEscape(g)+"/delay?timeout=5000&url="+url.QueryEscape(u.intlURL), nil, &r)
		},
		wg: func() (bool, int64, error) {
			if !fileExists("/sys/class/net/wg0") {
				return false, 0, nil
			}
			out, err := exec.Command("wg", "show", "wg0", "latest-handshakes").Output()
			if err != nil {
				return true, 0, nil // 没有 wg 命令：只确认接口在
			}
			var newest int64
			for _, ln := range strings.Split(string(out), "\n") {
				f := strings.Fields(ln)
				if len(f) == 2 {
					if t, _ := strconv.ParseInt(f[1], 10, 64); t > newest {
						newest = t
					}
				}
			}
			if newest == 0 {
				return true, 1 << 30, errors.New("还没有握手")
			}
			return true, time.Now().Unix() - newest, nil
		},
	}
}

// ---------------- 面板接口 ----------------

func (p *Panel) routesM11() map[string]handler {
	d := p.d
	u := func() (*Updater, error) {
		if d.upd == nil {
			return nil, errors.New("更新模块没启动")
		}
		return d.upd, nil
	}
	return map[string]handler{
		"GET /update/status": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			return x.Status(), nil
		},
		"POST /update/check": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
			defer cancel()
			if err := x.Check(ctx); err != nil {
				return nil, err
			}
			return x.Status(), nil
		},
		"POST /update/seen": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			x.setSeen(gets(in, "ver"))
			return nil, nil
		},
		"POST /update/skip": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			v := gets(in, "ver")
			if _, ok := parseVer(v); !ok {
				return nil, errors.New("版本号无效")
			}
			x.setSkip(v)
			return nil, nil
		},
		"POST /update/start": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			v := gets(in, "ver")
			switch gets(in, "when") {
			case "4am":
				if err := x.schedule(v); err != nil {
					return nil, err
				}
				x.event("system", "已安排今晚 4:00 更新到 v"+v)
				return x.Status(), nil
			case "cancel":
				x.unschedule()
				return x.Status(), nil
			}
			if err := x.Start(v, false); err != nil {
				return nil, err
			}
			return x.Status(), nil
		},
		"POST /update/auto": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			on := getb(in, "on")
			desc := "自动更新已关闭"
			if on {
				desc = "自动更新已打开（只在 4:00 更新正式版）"
			}
			return nil, d.applyEdit(applyOpts{desc: desc}, func(m map[string]any) error {
				um, _ := m["update"].(map[string]any)
				if um == nil {
					um = map[string]any{}
				}
				um["auto"] = on
				m["update"] = um
				return nil
			})
		},
		"POST /update/revert": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			info, err := x.RevertInfo(ctx)
			if err != nil {
				return nil, err
			}
			if !getb(in, "confirm") {
				return info, nil
			}
			if v := gets(in, "ver"); v != info["ver"] {
				return nil, errors.New("上一版信息变了，请重新打开")
			}
			if err := x.Revert(info["ver"].(string)); err != nil {
				return nil, err
			}
			return x.Status(), nil
		},
		"POST /update/ack": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			x, err := u()
			if err != nil {
				return nil, err
			}
			x.ack()
			return nil, nil
		},
	}
}

// ---------------- 更新时保留面板登录 ----------------
// 守护进程重启会清空内存里的面板会话；更新前把会话写到 /tmp（0600，只在内存里），新版（或退回后的旧版）
// 启动时读回，面板就能自动重连而不用重新登录。文件 30 分钟后删除。

type sessDump struct {
	T       string `json:"t"`
	Exp     int64  `json:"exp"`
	Luci    string `json:"luci,omitempty"`
	Checked int64  `json:"checked"`
}

func (u *Updater) sessFile() string { return u.p("/tmp/tinylane-sessions.json") }

func (u *Updater) saveSessions() {
	if u.d == nil || u.d.panel == nil {
		return
	}
	p := u.d.panel
	p.mu.Lock()
	var l []sessDump
	for k, s := range p.sessions {
		l = append(l, sessDump{T: k, Exp: s.exp.Unix(), Luci: s.luciSID, Checked: s.checked.Unix()})
	}
	p.mu.Unlock()
	b, _ := json.Marshal(l)
	writeFileAtomic(u.sessFile(), b, 0o600)
}

func (u *Updater) loadSessions() {
	st, err := os.Stat(u.sessFile())
	if err != nil {
		return
	}
	if time.Since(st.ModTime()) > 30*time.Minute {
		os.Remove(u.sessFile())
		return
	}
	if u.d == nil || u.d.panel == nil {
		return
	}
	b, _ := os.ReadFile(u.sessFile())
	var l []sessDump
	if json.Unmarshal(b, &l) != nil {
		return
	}
	p := u.d.panel
	p.mu.Lock()
	for _, s := range l {
		if len(s.T) >= 32 && time.Unix(s.Exp, 0).After(time.Now()) && len(p.sessions) < 32 {
			p.sessions[s.T] = &psess{exp: time.Unix(s.Exp, 0), luciSID: s.Luci, checked: time.Unix(s.Checked, 0)}
		}
	}
	p.mu.Unlock()
}
