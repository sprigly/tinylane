package main

// M6b：面板图标（favicon / apple-touch-icon / PWA manifest）。文件由 shots/icon/build_icons.py 生成到 web/icons/，
// build.sh 拷进 icons/ 后 go:embed；不需要登录即可读取（浏览器取 favicon 时不带会话也要能拿到）。
import (
	"embed"
	"net/http"
	"path"
)

//go:embed icons/favicon.ico icons/favicon.svg icons/apple-touch-icon.png icons/icon-192.png icons/icon-512.png icons/manifest.webmanifest
var iconFS embed.FS

var iconTypes = map[string]string{
	"/favicon.ico":          "image/x-icon",
	"/favicon.svg":          "image/svg+xml",
	"/apple-touch-icon.png": "image/png",
	"/icon-192.png":         "image/png",
	"/icon-512.png":         "image/png",
	"/manifest.webmanifest": "application/manifest+json",
}

func (p *Panel) icon(w http.ResponseWriter, r *http.Request) {
	ct, ok := iconTypes[r.URL.Path]
	if !ok || (r.Method != "GET" && r.Method != "HEAD") {
		http.NotFound(w, r)
		return
	}
	b, err := iconFS.ReadFile("icons/" + path.Base(r.URL.Path))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	secHeaders(w)
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Write(b)
}
