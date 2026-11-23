#!/bin/sh
# 在沙盒编译 tinylane（linux/arm64）。源码在 src/，同步进 sing-box v1.14.4 源码树后编译。
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
# 可用环境变量覆盖：SB=sing-box v1.14.4 源码目录，GOBIN_DIR=Go 所在目录，GOMODCACHE=模块缓存（CI 里用默认值）
SB=${SB:-/workspace/work/sbbuild/sing-box}
[ -n "${GOBIN_DIR:-}" ] && export PATH=$GOBIN_DIR:$PATH
[ -d /workspace/work/sbbuild/go/bin ] && export PATH=/workspace/work/sbbuild/go/bin:$PATH
[ -d /workspace/work/sbbuild/gomod ] && export GOMODCACHE=${GOMODCACHE:-/workspace/work/sbbuild/gomod}
export GOFLAGS=-mod=mod CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH:-arm64} GOTOOLCHAIN=local
rm -rf "$SB/cmd/tinylane"; mkdir -p "$SB/cmd/tinylane"
cp "$HERE"/src/cmd/tinylane/*.go "$HERE"/src/cmd/tinylane/tinylane-update.sh "$SB/cmd/tinylane/"
# M11：自更新辅助脚本（go:embed 进程序；files/ 里放同一份供手动部署）
cp "$HERE"/src/cmd/tinylane/tinylane-update.sh "$HERE"/files/usr/libexec/tinylane/tinylane-update.sh
# M6b 图标：web/icons → src/cmd/tinylane/icons（go:embed）
mkdir -p "$HERE/src/cmd/tinylane/icons" "$SB/cmd/tinylane/icons"
for f in favicon.ico favicon.svg apple-touch-icon.png icon-192.png icon-512.png manifest.webmanifest; do cp "$HERE/web/icons/$f" "$HERE/src/cmd/tinylane/icons/"; done
cp "$HERE"/src/cmd/tinylane/icons/* "$SB/cmd/tinylane/icons/"
python3 "$HERE"/web/assemble.py
gzip -9 -n -c "$HERE"/web/app.html > "$HERE"/src/cmd/tinylane/webui.html.gz
cp "$HERE"/src/cmd/tinylane/webui.html.gz "$SB/cmd/tinylane/"
cp "$HERE"/src/include/registry.go "$HERE"/src/include/clashapi.go "$SB/include/"
# include/ 只留精简注册表 + clash_api（和路由器上一直跑的构建一致；其余协议文件不编进来）
find "$SB/include" -maxdepth 1 -name '*.go' ! -name registry.go ! -name clashapi.go ! -name clashapi_stub.go -delete
# M6d：DNS 应答旁路钩子（内核直连域名反查）。只插一行调用，幂等
cp "$HERE"/src/patch/dns/tl_hook.go "$SB/dns/"
grep -q 'tlCallDNSHook(response)' "$SB/dns/router.go" || sed -i 's/^func (r \*Router) recordReverseMapping(message \*mDNS.Msg, response \*mDNS.Msg, transport adapter.DNSTransport) {$/&\n\ttlCallDNSHook(response)/' "$SB/dns/router.go"
grep -q 'tlCallDNSHook(response)' "$SB/dns/router.go" || { echo "patch dns/router.go 失败"; exit 1; }
# 私有构建参数（不进仓库）：TL_BUILTIN_BYPASS=远程运维链路网段，逗号分隔
# 发布版（TL_RELEASE=1，CI 和沙盒复现构建都用）不带私有参数，保证任何人按同样方式都能编出逐字节相同的程序
if [ -n "${TL_RELEASE:-}" ]; then TL_BUILTIN_BYPASS=; elif [ -f "$HERE/secret/build.env" ]; then . "$HERE/secret/build.env"; fi
cd "$SB"
# 默认输出 out/tinylane-dev-*；发布版用 OUT= 指定，别覆盖 out/ 里的回滚用二进制
OUT=${OUT:-$HERE/out/tinylane-dev-linux-$GOARCH}
mkdir -p "$(dirname "$OUT")"
go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=1.14.4 -X main.builtinBypass=${TL_BUILTIN_BYPASS:-}" -tags with_quic,with_clash_api,with_gvisor,with_utls -o "$OUT" ./cmd/tinylane
ls -l "$OUT"
