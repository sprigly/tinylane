#!/bin/sh
# TinyLane 透明代理 nftables + 策略路由。用法：tinylane-nft.sh up|down|status
# - 只挂 prerouting（LAN 口进来的流量）；路由器本机流量（含 wg0、sing-box 自己的出站）不经过。
# - 规则文件由 `tinylane gen --nft` 生成：/var/run/tinylane/tinylane.nft
# - down 必须做到：表、ip rule、路由表全部删干净；重复执行无副作用。
RUN=${RUN:-/var/run/tinylane}
[ -f "$RUN/env" ] && . "$RUN/env"
FWMARK=${FWMARK:-0x7a}
ROUTE_TABLE=${ROUTE_TABLE:-100}
NFT_FILE=${NFT_FILE:-$RUN/tinylane.nft}
log() { logger -t tinylane-nft "$*"; echo "$*"; }

route_up() {
	ip -4 rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null
	ip -4 rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE" pref 9100
	ip -4 route replace local 0.0.0.0/0 dev lo table "$ROUTE_TABLE"
}

route_down() {
	while ip -4 rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null; do :; done
	ip -4 route flush table "$ROUTE_TABLE" 2>/dev/null
	return 0
}

dns_on() {
	# dnsmasq 继续做局域网 DNS（DHCP/.lan/防重绑定），上游改成 sing-box 的 dns 入站
	local want="127.0.0.1#${DNS_PORT:-1053}"
	[ "$(uci -q get dhcp.@dnsmasq[0].server)" = "$want" ] && return 0
	uci -q delete dhcp.@dnsmasq[0].server
	uci add_list dhcp.@dnsmasq[0].server="$want"
	uci set dhcp.@dnsmasq[0].noresolv='1'
	uci commit dhcp
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	log "dnsmasq 上游 → $want"
}

dns_off() {
	# 恢复为普通国内 DNS（只在当前是我们接管的状态时才改）
	local cur fb s
	cur="$(uci -q get dhcp.@dnsmasq[0].server)"
	case "$cur" in *"127.0.0.1#${DNS_PORT:-1053}"*) ;; *) return 0 ;; esac
	fb="${FALLBACK_DNS:-223.5.5.5 119.29.29.29}"
	uci -q delete dhcp.@dnsmasq[0].server
	for s in $fb; do uci add_list dhcp.@dnsmasq[0].server="$s"; done
	uci set dhcp.@dnsmasq[0].noresolv='1'
	uci commit dhcp
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	log "dnsmasq 上游 → $fb"
}

case "$1" in
dns-on) dns_on ;;
dns-off) dns_off ;;
up)
	[ -s "$NFT_FILE" ] || { log "缺少 $NFT_FILE，先运行 tinylane gen"; exit 1; }
	nft -c -f "$NFT_FILE" || { log "nft 规则语法检查失败，不加载"; exit 1; }
	route_up || { log "策略路由失败"; route_down; exit 1; }
	nft -f "$NFT_FILE" || { log "nft 加载失败，回退"; route_down; exit 1; }
	log "透明代理已启用（mark $FWMARK → table $ROUTE_TABLE，tproxy :${TPROXY_PORT:-7893}）"
	;;
down)
	nft delete table inet tinylane 2>/dev/null
	route_down
	log "透明代理已关闭（table inet tinylane / ip rule / table $ROUTE_TABLE 已清除）"
	;;
acct-up)
	# 按设备流量计数表（M6）：独立的 inet tinylane_acct，只计数、policy accept；已存在就不动（保留计数）
	nft list table inet tinylane_acct >/dev/null 2>&1 && exit 0
	[ -s "$ACCT_FILE" ] || { echo "缺少 ACCT_FILE"; exit 1; }
	nft -c -f "$ACCT_FILE" && nft -f "$ACCT_FILE"
	;;
acct-dump)
	nft list set inet tinylane_acct up4 && nft list set inet tinylane_acct down4
	;;
acct-down)
	nft delete table inet tinylane_acct 2>/dev/null; exit 0
	;;
status)
	nft list table inet tinylane 2>/dev/null | grep -E "counter|elements" | cut -c1-160 || echo "table inet tinylane: 不存在"
	ip -4 rule | grep -i "lookup $ROUTE_TABLE" || echo "ip rule: 无"
	ip -4 route show table "$ROUTE_TABLE" 2>/dev/null
	;;
*)
	echo "用法: $0 up|down|status|dns-on|dns-off|acct-up|acct-dump|acct-down"; exit 2 ;;
esac
