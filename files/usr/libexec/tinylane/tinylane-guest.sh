#!/bin/sh
# TinyLane 访客 Wi‑Fi（M6）。用法：tinylane-guest.sh apply|up|down|status|plan
# - 独立 SSID → 独立网桥 br-tlguest（默认 192.168.77.1/24）+ 独立防火墙区 tlguest：
#   只允许 → wan；不能访问 LAN、路由器管理（只放行 DHCP/DNS）；同一访客网内客户端隔离。
# - TinyLane 只接管 br-lan 进来的流量，所以访客流量天然「仅直连」，不会进代理。
# - apply = 按 GUEST_ENV（ENABLED/SSID/KEY/BAND/GUEST_IP）执行 up 或 down，并自检：
#   主 Wi‑Fi 的 hostapd 接口都还在、远程运维链路（WG_PING，如 WireGuard 对端 IP；空 = 不查）能 ping 通；自检失败自动 down 撤回。
# - 只改 uci 的 tlguest* 段（network / wireless / dhcp / firewall），一次 network reload（含 Wi‑Fi）。
# - 测试：UCI_DIR=<目录> DRY=1 只改那个目录里的配置副本，不重载任何服务。
RUN=${RUN:-/var/run/tinylane}
GUEST_ENV=${GUEST_ENV:-$RUN/guest.env}
[ -f "$GUEST_ENV" ] && . "$GUEST_ENV"
BAND=${BAND:-both}; GUEST_IP=${GUEST_IP:-192.168.77.1}
U() { if [ -n "$UCI_DIR" ]; then uci -c "$UCI_DIR" "$@"; else uci "$@"; fi; }
log() { logger -t tinylane-guest "$*" 2>/dev/null; echo "$*"; }

radios() {
	U show wireless 2>/dev/null | sed -n 's/^wireless\.\([A-Za-z0-9_]*\)=wifi-device$/\1/p' | while read -r r; do
		b=$(U -q get "wireless.$r.band")
		case "$BAND" in both) echo "$r" ;; *) [ "$b" = "$BAND" ] && echo "$r" ;; esac
	done
}

del_all() {
	for s in $(U show wireless 2>/dev/null | sed -n 's/^wireless\.\(tlguest_[A-Za-z0-9_]*\)=wifi-iface$/\1/p'); do U -q delete "wireless.$s"; done
	U -q delete network.tlguest; U -q delete network.tlguest_br
	U -q delete dhcp.tlguest
	for s in tlguest_zone tlguest_fwd tlguest_dhcp tlguest_dns; do U -q delete "firewall.$s"; done
}

write_cfg() {
	del_all
	U set network.tlguest_br=device
	U set network.tlguest_br.type=bridge
	U set network.tlguest_br.name=br-tlguest
	U set network.tlguest_br.bridge_empty=1
	U set network.tlguest=interface
	U set network.tlguest.proto=static
	U set network.tlguest.device=br-tlguest
	U set "network.tlguest.ipaddr=$GUEST_IP"
	U set network.tlguest.netmask=255.255.255.0
	U set dhcp.tlguest=dhcp
	U set dhcp.tlguest.interface=tlguest
	U set dhcp.tlguest.start=100
	U set dhcp.tlguest.limit=100
	U set dhcp.tlguest.leasetime=2h
	U set dhcp.tlguest.dhcpv4=server
	U set firewall.tlguest_zone=zone
	U set firewall.tlguest_zone.name=tlguest
	U set firewall.tlguest_zone.network=tlguest
	U set firewall.tlguest_zone.input=REJECT
	U set firewall.tlguest_zone.output=ACCEPT
	U set firewall.tlguest_zone.forward=REJECT
	U set firewall.tlguest_fwd=forwarding
	U set firewall.tlguest_fwd.src=tlguest
	U set firewall.tlguest_fwd.dest=wan
	U set firewall.tlguest_dhcp=rule
	U set firewall.tlguest_dhcp.name=TinyLane-Guest-DHCP
	U set firewall.tlguest_dhcp.src=tlguest
	U set firewall.tlguest_dhcp.proto=udp
	U set firewall.tlguest_dhcp.dest_port=67
	U set firewall.tlguest_dhcp.target=ACCEPT
	U set firewall.tlguest_dns=rule
	U set firewall.tlguest_dns.name=TinyLane-Guest-DNS
	U set firewall.tlguest_dns.src=tlguest
	U set firewall.tlguest_dns.proto='tcp udp'
	U set firewall.tlguest_dns.dest_port=53
	U set firewall.tlguest_dns.target=ACCEPT
	n=0
	for r in $(radios); do
		s="tlguest_$r"
		U set "wireless.$s=wifi-iface"
		U set "wireless.$s.device=$r"
		U set "wireless.$s.mode=ap"
		U set "wireless.$s.network=tlguest"
		U set "wireless.$s.ssid=$SSID"
		if [ -n "$KEY" ]; then U set "wireless.$s.encryption=psk2"; U set "wireless.$s.key=$KEY"; else U set "wireless.$s.encryption=none"; fi
		U set "wireless.$s.isolate=1"
		U set "wireless.$s.ifname=tlg$n"   # 固定接口名 → hostapd.tlgN，自检时好和主 Wi‑Fi 区分
		n=$((n + 1))
	done
	[ "$n" -gt 0 ] || { echo "没有可用的无线电（频段 $BAND）"; return 1; }
}

commit_reload() {
	U commit network; U commit wireless; U commit dhcp; U commit firewall
	[ -n "$DRY" ] && return 0
	/etc/init.d/network reload >/dev/null 2>&1   # netifd 一次性应用 network + wireless（只重启受影响的无线电）
	/etc/init.d/firewall reload >/dev/null 2>&1
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
}

aps() { ubus list 'hostapd.*' 2>/dev/null | sort; }
wg_ok() { [ -z "$WG_PING" ] && return 0; ping -c 2 -W 2 "$WG_PING" >/dev/null 2>&1; }

verify() {
	# $1 = 应用前的 hostapd 接口列表文件；$2 = 应用前 wg 是否通
	i=0
	while [ $i -lt 30 ]; do
		sleep 2; i=$((i + 2))
		miss=0
		for a in $(cat "$1"); do
			aps | grep -qx "$a" || miss=1
			[ $miss = 0 ] && { ubus call "$a" get_status 2>/dev/null | grep -q '"status": "ENABLED"' || miss=1; }
		done
		[ $miss = 0 ] || continue
		if [ "$2" = 1 ] && ! wg_ok; then continue; fi
		return 0
	done
	return 1
}

case "$1" in
plan)
	write_cfg && U changes 2>/dev/null; U revert network; U revert wireless; U revert dhcp; U revert firewall ;;
up)
	write_cfg || exit 1; commit_reload; log "访客 Wi‑Fi 已写入并重载" ;;
down)
	del_all; commit_reload; log "访客 Wi‑Fi 已删除并重载" ;;
apply)
	if [ -n "$DRY" ]; then
		if [ "$ENABLED" = 1 ]; then write_cfg && U commit network && U commit wireless && U commit dhcp && U commit firewall && echo "OK（DRY）已写入"; else del_all; U commit network; U commit wireless; U commit dhcp; U commit firewall; echo "OK（DRY）已删除"; fi
		exit 0
	fi
	pre=/tmp/tl-guest-pre.$$; aps | grep -v '^hostapd\.tlg' > "$pre"   # 主 Wi‑Fi 接口（不含访客 tlgN）
	[ -s "$pre" ] || { rm -f "$pre"; echo "失败：没找到主 Wi‑Fi 的 hostapd 接口，不动"; exit 1; }
	wgpre=0; wg_ok && wgpre=1
	if [ "$ENABLED" = 1 ]; then
		write_cfg || { rm -f "$pre"; U revert network; U revert wireless; U revert dhcp; U revert firewall; echo "失败：配置写入出错"; exit 1; }
	else
		del_all
	fi
	commit_reload
	if verify "$pre" "$wgpre"; then
		rm -f "$pre"
		if [ "$ENABLED" = 1 ]; then log "OK 访客 Wi‑Fi「$SSID」已开启（主 Wi‑Fi 正常，wg0 正常）"; else log "OK 访客 Wi‑Fi 已关闭（主 Wi‑Fi 正常，wg0 正常）"; fi
		exit 0
	fi
	log "自检失败（主 Wi‑Fi 接口或 wg0 没有恢复），正在撤回"
	del_all; commit_reload; verify "$pre" "$wgpre"
	rm -f "$pre"
	echo "失败：自检没通过，已撤回访客 Wi‑Fi（主 Wi‑Fi 已重载）"; exit 1 ;;
status)
	U show wireless 2>/dev/null | grep -E '^wireless\.tlguest_[^.]*=' ; aps; ip -4 addr show br-tlguest 2>/dev/null | grep inet ;;
*) echo "用法: $0 apply|up|down|status|plan"; exit 2 ;;
esac
