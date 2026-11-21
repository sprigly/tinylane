#!/bin/sh
# TinyLane 国内直连优化：WAN 上的 cake 整形 + cake-autorate（按延迟自动调速）。
# 用法：tinylane-sqm.sh up|down|status|measure
# - 配置由 tinylane 守护进程写到 $RUN/sqm.env（ENABLED IFACE DL_MIN DL_BASE DL_MAX UL_MIN UL_BASE UL_MAX，单位 Mbit）
# - 下行经 ifb（ifb4<iface>）入站整形；只动 qdisc，不碰路由 / 防火墙，wg0 等隧道照常（只是一起被整形）
# - cake-autorate 脚本在 /usr/share/cake-autorate，配置写到 tmpfs（$RUN/sqm/config.primary.sh），不占闪存
RUN=${RUN:-/var/run/tinylane}
[ -f "$RUN/sqm.env" ] && . "$RUN/sqm.env"
IFACE=${IFACE:-wan}; IFB=ifb4$IFACE
CA=/usr/share/cake-autorate
log() { logger -t tinylane-sqm "$*"; echo "$*"; }

qdisc_up() {
	# 先撤 ingress 重定向再删 ifb：反过来的话中间那一下入站包会被重定向到不存在的设备而丢掉（M6 修）
	tc qdisc del dev "$IFACE" ingress 2>/dev/null
	ip link show "$IFB" >/dev/null 2>&1 && ip link del "$IFB"
	ip link add "$IFB" type ifb && ip link set "$IFB" up || return 1
	tc qdisc replace dev "$IFACE" root cake bandwidth "${UL_BASE}mbit" besteffort nat ack-filter memlimit 2mb || return 1
	tc qdisc replace dev "$IFB" root cake bandwidth "${DL_BASE}mbit" besteffort nat wash ingress memlimit 4mb || return 1
	tc qdisc add dev "$IFACE" handle ffff: ingress || return 1
	tc filter replace dev "$IFACE" parent ffff: protocol all matchall action mirred egress redirect dev "$IFB" || return 1
}

qdisc_down() {
	tc qdisc del dev "$IFACE" ingress 2>/dev/null
	tc qdisc del dev "$IFACE" root 2>/dev/null
	ip link del "$IFB" 2>/dev/null
	return 0
}

autorate_conf() {
	mkdir -p "$RUN/sqm"
	cat > "$RUN/sqm/config.primary.sh" <<EOC
#!/usr/bin/env bash
dl_if=$IFB
ul_if=$IFACE
adjust_dl_shaper_rate=1
adjust_ul_shaper_rate=1
min_dl_shaper_rate_kbps=$((DL_MIN * 1000))
base_dl_shaper_rate_kbps=$((DL_BASE * 1000))
max_dl_shaper_rate_kbps=$((DL_MAX * 1000))
min_ul_shaper_rate_kbps=$((UL_MIN * 1000))
base_ul_shaper_rate_kbps=$((UL_BASE * 1000))
max_ul_shaper_rate_kbps=$((UL_MAX * 1000))
connection_active_thr_kbps=2000
output_processing_stats=0
output_load_stats=0
output_reflector_stats=0
output_summary_stats=0
log_to_file=1
debug=0
log_file_path_override="$RUN/sqm"
log_file_max_size_KB=200
pinger_binary=fping
# 国内可达的反射点（默认的海外 anycast 在国内抖动大）
reflectors=("223.5.5.5" "223.6.6.6" "119.29.29.29" "180.76.76.76" "114.114.114.114" "1.2.4.8" "210.2.4.8" "119.28.28.28")
no_pingers=4
reflector_ping_interval_s=0.3
# 上游设备满载时更倾向丢包而不是排队：阈值调低，早一点降速
dl_owd_delta_thr_ms=15.0
ul_owd_delta_thr_ms=15.0
dl_avg_owd_delta_thr_ms=40.0
ul_avg_owd_delta_thr_ms=40.0
startup_wait_s=5.0
EOC
}

case "$1" in
up)
	[ "$ENABLED" = 1 ] || { "$0" down >/dev/null; exit 0; }
	[ -x "$CA/cake-autorate.sh" ] || { log "缺少 cake-autorate（$CA）"; exit 1; }
	/etc/init.d/cake-autorate stop >/dev/null 2>&1
	qdisc_up || { log "cake 设置失败，已撤销"; qdisc_down; exit 1; }
	autorate_conf
	/etc/init.d/cake-autorate start >/dev/null 2>&1
	log "cake 已启用：$IFACE ↓${DL_MIN}/${DL_BASE}/${DL_MAX} ↑${UL_MIN}/${UL_BASE}/${UL_MAX} Mbit（min/base/max）"
	;;
down)
	/etc/init.d/cake-autorate stop >/dev/null 2>&1
	qdisc_down
	rm -f "$RUN/sqm/config.primary.sh"
	;;
status)
	tc qdisc show dev "$IFACE" | grep cake; tc qdisc show dev "$IFB" 2>/dev/null | grep cake
	pgrep -f cake-autorate.sh >/dev/null && echo "cake-autorate 运行中" || echo "cake-autorate 未运行"
	;;
measure)
	# 自动测速（M7b 起省内存）：先查 MemAvailable，低于 MIN_AVAIL_MB（默认 40）就拒绝；
	# 下载 / 上传各最多 2 路并发，curl 输出丢 /dev/null，上传从管道流式发送（不建 tmpfs 文件、不进 curl 内存）。
	MIN=${MIN_AVAIL_MB:-40}
	AV=$(awk '/^MemAvailable:/{printf "%d", $2/1024}' /proc/meminfo)
	if [ "${AV:-0}" -lt "$MIN" ]; then echo "{\"error\":\"low_mem\",\"avail_mb\":${AV:-0},\"min_mb\":$MIN}"; exit 0; fi
	[ "${DRY_RUN:-0}" = 1 ] && { echo "{\"dry_run\":1,\"avail_mb\":$AV,\"min_mb\":$MIN,\"par\":2}"; exit 0; }
	was=0; tc qdisc show dev "$IFACE" | grep -q cake && was=1
	[ $was = 1 ] && { /etc/init.d/cake-autorate stop >/dev/null 2>&1; qdisc_down; }
	F=ubuntu-releases/24.04/ubuntu-24.04.5-live-server-amd64.iso
	ctr() { grep " $IFACE:" /proc/net/dev | sed 's/.*://' | awk '{print $1, $9}'; }
	up() { cut -d' ' -f1 /proc/uptime; }
	for m in mirrors.ustc.edu.cn mirrors.aliyun.com; do
		curl -s4L -o /dev/null --max-time 14 "https://$m/$F" &
	done
	sleep 3; a=$(ctr); ta=$(up); sleep 10; b=$(ctr); tb=$(up); wait
	DL=$(echo "$a $b $ta $tb" | awk '{printf "%.0f", ($3-$1)*8/($6-$5)/1e6}')
	for i in 1 2; do
		( dd if=/dev/zero bs=64k count=1536 2>/dev/null | curl -s4 -o /dev/null --max-time 14 -X POST -T - -H 'Content-Type: application/octet-stream' https://speed.cloudflare.com/__up ) &
	done
	sleep 3; a=$(ctr); ta=$(up); sleep 10; b=$(ctr); tb=$(up); wait
	UL=$(echo "$a $b $ta $tb" | awk '{printf "%.0f", ($4-$2)*8/($6-$5)/1e6}')
	[ $was = 1 ] && "$0" up >/dev/null 2>&1
	echo "{\"down_mbit\":$DL,\"up_mbit\":$UL}"
	;;
*) echo "用法: $0 up|down|status|measure"; exit 2 ;;
esac
