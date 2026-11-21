#!/bin/sh
# 逐节点上下行测速（经 mixed 127.0.0.1:7890 + 「测速」组）。用法：tinylane-speedtest.sh [轮数=3] [组=测速]
# 下载 cloudflare __down 10 MB；上传 POST 2 MB 到 __up（看 size_upload / speed_upload；结尾 rc=56 属正常）。
ROUNDS=${1:-3}; G=${2:-测速}
CONF=${TL_CONF:-/etc/tinylane/tinylane.json}
TL=${TL_BIN:-tinylane}
UP=/tmp/tl-up2m
dd if=/dev/urandom of=$UP bs=1024 count=2048 2>/dev/null
ORIG=$($TL select -i "$CONF" "$G" | sed -n 's/^\* //p')
kbs() { awk -v b="$1" 'BEGIN{printf "%.0f KB/s", b/1024}'; }
$TL select -i "$CONF" "$G" | sed 's/^[* ] //' > /tmp/tl-nodes
while IFS= read -r N; do
	$TL select -i "$CONF" "$G" "$N" >/dev/null || { echo "$N：切换失败"; continue; }
	r=1
	while [ $r -le "$ROUNDS" ]; do
		set -- $(curl -s -x http://127.0.0.1:7890 -o /dev/null -m 30 -w '%{http_code} %{size_download} %{speed_download}' 'https://speed.cloudflare.com/__down?bytes=10000000'; echo " $?")
		D="下行 $(kbs "$3")（$2 B，HTTP $1，rc=$4）"
		set -- $(curl -s -x http://127.0.0.1:7890 -o /dev/null -m 30 -X POST --data-binary @$UP -H 'Content-Type: application/octet-stream' -w '%{http_code} %{size_upload} %{speed_upload}' 'https://speed.cloudflare.com/__up'; echo " $?")
		U="上行 $(kbs "$3")（$2 B，HTTP $1，rc=$4）"
		echo "$N #$r | $D | $U"
		r=$((r + 1))
	done
done < /tmp/tl-nodes
[ -n "$ORIG" ] && $TL select -i "$CONF" "$G" "$ORIG" >/dev/null
rm -f $UP /tmp/tl-nodes
