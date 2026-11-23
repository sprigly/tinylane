#!/bin/sh
# TinyLane 自更新辅助脚本（M11）。守护进程把它写到 /usr/libexec/tinylane/tinylane-update.sh，
# 用独立会话启动（不随 TinyLane 服务停止而退出）。所有参数从「试运行标记」读：
#   /etc/tinylane/.update-trial（KEY='值' 每行一个；值里没有单引号和换行）
# 用法：
#   tinylane-update.sh apply    <标记>          停服务 → 删旧版 → 写新版 → 启动 → 等新版自检；超时没结果就退回
#   tinylane-update.sh watch    <标记>          只等自检、超时退回（开机恢复试运行时用）
#   tinylane-update.sh rollback <标记> [原因]   立刻退回旧版（守护进程发现辅助进程不在时用）
#   tinylane-update.sh revert   <标记>          手动「退回上一版」：换成标记里的旧版，不试运行
#   tinylane-update.sh boot     <标记>          init 启动前修复：换版中途断电导致程序缺失/不完整 → 用旧版补回
# 任何时候都不碰 wg0、不改 /etc/config/network；最坏情况（旧版也写不回）是 TinyLane 不运行 = 普通路由。
MODE=$1
M=$2
[ -n "$M" ] && [ -f "$M" ] || { echo "没有试运行标记：$M"; exit 0; }
LOGF=${TL_UPD_LOG:-/tmp/tinylane-update.log}
export TL_UPD_HELPER=1

log() { echo "$(date '+%F %T') $*" >> "$LOGF"; logger -t tinylane-update "$*" 2>/dev/null; }
load() { . "$M"; }
setkv() {
	[ -f "$M" ] || return 0
	t="$M.tmp.$$"
	grep -v "^$1=" "$M" > "$t" 2>/dev/null
	printf "%s='%s'\n" "$1" "$(printf %s "$2" | tr "'\n" '" ')" >> "$t"
	mv -f "$t" "$M"
}
result() { # $1=RESULT $2=原因
	r="$RES.tmp.$$"
	{
		printf "RESULT='%s'\n" "$1"
		if [ "$MODE_KIND" = revert ]; then f=$CUR_VER; else f=$NEW_VER; fi
		printf "FROM='%s'\nTO='%s'\n" "$f" "$OLD_VER"
		printf "REASON='%s'\n" "$(printf %s "$2" | tr "'\n" '" ')"
		printf "T='%s'\nKIND='%s'\n" "$(date +%s)" "${MODE_KIND:-update}"
	} > "$r"
	mv -f "$r" "$RES"
}

# 只认 exe 指向 $BIN 的进程（守护进程 + 内核子进程），不按名字乱杀
running() {
	for p in /proc/[0-9]*; do
		e=$(readlink "$p/exe" 2>/dev/null) || continue
		case "$e" in "$BIN" | "$BIN (deleted)") return 0 ;; esac
	done
	return 1
}
kill_bin() {
	for p in /proc/[0-9]*; do
		e=$(readlink "$p/exe" 2>/dev/null) || continue
		case "$e" in "$BIN" | "$BIN (deleted)") kill -9 "${p#/proc/}" 2>/dev/null ;; esac
	done
}
svc_stop() {
	$INIT stop >/dev/null 2>&1
	i=0
	while [ $i -lt 15 ] && running; do sleep 1; i=$((i + 1)); done
	running && { log "服务 15 秒没停干净，强制结束"; kill_bin; sleep 1; }
}
svc_start() { $INIT start >/dev/null 2>&1; }

# 解压 $1 写成 $BIN（先写 .new 再改名；$2 = 期望的 sha256）
install_gz() {
	rm -f "$BIN.new"
	gunzip -c "$1" > "$BIN.new" 2>/dev/null || { rm -f "$BIN.new"; return 1; }
	if [ -n "$2" ] && [ "$(sha256sum "$BIN.new" | cut -d' ' -f1)" != "$2" ]; then rm -f "$BIN.new"; return 2; fi
	chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN" && sync
}

drop_prev() { # 退回 / 手动退回后，上一版已经是正在跑的版本，删掉腾空间
	[ -n "$PREV_DIR" ] && rm -rf "$PREV_DIR"
	[ -n "$CUR_GZ" ] && rm -f "$CUR_GZ"
	[ -n "$NEW_GZ" ] && rm -f "$NEW_GZ"
}

# 退回旧版：$1 原因，$2=nostart 时不启动（init 启动前修复用）
restore_old() {
	load
	why=$1
	setkv STATE rollback
	setkv REASON "$why"
	log "退回 v$OLD_VER：$why"
	svc_stop
	if [ -n "$PREV_BIN" ] && [ -f "$PREV_BIN" ]; then
		rm -f "$BIN" # 先删新版腾空间
		if install_gz "$PREV_BIN" "$PREV_SHA"; then
			[ -n "$PREV_CONF" ] && [ -f "$PREV_CONF" ] && cp -p "$PREV_CONF" "$CONF"
			res=rolled_back
		else
			res=rollback_failed
			why="$why；旧版写回失败，TinyLane 暂停（普通路由）"
		fi
	else
		# 旧版文件不在：保留当前程序，不删
		res=rollback_failed
		why="$why；旧版文件已不在，无法退回，保持现状"
	fi
	result "$res" "$why"
	rm -f "$M"
	[ "$res" = rolled_back ] && drop_prev
	[ "$2" = nostart ] || { [ -x "$BIN" ] && svc_start; }
	log "退回结束：$res"
}

wait_check() {
	setkv HELPER_PID $$
	while :; do
		[ -f "$M" ] || { log "新版自检完成，辅助进程退出"; exit 0; }
		load
		[ "$STATE" = rollback_req ] && { restore_old "$REASON"; exit 0; }
		now=$(date +%s)
		lim=$((${CHECK_S:-180} + ${GRACE_S:-90}))
		if [ -n "$CHECK_START" ] && [ $((now - CHECK_START)) -gt $lim ]; then
			restore_old "新版启动后 $((lim / 60)) 分钟内没有完成自检（可能没能正常启动）"
			exit 0
		fi
		sleep ${TL_UPD_POLL:-2}
	done
}

# 跳出 procd 的 cgroup（若有），保证 /etc/init.d/tinylane stop 不会连带结束本脚本
CG=${TL_UPD_CGROUP:-/sys/fs/cgroup}
[ "$CG" != none ] && [ -w "$CG/cgroup.procs" ] && echo $$ > "$CG/cgroup.procs" 2>/dev/null

load
case "$MODE" in
apply)
	sleep ${TL_UPD_DELAY:-1} # 让面板先把响应发出去
	setkv HELPER_PID $$
	log "开始更新 v$OLD_VER → v$NEW_VER（上一版放在 $PREV_DIR）"
	setkv STATE swap
	svc_stop
	rm -f "$BIN" # 先删旧版腾空间（旧版已压缩备份在 $PREV_BIN）
	if ! install_gz "$NEW_GZ" "$NEW_SHA"; then
		restore_old "写入新版失败（可能闪存空间不够）"
		exit 0
	fi
	rm -f "$NEW_GZ"
	setkv CHECK_START "$(date +%s)"
	setkv STATE check
	log "新版已写入，启动并开始自检"
	svc_start
	wait_check
	;;
watch)
	wait_check
	;;
rollback)
	restore_old "${3:-$REASON}"
	;;
revert)
	sleep ${TL_UPD_DELAY:-1}
	MODE_KIND=revert
	log "手动退回：v$CUR_VER → v$OLD_VER"
	svc_stop
	[ -f "$CONF" ] && cp -p "$CONF" "$CONF.before-revert"
	rm -f "$BIN"
	if install_gz "$PREV_BIN" "$PREV_SHA"; then
		[ -n "$PREV_CONF" ] && [ -f "$PREV_CONF" ] && cp -p "$PREV_CONF" "$CONF"
		result reverted ""
		rm -f "$M"
		drop_prev
	else
		# 旧版写不进去：装回当前版
		if [ -n "$CUR_GZ" ] && install_gz "$CUR_GZ" "$CUR_SHA"; then
			result revert_failed "旧版写入失败，已保持 v$CUR_VER"
		else
			result revert_failed "旧版写入失败，当前版也没能写回，TinyLane 暂停（普通路由）"
		fi
		rm -f "$M" "$CUR_GZ"
	fi
	[ -x "$BIN" ] && svc_start
	;;
boot)
	# init 里在 gen 之前调用：只修「程序缺失 / 写了一半」，正常情况什么都不做
	if [ "$STATE" = rollback ] || [ "$STATE" = rollback_req ]; then
		restore_old "${REASON:-自检没通过}（退回时被中断，已重新退回）" nostart
	elif [ ! -x "$BIN" ]; then
		restore_old "换新版时被中断（断电或重启），已用旧版补回" nostart
	elif [ "$STATE" = swap ] && [ "$(sha256sum "$BIN" | cut -d' ' -f1)" != "$NEW_SHA" ]; then
		restore_old "换新版时被中断（程序不完整），已用旧版补回" nostart
	fi
	;;
*)
	echo "用法：$0 apply|watch|rollback|revert|boot <标记>"
	exit 2
	;;
esac
exit 0
