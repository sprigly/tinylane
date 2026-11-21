#!/usr/bin/env python3
# M6 API 测试（设备/访客部分）（沙盒）：python3 m6_api_test.py http://127.0.0.1:19999 <root 密码文件> <m6test 目录> <fixtures URL 前缀>
import json, sys, time, subprocess, urllib.request, http.cookiejar, os
BASE, PWF, D, FX = sys.argv[1:5]; PW = open(PWF).read().strip()
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.ProxyHandler({}))
res = []
def call(path, body=None):
    req = urllib.request.Request(BASE + '/api' + path, data=None if body is None else json.dumps(body).encode(), method='POST' if body is not None else 'GET')
    req.add_header('Content-Type', 'application/json'); req.add_header('X-TL', '1')
    try: r = op.open(req, timeout=120); return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b'{}')
def check(n, c, i=''): res.append(bool(c)); print(('PASS ' if c else 'FAIL ') + n + ('' if c else '  ' + str(i)[:400]), flush=True)
sudo = lambda p: subprocess.check_output(['sudo', '-n', 'cat', p], stderr=subprocess.DEVNULL).decode()
cfg = lambda: json.loads(sudo(D + '/tinylane.json')); sb = lambda: json.loads(sudo(D + '/run/config.json'))
def tags(): return [x['tag'] for x in sb()['route'].get('rule_set', [])]
s, _ = call('/login', {'password': PW}); check('登录', s == 200, s)
# ---- 按设备流量 ----
an = sudo(D + '/acct-seen.nft')
check('acct 表：独立 table、只 update 计数、policy accept、无 drop', 'table inet tinylane_acct' in an and 'policy accept' in an and 'drop' not in an and 'update @up4' in an and 'update @down4' in an, an)
time.sleep(21)
s, cx = call('/conns'); dv = {d['ip']: d for d in cx['devices']}
d1 = dv.get('127.0.0.2', {})
check('设备：今日上下行 + 实时速率（按 MAC 记）', d1.get('today_up', 0) > 0 and d1.get('today_down', 0) > 0 and d1.get('nft_down_rate', 0) > 0, d1)
s, t = call('/traffic'); check('/traffic 汇总', s == 200 and t['ok'] and t['today_down'] > 0, t)
check('acct.json 落到 tmpfs 工作目录', subprocess.run(['sudo', '-n', 'test', '-s', D + '/work/acct.json'], stderr=subprocess.DEVNULL).returncode == 0, '')
# ---- 访客 Wi-Fi ----
s, j = call('/guest/wifi', {'wifi': {'enabled': True, 'ssid': 'TinyLane-Guest', 'key': 'short'}}); check('访客密码太短 → 400', s == 400, j)
s, j = call('/guest/wifi', {'wifi': {'enabled': True, 'ssid': 'A' * 40, 'key': 'goodpassword1'}}); check('SSID 太长 → 400', s == 400, j)
s, j = call('/guest/wifi', {'wifi': {'enabled': True, 'ssid': "Guest'; rm -rf /", 'key': 'goodpass"word1', 'band': 'both'}})
time.sleep(4); env = sudo(D + '/guest-calls.log').strip().split('\n')[-1]
s2, gs = call('/guest/wifi')
check('开启访客 Wi‑Fi → 脚本 apply（参数单引号转义 + WG_PING）→ OK + applied', s == 200 and 'WG_PING=' in env and "SSID='Guest'\\''; rm -rf /'" in env and gs['msg'].startswith('OK') and cfg()['guest_wifi'].get('applied'), (env, gs))
s, j = call('/guest/wifi', {'wifi': {'enabled': False, 'ssid': 'TinyLane-Guest', 'key': 'goodpassword1'}}); time.sleep(4)
check('关闭访客 Wi‑Fi', s == 200 and 'ENABLED=0' in sudo(D + '/guest-calls.log').strip().split('\n')[-1] and cfg()['guest_wifi']['enabled'] is False, j)
# ---- 新设备默认访客 ----
s, j = call('/guest/newdefault', {'on': True}); c = cfg()
check('打开「新设备默认访客」→ 现有 3 台记为已知、不是访客', s == 200 and c['guest']['new_device_default'] and all(m in c.get('device_info', {}) for m in ('aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02', 'aa:bb:cc:00:00:03')) and 'aa:bb:cc:00:00:01' not in c['guest'].get('macs', []), c['guest'])
subprocess.run(['sudo', '-n', 'sh', '-c', "echo '1763500000 02:11:22:33:44:55 127.0.0.9 NewPhone *' >> " + D + '/leases'], stderr=subprocess.DEVNULL)
ok = False
for _ in range(40):
    time.sleep(1)
    if '02:11:22:33:44:55' in cfg()['guest'].get('macs', []): ok = True; break
check('新 MAC 出现 → 30 秒内自动设为访客（nft guest_mac 集合）', ok and '02:11:22:33:44:55' in sudo(D + '/run/tinylane.nft'), cfg()['guest'])
s, j = call('/guest/newdefault', {'on': False}); check('关闭', s == 200 and not cfg()['guest'].get('new_device_default'), j)
call('/device/guest', {'mac': '02:11:22:33:44:55', 'guest': False})
# ---- 踢下线（合成 MAC）----
s, j = call('/device/kick', {'mac': '02:00:5e:00:00:99', 'ban_s': 0}); check('踢合成 MAC（不在 Wi‑Fi）→ 400 不调用 hostapd', s == 400 and 'Wi' in j.get('error', ''), j)
print(f'{sum(res)}/{len(res)} PASS')
