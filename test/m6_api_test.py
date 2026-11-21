#!/usr/bin/env python3
# M6 API 测试（沙盒）：python3 m6_api_test.py http://127.0.0.1:19999 <root 密码文件> <m6test 目录> <fixtures URL 前缀>
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
s, st = call('/state')
for x in st.get('rule_sets', []): call('/ruleset/delete', {'name': x['name']})
s, st = call('/state'); check('state 有 rule_sets / guest_wifi / traffic / raw_pending', all(k in st for k in ('rule_sets', 'guest_wifi', 'traffic', 'raw_pending')), list(st)[:40])
base_rules = st['rules']; base_nodes = [n['name'] for n in st['nodes']]
# ---- 规则集 ----
s, j = call('/ruleset/save', {'rs': {'name': '测试源', 'url': FX + '/rs-src.json', 'outbound': '主线路', 'update': 'daily'}})
c = cfg(); r = [x for x in c.get('rule_sets', []) if x['name'] == '测试源']
check('添加 source 规则集 → 下载 + 统计（2 条、含域名）', s == 200 and r and r[0].get('count') == 2 and r[0].get('has_domain') and r[0].get('format', 'source') == 'source', (s, j, r))
t = [x for x in sb()['route']['rule_set'] if x['tag'].startswith('rs-custom-')]
rr = [x for x in sb()['route']['rules'] if x.get('rule_set') and x['rule_set'][0].startswith('rs-custom-')]
dr = [x for x in sb()['dns']['rules'] if x.get('rule_set') and x['rule_set'][0].startswith('rs-custom-')]
check('sing-box：rule_set 本地文件 + 路由规则 → 主线路 + DNS 规则 → 国外 DNS', len(t) == 1 and t[0]['format'] == 'source' and rr and rr[0]['outbound'] == '主线路' and dr, (t, rr, dr))
ri = [i for i, x in enumerate(sb()['route']['rules']) if x.get('rule_set') == rr[0]['rule_set']][0]
ci = [i for i, x in enumerate(sb()['route']['rules']) if x.get('domain_suffix') == ['cn']][0]
pi = [i for i, x in enumerate(sb()['route']['rules']) if '指定出口' in str(x.get('outbound'))][0]
check('顺序：指定出口 固定规则 < 规则集 < .cn 直连', pi < ri < ci, (pi, ri, ci))
s, j = call('/ruleset/save', {'rs': {'name': '国内IP', 'url': FX + '/geoip-cn.srs', 'outbound': 'direct', 'update': 'weekly'}})
r = [x for x in cfg()['rule_sets'] if x['name'] == '国内IP'][0]
check('添加 .srs（二进制）规则集 → has_ip、无 DNS 规则', s == 200 and r.get('has_ip') and not r.get('has_domain') and r['count'] > 1000, (s, j, r))
n_dns = len([x for x in sb()['dns']['rules'] if x.get('rule_set') and x['rule_set'][0].startswith('rs-custom-')])
check('纯 IP 规则集不加 DNS 规则', n_dns == 1, n_dns)
s, j = call('/ruleset/save', {'rs': {'name': '坏文件', 'url': FX + '/bad.srs', 'outbound': '主线路', 'update': 'off'}})
r = [x for x in cfg()['rule_sets'] if x['name'] == '坏文件'][0]
check('坏文件（HTML）→ 已保存但不加载、记错误', s == 200 and 'warn' in j and r.get('last_error') and len([x for x in tags() if x.startswith('rs-custom-')]) == 2, (j, r))
s, j = call('/ruleset/save', {'rs': {'name': 'x', 'url': 'ftp://a', 'outbound': '主线路', 'update': 'off'}}); check('URL 非 http(s) → 400', s == 400, s)
s, j = call('/ruleset/save', {'rs': {'name': 'y', 'url': FX + '/rs-src.json', 'outbound': '不存在的组', 'update': 'off'}}); check('去向不存在 → 400', s == 400, s)
s, j = call('/ruleset/update', {'name': '测试源'}); check('立即更新', s == 200 and j['rs']['count'] == 2, j)
s, st = call('/state'); names = [x['name'] for x in st['rule_sets']]
s, j = call('/ruleset/order', {'names': list(reversed(names))}); check('规则集排序', s == 200 and [x['name'] for x in cfg()['rule_sets']] == list(reversed(names)), j)
for nm in names:
    call('/ruleset/delete', {'name': nm})
check('删除全部规则集 → 配置和 sing-box 都没有了', not cfg().get('rule_sets') and not [x for x in tags() if x.startswith('rs-custom-')], cfg().get('rule_sets'))
# ---- 导入 ----
links = open(D + '/subsrv/links.b64').read()
s, p = call('/import/preview', {'text': links})
check('导入预览：Base64 分享链接 → 节点列表（不改配置）', s == 200 and p['nodes'] and p['token'] and [n['name'] for n in call('/state')[1]['nodes']] == base_nodes, (s, p))
s, j = call('/import/apply', {'token': p['token']}); c = cfg()
check('导入应用：节点追加为 manual，组不变', s == 200 and j['nodes_added'] > 0 and len(c['nodes']) == len(base_nodes) + j['nodes_added'] and all(n.get('source') == 'manual' for n in c['nodes'][len(base_nodes):]), (s, j))
s, j = call('/import/apply', {'token': p['token']}); check('同一预览不能应用两次', s == 400, s)
rules_txt = 'rules:\n  - DOMAIN-SUFFIX,example-a.com,Proxy\n  - DOMAIN,www.example-b.com,DIRECT\n  - DOMAIN-KEYWORD,examplekw,Proxy\n  - IP-CIDR,203.0.113.0/24,REJECT,no-resolve\n  - GEOIP,CN,DIRECT\n  - MATCH,Proxy\n'
s, p = call('/import/preview', {'text': rules_txt})
check('导入预览：Clash 规则 → 3 组规则、跳过 2 条、需要选去向', s == 200 and len(p['rules']) == 3 and p['rule_skipped'] == 2 and p['need_target'], p)
s, j = call('/import/apply', {'token': p['token'], 'target': '指定出口'}); c = cfg()
new = c['rules'][len(base_rules):]
check('应用规则 → 追加在末尾，代理去向 = 选的组', s == 200 and j['rules_added'] == 3 and any(r['outbound'] == '指定出口' and 'example-a.com' in r.get('domain_suffix', []) for r in new) and any(r['outbound'] == 'block' and r.get('ip_cidr') == ['203.0.113.0/24'] for r in new), (j, new))
s, p = call('/import/preview', {'text': 'example-c.com\n+.example-d.org\n1.2.3.0/24\nnot a domain\n'})
check('纯域名列表也能识别', s == 200 and p['kind'] == '规则列表' and p['rule_skipped'] == 1, p)
full = cfg()
for g in full['groups']:
    if g.get('forbid'): g['forbid'] = []
s, p = call('/import/preview', {'text': json.dumps(full)}); check('导入完整配置去掉 禁止规则 → 被安全保护拒绝', s == 400 and '安全保护' in p.get('error', ''), p)
full = cfg(); full['log_level'] = 'info'
s, p = call('/import/preview', {'text': json.dumps(full)}); check('导入完整配置（只改日志级别）→ 预览可用', s == 200 and p['kind'].startswith('TinyLane'), p)
s, j = call('/import/apply', {'token': p['token']}); check('应用完整配置', s == 200 and cfg()['log_level'] == 'info', j)
call('/rules', {'rules': base_rules})
# ---- 高级模式 ----
s, r = call('/raw'); check('GET /raw：clash_api.secret 已掩码，有 sing-box 视图', s == 200 and '"secret": "********"' in r['text'] and cfg()['clash_api']['secret'] not in r['text'] and cfg()['clash_api']['secret'] not in r['singbox'], '')
s, j = call('/raw/check', {'text': '{\n "mode": "rule",\n oops\n}'}); check('语法错误 → 指出行号', s == 400 and '行' in j.get('error', ''), j)
m = json.loads(r['text']); m['rules'] = [x for x in m['rules'] if not x.get('pin')]
s, j = call('/raw/check', {'text': json.dumps(m)}); check('删除固定规则（指定出口）→ 安全保护拒绝', s == 400 and '安全保护' in j.get('error', ''), j)
m = json.loads(r['text']); m['always_bypass'] = {'cidr': [], 'udp_ports': []}
s, j = call('/raw/check', {'text': json.dumps(m)}); check('清空永久绕过 → 内置 wg 绕过仍在（gen 强制补上）', s == 200, j)
m = json.loads(r['text']); m['mode'] = 'bogus'
s, j = call('/raw/check', {'text': json.dumps(m)}); check('非法值 → 校验报错', s == 400, j)
m = json.loads(r['text']); m['log_level'] = 'warn'; m['rules'].append({'name': 'raw测试', 'domain_suffix': ['raw-test.example'], 'outbound': 'direct'})
s, j = call('/raw/check', {'text': json.dumps(m)}); check('合法改动 → 预检通过 + 变化摘要', s == 200 and any('规则' in x for x in j['summary']), j)
sec = cfg()['clash_api']['secret']
s, j = call('/raw/apply', {'text': json.dumps(m)}); check('应用 → 等待确认', s == 200 and j['confirm_by'] > time.time() and any(x.get('name') == 'raw测试' for x in cfg()['rules']) and cfg()['clash_api']['secret'] == sec, j)
s, j = call('/raw/apply', {'text': json.dumps(m)}); check('等待确认期间不能再应用', s == 400, j)
s, j = call('/raw/confirm', {}); check('确认保留', s == 200 and any(x.get('name') == 'raw测试' for x in cfg()['rules']), j)
m2 = json.loads(call('/raw')[1]['text']); m2['rules'] = [x for x in m2['rules'] if x.get('name') != 'raw测试']
s, j = call('/raw/apply', {'text': json.dumps(m2)}); ok1 = not any(x.get('name') == 'raw测试' for x in cfg()['rules'])
time.sleep(int(os.environ.get('RAWWIN', '6')) + 3)
check('不确认 → 窗口结束自动回滚（改动撤销）', s == 200 and ok1 and any(x.get('name') == 'raw测试' for x in cfg()['rules']) and call('/state')[1]['raw_pending'] == 0, j)
s, j = call('/raw/apply', {'text': json.dumps(m2)}); s2, _ = call('/raw/rollback', {})
check('手动撤销', s == 200 and s2 == 200 and any(x.get('name') == 'raw测试' for x in cfg()['rules']), (j,))
call('/rules', {'rules': base_rules})
print(f'{sum(res)}/{len(res)} PASS')
