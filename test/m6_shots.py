# M6 截图 + 交互：python3 m6_shots.py http://127.0.0.1:19999 <root 密码文件> <输出目录> <light|dark> <fixtures URL>
import asyncio,sys,json
from playwright.async_api import async_playwright
B,PWF,OUT,TH,FX=sys.argv[1:6]; PW=open(PWF).read().strip(); R=[]
def ck(n,c,i=''): R.append(bool(c)); print(('PASS ' if c else 'FAIL ')+n+('' if c else '  '+str(i)[:300]),flush=True)
async def main():
  async with async_playwright() as p:
    b=await p.chromium.launch(); ctx=await b.new_context(viewport={'width':390,'height':844},device_scale_factor=2,has_touch=True,is_mobile=True,color_scheme=TH)
    pg=await ctx.new_page(); errs=[]; pg.on('pageerror',lambda e:errs.append(str(e)))
    await pg.goto(B); await pg.wait_for_timeout(700); await pg.fill('#lp',PW); await pg.click('#lb'); await pg.wait_for_timeout(2500)
    await pg.evaluate("theme('auto');render()")
    ck('外观「自动」跟随系统 '+TH, await pg.evaluate("document.documentElement.dataset.theme")==TH)
    async def tab(t): await pg.click(f'#tb [data-t={t}]'); await pg.wait_for_timeout(1300)
    sh=lambda n,full=True: pg.screenshot(path=f'{OUT}/m6-{n}-{TH}-mobile.png',full_page=full)
    async def overflow(): return await pg.evaluate("document.documentElement.scrollWidth>innerWidth+1")
    for t,n in [('ov','overview'),('nd','nodes'),('sb','subs'),('dv','devices'),('lg','logs')]:
      await tab(t); await sh(n); ck(f'{n}：无横向溢出', not await overflow())
    fs=await pg.evaluate("[getComputedStyle(document.querySelector('#view h2')).fontSize,getComputedStyle(document.querySelector('#view h2')).fontWeight]")
    ck('大标题 34px 粗体',fs==['34px','700'],fs)
    tb=await pg.evaluate("getComputedStyle(document.querySelector('.tb')).backdropFilter||getComputedStyle(document.querySelector('.tb')).webkitBackdropFilter")
    ck('标签栏毛玻璃',('blur' in (tb or '')),tb)
    sw=await pg.evaluate("(()=>{const e=document.querySelector('.sw');const c=getComputedStyle(e);return [c.width,c.height]})()"); ck('iOS 开关 51×31',sw==['51px','31px'],sw)
    await tab('st'); await pg.evaluate("S.sub='set';render();scrollTo(0,600)"); await pg.wait_for_timeout(1200)
    ck('往下滚 → 导航栏出现小标题',await pg.evaluate("document.querySelector('header').classList.contains('scrolled')&&document.getElementById('ntitle').textContent.length>0"))
    await pg.screenshot(path=f'{OUT}/m6-settings-scrolled-{TH}-mobile.png'); await pg.evaluate("scrollTo(0,0)")
    await tab('dv'); t=await pg.inner_text('#view'); ck('设备卡显示今日流量','今日' in t,t[:200])
    # 规则页：规则集
    await tab('st'); await pg.evaluate("S.sub='rule';render()"); await pg.wait_for_timeout(500); await sh('rules')
    t=await pg.inner_text('#view'); ck('规则页无「即将推出」','即将推出' not in t)
    await pg.click('[data-a=rsadd]'); await pg.wait_for_timeout(500)
    await pg.fill('#rn','演示规则集'); await pg.fill('#ru',FX+'/rs-src.json'); await pg.screenshot(path=f'{OUT}/m6-ruleset-add-{TH}-mobile.png')
    await pg.click('#rs_ok'); await pg.wait_for_timeout(2500)
    ck('添加规则集 → 列表出现 + 条数（页面已刷新）',await pg.evaluate("S.st.rule_sets.some(r=>r.name=='演示规则集'&&r.count==2)&&document.querySelector('#view').innerText.includes('演示规则集')")); await sh('rules-with-ruleset')
    # 设置页：访客、导入、高级模式
    await pg.evaluate("S.sub='set';render()"); await pg.wait_for_timeout(600); await sh('settings')
    t=await pg.inner_text('#view'); ck('设置页无「即将推出」','即将推出' not in t,t[:300])
    ck('设置页有 访客 Wi‑Fi / 新设备默认访客 / 导入 / 高级模式','访客 Wi‑Fi' in t and '新设备默认算访客' in t and '导入' in t and '高级模式' in t)
    await pg.click('[data-a=gwifi]'); await pg.wait_for_timeout(500); await pg.screenshot(path=f'{OUT}/m6-guest-wifi-{TH}-mobile.png')
    ck('访客 Wi‑Fi 表单：随机密码 ≥10 位',await pg.evaluate("$('#gk').value.length>=10")); await pg.click('#g_x'); await pg.wait_for_timeout(300)
    await pg.click('[data-a=import]'); await pg.wait_for_timeout(500)
    await pg.click('#isrc [data-v=text]'); await pg.fill('#it','rules:\n  - DOMAIN-SUFFIX,example-a.com,Proxy\n  - DOMAIN,b.example.com,DIRECT\n  - GEOIP,CN,DIRECT\n')
    await pg.click('#i_pv'); await pg.wait_for_timeout(1200); await pg.screenshot(path=f'{OUT}/m6-import-preview-{TH}-mobile.png')
    ck('导入预览显示规则 + 选择去向',await pg.evaluate("!!document.querySelector('#itg')&&!!document.querySelector('#i_ap')"))
    await pg.evaluate("document.querySelector('.mask').remove()"); await pg.wait_for_timeout(200)
    await pg.click('[data-a=raw]'); await pg.wait_for_timeout(900); await pg.screenshot(path=f'{OUT}/m6-advanced-{TH}-mobile.png')
    v=await pg.evaluate("$('#rt').value"); ck('高级模式显示 JSON 且密钥已掩码','"secret": "********"' in v)
    await pg.evaluate("$('#rt').value=$('#rt').value.replace('\"log_level\": \"warn\"','\"log_level\": \"warn\",,')"); await pg.click('#r_ck'); await pg.wait_for_timeout(700)
    ck('校验错误提示行号',await pg.evaluate("$('#r_msg').textContent.includes('行')"),await pg.evaluate("$('#r_msg').textContent"))
    await pg.evaluate("document.querySelector('.mask').remove()")
    # 清理演示规则集
    await pg.evaluate("act('/ruleset/delete',{name:'演示规则集'})"); await pg.wait_for_timeout(1500)
    # 老交互回归：抽屉滚动锁 + 下拉关闭
    await tab('dv'); await pg.evaluate("scrollTo(0,200)"); y0=await pg.evaluate("scrollY")
    await pg.evaluate("sheet('<h3>测试抽屉</h3>'+'<p>行</p>'.repeat(40))"); await pg.wait_for_timeout(600)
    ck('抽屉打开 → body 锁定',await pg.evaluate("getComputedStyle(document.body).position")=='fixed')
    await pg.screenshot(path=f'{OUT}/m6-sheet-{TH}-mobile.png')
    cdp=await ctx.new_cdp_session(pg); sb=await pg.evaluate("(()=>{const b=document.querySelector('.sheet').getBoundingClientRect();return [b.x+b.width/2,b.y+20,b.height]})()")
    await cdp.send('Input.dispatchTouchEvent',{'type':'touchStart','touchPoints':[{'x':sb[0],'y':sb[1]}]})
    for k in range(1,9): await cdp.send('Input.dispatchTouchEvent',{'type':'touchMove','touchPoints':[{'x':sb[0],'y':sb[1]+sb[2]*0.45*k/8}]}); await pg.wait_for_timeout(30)
    await cdp.send('Input.dispatchTouchEvent',{'type':'touchEnd','touchPoints':[]}); await pg.wait_for_timeout(800)
    ck('下拉超过 30% 关闭 + 恢复滚动',await pg.evaluate("!document.querySelector('.mask')&&document.body.style.position==''"))
    await tab('nd'); ck('节点页仍是「使用中」标签、无圆点',await pg.evaluate("document.querySelectorAll('.inuse').length>0&&!document.querySelector('#view .mem .dot')"))
    ck('无 JS 错误',not errs,errs)
    # 桌面
    await pg.set_viewport_size({'width':1280,'height':860}); await tab('ov') if False else None
    await pg.evaluate("S.tab='ov';nav();render()"); await pg.wait_for_timeout(900); await pg.screenshot(path=f'{OUT}/m6-overview-{TH}-desk.png')
    await b.close()
  print(f'{sum(R)}/{len(R)} PASS')
asyncio.run(main())
