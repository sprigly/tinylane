const $=s=>document.querySelector(s);
const IC={
ov:'<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 9h8V3h-8z"/>',
nd:'<circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5 6.5 17M12 11.5l5.5 5.5"/>',
sb:'<path d="M4 4h16v4H4zM4 10h16v4H4zM4 16h10v4H4z"/>',
dv:'<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/>',
lg:'<path d="M4 6h16M4 12h16M4 18h10"/>',
st:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>'};
const TABS=[['ov','概览'],['nd','节点'],['sb','订阅'],['dv','设备'],['lg','日志'],['st','规则']];
const svg=k=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${IC[k]}</svg>`;
const MODES={rule:'规则分流',global:'全局代理',direct:'全局直连'};
const MT={domain:'完整域名',domain_suffix:'域名后缀',domain_keyword:'关键词',domain_regex:'正则',ip_cidr:'IP 段',port:'端口',source_ip:'来源 IP'};
const LS=localStorage;
const S={rx:{},tab:LS.tl_tab||'ov',theme:LS.tl_theme||'auto',accent:LS.tl_accent||'blue',st:null,lv:{traffic:[]},cx:null,lgv:'dev',appView:false,paused:false,q:'',sub:'rule',ord:{},rules:null,busy:{}};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtR=b=>b>=1048576?(b/1048576).toFixed(1)+' MB/s':b>=1024?Math.round(b/1024)+' KB/s':Math.round(b||0)+' B/s';
const fmtB=b=>b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(1)+' MB':Math.round((b||0)/1024)+' KB';
const kb=v=>v>=1024?(v/1024).toFixed(1)+' MB/s':v+' KB/s';
const tz={timeZone:'Asia/Shanghai',hour12:false};
function tfmt(u){if(!u)return'—';const d=new Date(u*1e3),n=new Date(),day=x=>x.toLocaleDateString('zh-CN',tz);const hm=d.toLocaleTimeString('zh-CN',{...tz,hour:'2-digit',minute:'2-digit'});if(day(d)==day(n))return hm;const y=new Date(n-864e5);return day(d)==day(y)?'昨天 '+hm:d.toLocaleDateString('zh-CN',{...tz,month:'2-digit',day:'2-digit'})+' '+hm}
function ago(u){if(!u)return'未检测';const s=Date.now()/1e3-u;return s<60?'刚刚':s<3600?Math.floor(s/60)+' 分钟前':Math.floor(s/3600)+' 小时前'}
function toast(t,bad){const e=document.createElement('div');e.className='toast'+(bad?' bad':'');e.textContent=t;document.body.appendChild(e);setTimeout(()=>e.remove(),bad?4200:1800)}
function sheet(html,onMount){const m=document.createElement('div');m.className='mask';const g=html.startsWith('<div class="grab"')||html.startsWith('<div id="login"')?'':'<div class="grab"></div>';m.innerHTML=`<div class="sheet">${g}${html}</div>`;m.onclick=e=>{if(e.target===m)m.remove()};document.body.appendChild(m);onMount&&onMount(m);if(!m.querySelector('#login'))swipeSheet(m);return m}
// 抽屉/弹窗打开时锁住背后页面（含 iOS Safari：body position:fixed + 记住滚动位置，关闭后恢复）。所有 .mask 都直接挂在 body 上，统一由 MutationObserver 处理，任何关闭方式都会解锁。
const SL={on:0,y:0};
function scrollLock(on){const b=document.body.style;if(on&&!SL.on){SL.on=1;SL.y=scrollY;Object.assign(b,{position:'fixed',top:-SL.y+'px',left:'0',right:'0',width:'100%',overflow:'hidden'})}else if(!on&&SL.on){SL.on=0;Object.assign(b,{position:'',top:'',left:'',right:'',width:'',overflow:''});scrollTo(0,SL.y)}}
new MutationObserver(()=>scrollLock(!!document.querySelector('body>.mask'))).observe(document.body,{childList:true});
// 下滑关闭：内容滚到顶再往下拖，抽屉跟手（带阻尼）；松手超过 30% 高度或快速下甩 → 动画关闭，否则回弹。
function swipeSheet(m){const s=m.querySelector('.sheet');if(!s)return;let y0=0,t0=0,dy=0,st=0;// st: 0 未定 1 拖抽屉 2 正常滚动
 const set=(y,an)=>{s.style.transition=an?'transform .24s cubic-bezier(.2,.8,.2,1)':'none';s.style.transform=y?`translateY(${y}px)`:'';m.style.transition=an?'background-color .24s':'none';m.style.backgroundColor=y?`rgba(0,0,0,${(.53*Math.max(0,1-y/s.offsetHeight)).toFixed(3)})`:''};
 s.addEventListener('touchstart',e=>{if(e.touches.length!=1){st=2;return}y0=e.touches[0].clientY;t0=Date.now();dy=0;st=0},{passive:true});
 s.addEventListener('touchmove',e=>{if(st==2||e.touches.length!=1)return;const d=e.touches[0].clientY-y0;
  if(st==0){if(Math.abs(d)<6)return;const ta=e.target.closest&&e.target.closest('textarea,.dlist,.tw');if(d>0&&s.scrollTop<=0&&!(ta&&(ta.scrollTop>0||ta.classList.contains('dlist')))){st=1;y0=e.touches[0].clientY;t0=Date.now()}else{st=2;return}}
  e.preventDefault();dy=Math.max(0,e.touches[0].clientY-y0);const h=s.offsetHeight||1;set(dy<h*.3?dy:h*.3+(dy-h*.3)*.55,false)},{passive:false});
 const end=()=>{if(st!=1){st=0;return}st=0;const h=s.offsetHeight||1,v=dy/Math.max(1,Date.now()-t0);
  if(dy>h*.3||(v>.6&&dy>40)){set(h+40,true);setTimeout(()=>m.dispatchEvent(new MouseEvent('click',{bubbles:false})),230)}else set(0,true)};
 s.addEventListener('touchend',end,{passive:true});s.addEventListener('touchcancel',end,{passive:true})}
async function A(path,body){const o=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-TL':'1'},body:JSON.stringify(body)};
 const r=await fetch('/api'+path,o);const j=await r.json().catch(()=>({}));if(r.status==401&&path!='/login'){login();throw new Error('请先登录')}if(!r.ok)throw new Error(j.error||'HTTP '+r.status);return j}
async function act(path,body,ok,el){if(el){if(el.dataset.busy)return;el.dataset.busy=1;el.dataset.t=el.textContent;el.textContent='…'}
 try{const j=await A(path,body);if(ok)toast(ok);await loadState();return j}catch(e){toast('✗ '+e.message,1)}finally{if(el&&el.isConnected){delete el.dataset.busy;el.textContent=el.dataset.t}}}
const nodeBy=n=>(S.st?.nodes||[]).find(x=>x.name==n)||{name:n,type:'?'};
const gl=g=>g?(g.label||g.name):'';
function lab(o){const g=(S.st?.groups||[]).find(x=>x.name==o);return g?gl(g):o}
function relab(t){for(const g of S.st?.groups||[]){if(!g.label||g.label==g.name)continue;const suf=g.label.startsWith(g.name)?g.label.slice(g.name.length):'';t=t.split(g.name).map((x,i,a)=>i<a.length-1?x+(suf&&a[i+1].startsWith(suf)?g.name:g.label):x).join('')}return t}
const KEEP=new Set(['data-busy','data-t']),DG=new WeakSet();
function morph(a,b){if(a.dataset&&a.dataset.busy&&b.nodeType==1)return;if(a.nodeType!==b.nodeType||a.nodeName!==b.nodeName){a.replaceWith(b);return}
 if(a.nodeType!==1){if(a.nodeValue!==b.nodeValue)a.nodeValue=b.nodeValue;return}
 for(const x of [...a.attributes])if(!b.hasAttribute(x.name)&&!KEEP.has(x.name))a.removeAttribute(x.name);
 for(const x of [...b.attributes])if(a.getAttribute(x.name)!==x.value)a.setAttribute(x.name,x.value);
 if(a.tagName=='INPUT'||a.tagName=='TEXTAREA'||a.tagName=='SELECT'){if(document.activeElement!==a&&a.tagName!='SELECT'&&a.value!==b.value)a.value=b.value;if(a.tagName!='SELECT')return}
 kids(a,b)}
function kids(a,b){const bc=[...b.childNodes],ac=[...a.childNodes],keyed=bc.length&&bc.every(n=>n.nodeType==1&&n.dataset.k);
 if(keyed){const m=new Map();ac.forEach(n=>{if(n.nodeType==1&&n.dataset.k&&!m.has(n.dataset.k))m.set(n.dataset.k,n);else n.remove()});let prev=null;
  for(const n of bc){let o=m.get(n.dataset.k);if(o){m.delete(n.dataset.k);morph(o,n);if(!o.isConnected)o=n}else o=n;
   const want=prev?prev.nextSibling:a.firstChild;if(o!==want)a.insertBefore(o,want);prev=o}
  m.forEach(n=>n.remove());return}
 for(let i=0;i<bc.length;i++){if(i<ac.length)morph(ac[i],bc[i]);else a.appendChild(bc[i])}for(let i=bc.length;i<ac.length;i++)ac[i].remove()}
function patch(el,html){if(!el)return;const t=document.createElement(el.tagName);t.innerHTML=html;kids(el,t)}
const ptag=t=>t=='hysteria2'?'<span class="tag t-hy2">hy2</span>':t=='vless'?'<span class="tag t-vl">VLESS</span>':`<span class="tag">${esc(t)}</span>`;
const egTag=d=>{const e=d&&d.egress;if(d&&d.eg_pending&&!(e&&e.ip))return '<span class="tag">出口检测中…</span>';if(e&&e.ip)return `<span class="tag" data-egt="${esc(d.name)}" title="${esc([e.org,e.city].filter(Boolean).join(' · ')+' · 点击重测')}">出口 ${esc(e.cc?e.cc+' ':'')}${esc(e.ip)}</span>`;if(e&&e.err)return `<span class="tag t-blk" data-egt="${esc(d.name)}" title="${esc(e.err)} · 点击重测">出口未测出</span>`;return ''};
const nmRe=p=>{p=(p||'').trim();if(!p)return null;if(p.length>1&&p[0]=='/'&&p.endsWith('/')){try{const r=new RegExp(p.slice(1,-1),'i');return s=>r.test(s)}catch(e){return null}}const k=p.split(/[|,，]/).map(x=>x.trim().toLowerCase()).filter(Boolean);return k.length?s=>{s=s.toLowerCase();return k.some(x=>s.includes(x))}:null};
function hdot(h){if(!h||!h.delay_at)return'idle';if(h.heavy_ok===false||h.fail_streak>0)return h.fail_streak>=3||h.heavy_fail>=3?'bad':'warn';return h.delay?'ok':'bad'}
const KTAG='<span class="tag t-dir" title="国内 IP 由路由器内核直接转发，不经过代理内核">内核直连</span>';
function outTag(o){return o=='direct'||o=='直连'?'<span class="tag t-dir">直连</span>':o=='block'||o=='拦截'?'<span class="tag t-blk">拒绝</span>':`<span class="tag t-px">${esc(lab(o))}</span>`}
function nav(){
 const h=TABS.map(([k,n])=>`<button data-t="${k}" class="${S.tab==k?'on':''}">${svg(k)}<span>${n}</span></button>`).join('');
 $('#tb').innerHTML=h;$('#side').innerHTML='<div class="logo"><i></i>TinyLane</div>'+TABS.map(([k,n])=>`<button data-t="${k}" class="${S.tab==k?'on':''}">${svg(k)}${k=='st'?'规则与设置':n}</button>`).join('');
 document.querySelectorAll('[data-t]').forEach(b=>b.onclick=()=>{S.tab=LS.tl_tab=b.dataset.t;nav();render();scrollTo(0,0);if(['ov','dv','lg'].includes(S.tab))loadConns()});
}
function head(){const st=S.st;if(!st)return;const p=$('#mpill');
 p.textContent=st.fallback?'内核异常·直连':st.enabled?MODES[st.mode]:'已停用';p.className='pill'+(st.enabled&&!st.fallback?'':' off');
 $('#hsw').className='sw'+(st.enabled?' on':'');const l=S.lv.traffic.at(-1)||[0,0];$('#hspd').innerHTML=`↓ ${fmtR(l[1])}<br>↑ ${fmtR(l[0])}`}
function chart(){const W=300,H=90,pts=S.lv.traffic.slice(-60);if(pts.length<2)return`<div class="mut" style="height:90px;display:grid;place-items:center;font-size:12px">等待流量数据…</div>`;
 const mx=Math.max(1024,...pts.map(p=>Math.max(p[0],p[1])))*1.15,n=pts.length-1;
 const pt=k=>pts.map((p,i)=>`${(i/n*W).toFixed(1)},${(H-p[k]/mx*H).toFixed(1)}`).join(' ');
 return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><defs><linearGradient id="g" x1="0" x2="0" y1="0" y2="1"><stop offset="0" style="stop-color:var(--acc);stop-opacity:.35"/><stop offset="1" style="stop-color:var(--acc);stop-opacity:0"/></linearGradient></defs><polygon fill="url(#g)" points="0,${H} ${pt(1)} ${W},${H}"/><polyline fill="none" style="stroke:var(--acc)" stroke-width="1.8" points="${pt(1)}" vector-effect="non-scaling-stroke"/><polyline fill="none" stroke="#a78bfa" stroke-width="1.5" points="${pt(0)}" vector-effect="non-scaling-stroke"/></svg>`}
const V={};
function grp(n){return (S.st?.groups||[]).find(g=>g.name==n)}
function evList(n){const ev=(S.st?.events||[]).slice(0,n);return ev.length?ev.map(e=>`<div class="ev"><time>${tfmt(e.t)}</time><div class="${e.kind=='error'?'chg':''}">${esc(relab(e.msg))}</div></div>`).join(''):'<p class="mut">暂无事件</p>'}
V.ov=()=>{const st=S.st,g=grp(st.main_group)||st.groups[0],n=g?.now||'—',nd=nodeBy(n),h=nd.health||{},mg=st.groups.find(x=>x.strict&&x.type=='failover'&&x.name!=g?.name)||st.groups.find(x=>x.type=='failover'&&x.name!=g?.name),cx=S.cx;
 const on=cx?cx.devices.filter(d=>d.online).length:'…';
 return `<h2>概览</h2>${rawBanner()}
${st.fallback?'<div class="banner bad">内核短时间内多次崩溃，已自动撤掉透明代理，全部设备临时直连上网；内核稳定后会自动恢复。</div>':''}
${st.enabled?'':'<div class="banner">代理已停用，所有设备直连上网。</div>'}
<div class="card"><div class="row" style="margin-bottom:12px"><div style="flex:1"><b>启用代理</b><div class="mut" style="font-size:12px">关闭后全部直连，不影响上网</div></div><div class="sw ${st.enabled?'on':''}" data-a="power"></div></div>
<div class="seg">${Object.entries(MODES).map(([k,v])=>`<button data-mode="${k}" class="${st.mode==k?'on':''}">${v}</button>`).join('')}</div></div>
<div class="cols"><div class="card"><h3><span class="dot d-${st.enabled&&!st.fallback?hdot(h):'idle'}"></span>${esc(gl(g)||'主线路')} · 当前节点</h3>
<div style="font-size:19px;font-weight:600;overflow-wrap:anywhere">${esc(n)} ${ptag(nd.type)}</div>
<div class="kv"><div><span>延迟</span>${h.delay?h.delay+' ms':'—'}</div><div><span>探测下载</span>${h.heavy_at?kb(h.down_kbps):'—'}</div><div><span>探测上传</span>${h.heavy_at?kb(h.up_kbps):'—'}</div></div>
<div class="mut" style="font-size:12px;margin-top:8px">${g?.type=='failover'?(g.hold_until*1e3>Date.now()?'手动锁定中 · '+tfmt(g.hold_until)+' 恢复自动':'自动切换 · '+ago(g.last_check)+'检测'):'手动选择'}${g?.note?' · '+esc(g.note):''}</div></div>
<div class="card"><h3>实时流量 <span class="sp"></span><span class="mut" style="font-size:11.5px;font-weight:400"><span style="color:var(--acc)">━</span> 下行 <span style="color:#a78bfa">━</span> 上行</span></h3><div id="chart">${chart()}</div></div></div>
<div class="grid"><div class="tile"><small>在线设备</small><b>${on}</b></div><div class="tile"><small>今日流量</small><b>${st.traffic?.ok?fmtB(st.traffic.today_down+st.traffic.today_up):cx?fmtB(cx.down_total+cx.up_total):'…'}</b><small>${st.traffic?.ok?'↓ '+fmtB(st.traffic.today_down)+' · ↑ '+fmtB(st.traffic.today_up):cx?'启动以来 ↓ '+fmtB(cx.down_total):''}</small></div><div class="tile"><small>当前连接</small><b>${cx?cx.total:'…'}</b></div><div class="tile"><small>${esc(mg?gl(mg):'第二组')} 线路</small><b style="font-size:15px;margin-top:6px;overflow-wrap:anywhere">${esc(mg?.now||'—')}</b></div></div>
<div class="card"><h3>最近事件</h3>${evList(8)}</div>`};
function lat(h){const stale=!h.delay&&h.delay_at&&h.last_ok&&h.fail_streak<2&&h.delay_at-h.last_ok_at<900;if(stale)return `<div class="num lat-stale" title="刚才一次测试失败，显示上次成功的值">${h.last_ok} ms</div>`;const bad=h.delay_at&&(!h.delay||h.fail_streak>0),c=!h.delay_at?'lat-n':bad?'lat-bad':h.heavy_ok===false?'lat-warn':'lat-ok';return `<div class="num ${c}">${h.delay?h.delay+' ms':h.delay_at?'超时':'未测'}</div>`}
function lockTag(g){return g.strict?'<span class="tag t-blk" title="组里没有可用节点时断网，不回落直连">🔒 断网保护</span>':''}
function gRule(g){const a=[];if(g.filter)a.push('自动加入名称含「'+g.filter+'」');if(g.exclude)a.push('排除「'+g.exclude+'」');return a.length?`<div class="mut" style="font-size:12px;margin-bottom:6px">${esc(a.join(' · '))} · 共 ${g.eff.length} 个</div>`:''}
// M7a：全部节点按来源分组折叠（手风琴：同时最多展开一个，LS.tl_ndsec 记当前展开的那个，'' = 全收起）
function ndRow(d){const h=d.health||{};return `<div class="mem nb"><div class="row"><div class="nm"><div>${esc(d.name)}</div></div>${lat(h)}</div><div class="row"><div class="tags">${ptag(d.type)}${egTag(d)}<span class="tag">${d.source=='manual'?'手动':'订阅'}</span>${h.heavy_at?`<span class="mut tp">↓${kb(h.down_kbps)} ↑${kb(h.up_kbps)}</span>`:''}</div><div class="trail">${d.mtu!==undefined?`<span class="mut tp">MTU</span><div class="sw sm ${d.mtu?'on':''}" data-mtu="${esc(d.name)}" title="MTU 修正"></div>`:''}<button class="btn" data-tn="${esc(d.name)}">测速</button>${d.source=='manual'||(d.source.startsWith('sub:')&&!S.st.subs.some(s=>'sub:'+s.name==d.source))?`<button class="btn dan" data-dn="${esc(d.name)}">删</button>`:''}</div></div></div>`}
function ndSecs(st){const subs=st.subs||[],ks=subs.map(s=>'sub:'+s.name),sec=[...subs.map(s=>({k:'sub:'+s.name,n:s.name,l:[]})),{k:'manual',n:'手动',l:[]},{k:'other',n:'其他',l:[]}];
 st.nodes.forEach(d=>{const i=d.source=='manual'?subs.length:ks.indexOf(d.source);sec[i>=0?i:subs.length+1].l.push(d)});
 const open=LS.tl_ndsec||'';return sec.filter((x,i)=>i<subs.length||x.l.length).map(x=>{const on=x.k==open,ok=x.l.filter(d=>d.health&&d.health.delay).length;
 return `<div class="nsec ${on?'on':''}" data-k="ns${esc(x.k)}"><div class="nsh" data-ns="${esc(x.k)}" role="button" aria-expanded="${on}"><div class="nst"><b>${esc(x.n)}</b><div class="mut">${x.l.length} 个节点 · ${ok} 个可用${x.k=='other'?' · 订阅已删除':''}</div></div>${x.l.length?`<button class="btn" data-nsd="${esc(x.k)}">测延迟</button>`:''}<span class="chev" aria-hidden="true">›</span></div>${on?`<div class="nsb">${x.l.map(ndRow).join('')||'<p class="mut" style="padding:10px 0">这个订阅还没有节点</p>'}</div>`:''}</div>`}).join('')||'<p class="mut">还没有节点</p>'}
function ndSecNodes(k){const st=S.st,ks=st.subs.map(s=>'sub:'+s.name);return st.nodes.filter(d=>k=='manual'?d.source=='manual':k=='other'?d.source!='manual'&&!ks.includes(d.source):d.source==k)}
V.nd=()=>{const st=S.st;return `<h2>节点</h2>${st.groups.map((g,gi)=>{const m=g.eff.filter(n=>!g.auto.includes(n)),fo=g.type=='failover',held=g.hold_until*1e3>Date.now();const row=(n,i,au)=>{const d=nodeBy(n),h=d.health||{};return `<div class="mem ${au?'':'drag'}" data-k="${esc(n)}" data-n="${esc(n)}">${au?'<span class="hdl au" aria-hidden="true">⠿</span>':'<span class="hdl" aria-label="拖动排序">⠿</span>'}<div class="nm ${fo?'':'dl'}" ${fo?'':`data-sel="${gi},${esc(n)}"`}><div><span class="no">${i+1}</span>${esc(n)}${n==g.now?'<span class="inuse">使用中</span>':''}</div>${ptag(d.type)}${au?' <span class="tag">自动</span>':''} ${egTag(d)}${h.heavy_at?` <span class="mut tp">↓${kb(h.down_kbps)} ↑${kb(h.up_kbps)}</span>`:''}</div>${lat(h)}</div>`};return `<div class="card"><h3>${esc(gl(g))}<span class="tag">${fo?'故障切换':'手动'}</span>${lockTag(g)}</h3>
${held?`<div class="banner" style="margin-bottom:8px">手动锁定中，${tfmt(g.hold_until)} 恢复自动切换</div>`:''}${g.now=='direct'?'<div class="banner" style="margin-bottom:8px">组内节点全部不可用，暂时直连；节点恢复后自动切回</div>':''}${!g.eff.length?`<div class="banner bad" style="margin-bottom:8px">组里没有节点：${g.strict?'这个组的流量会被拒绝（断网保护）':'这个组的流量会直连'}</div>`:''}${g.note?`<div class="mut" style="font-size:12px;margin-bottom:6px">${esc(relab(g.note))}</div>`:''}${gRule(g)}
<div class="dlist" data-gi="${gi}">${m.map((n,i)=>row(n,i,0)).join('')}</div>${g.auto.length?`<div class="alist">${g.auto.map((n,i)=>row(n,m.length+i,1)).join('')}</div>`:''}
<div class="mut" style="font-size:11.5px;margin-top:6px">${fo?'顺序 = 优先级：看门狗用排在最前、且能用的节点，出问题按顺序往下切，前面的恢复后自动切回。':'点节点名手动切换。'}按住节点拖动调整顺序，松手自动保存${g.auto.length?'；「自动」= 按名称筛选加入，排在手选之后':''}。</div>
<div class="btns"><button class="btn pri" data-test="${gi}">测延迟</button><button class="btn" data-eg="${gi}">编辑组</button>${held?`<button class="btn" data-auto="${gi}">恢复自动</button>`:''}</div></div>`}).join('')}
<button class="btn big" data-a="addgroup">＋ 新建组</button>
<div class="card"><h3>全部节点 <span class="sp"></span><button class="btn" data-a="addnode">+ 手动添加</button></h3>${ndSecs(st)}
<p class="mut" style="font-size:11.5px;margin-top:8px">测速 = 经专用探测入口下载 ${Math.round(st.watchdog.down_bytes/1024)} KB + 上传 ${Math.round(st.watchdog.up_bytes/1024)} KB（speed.cloudflare.com）</p></div>`};
const maskURL=u=>{const m=/^(\w+:\/\/[^/]+)(\/[^/?#]*)?/.exec(u||'');return m?m[1]+(m[2]&&m[2].length>1?m[2]+'/•••':'/•••'):'•••'};
const AUTO={weekly:'每周一 08:00',daily:'每天 08:00',off:'手动'};
V.sb=()=>{const st=S.st;return `<h2>订阅</h2>${st.subs.map((s,i)=>`<div class="card"><h3>${esc(s.name)}<span class="tag">${s.count||0} 节点</span></h3>${s.last_error?`<div class="banner bad">上次自动更新失败：${esc(s.last_error)}</div>`:''}<div class="kv"><div><span>上次更新</span>${esc(s.updated||'从未')}</div><div><span>自动更新</span>${AUTO[s.auto]||s.auto}</div><div><span>格式</span>自动识别</div></div><div class="mono mut" style="margin-top:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(maskURL(s.url))}</div><div class="btns"><button class="btn pri" data-upd="${i}">立即更新</button><button class="btn" data-es="${i}">编辑</button><button class="btn dan" data-ds="${i}">删除</button></div></div>`).join('')||'<div class="card mut">还没有订阅。现有节点是之前用 import-clash 导入的，添加订阅后第一个订阅会接管它们。</div>'}
<button class="btn big" data-es="-1">＋ 添加订阅</button>
<div class="card"><h3>导入设置</h3><div class="fld"><label>过滤信息条目（名称含这些的不导入，| 分隔）</label><input id="ix" value="${esc(st.import.exclude)}"></div><div class="set"><div>自动检测出口<div class="mut sm2">新节点导入后经该节点测一次出口 IP，一次只测一个</div></div><div class="sw ${st.import.egress_probe?'on':''}" id="iep"></div></div><div class="btns"><button class="btn pri" data-a="impset">保存</button><button class="btn" data-a="ixdef">恢复默认</button><button class="btn" data-a="egall">重测全部出口</button></div></div>
<p class="mut" style="font-size:12px;margin:12px 4px">支持 Clash YAML、Base64 分享链接、明文分享链接、sing-box JSON（hy2 / VLESS / VMess / Trojan / SS / TUIC / AnyTLS）。手动添加的节点更新时永久保留；更新前先显示差异，确认后才生效。删除订阅会连同它导入的节点一起删除。</p>`};
const DT={phone:['📱','手机'],computer:['💻','电脑'],tablet:['📱','平板'],tv:['📺','电视/盒子'],other:['🔌','其他']};
function devIcon(d){if(d.type&&DT[d.type])return DT[d.type][0];const h=(d.hostname+' '+(d.name||'')).toLowerCase();return /iphone|android|phone|redmi|xiaomi|huawei|oppo|vivo|手机/.test(h)?'📱':/ipad|pad|tab/.test(h)?'📱':/mac|book|laptop|pc|desktop|win|蛟龙|电脑/.test(h)?'💻':/tv|电视|box/.test(h)?'📺':'🔌'}
function sig(d){if(!d.wifi)return'';const v=d.signal,n=v>=-55?4:v>=-65?3:v>=-75?2:1,c=n>=3?'var(--ok)':n==2?'var(--warn)':'var(--bad)';return `<span class="sig" title="${v} dBm">${[1,2,3,4].map(i=>`<i style="height:${i*3+2}px;background:${i<=n?c:'var(--line)'}"></i>`).join('')}</span>`}
const dday=u=>u?new Date(u*1e3).toLocaleDateString('zh-CN',{...tz,year:'numeric',month:'2-digit',day:'2-digit'}):'—';
const dname=d=>d.name||d.hostname||d.ip||'未知设备';
function dmode(d){if(d.guest&&S.st.guest.direct_only)return'访客 · 仅直连';return d.mode=='follow'?'跟随全局':d.mode=='direct'?'全局直连':'全局代理'+(d.group?' · '+lab(d.group):'')}
// M6b：设备卡操作按钮。顺序：指定模式 · 改名/类型 · 设为访客 / 查看连接 · 踢下线 · 拉黑（破坏性放最后）；6 列网格按个数等分（6/3 → 每排 3 个，4/2 → 每排 2 个，5 → 3+2）
function dago(t){if(!t)return'';const m=Math.floor((Date.now()/1000-t)/60);return m<1?'刚刚活动':m<60?`${m} 分钟前活动`:`${Math.floor(m/60)} 小时前活动`}
function dstC(d){return d.state=='sleep'?'sl-c':d.online?'':'off-c'}
function devBtns(d){const b=[];if(d.ip&&(d.online||d.state=='sleep'))b.push(`<button class="btn" data-dm="${esc(d.ip)}">指定模式</button>`);
 if(d.mac)b.push(`<button class="btn" data-ren="${esc(d.mac)}">改名/类型</button>`,`<button class="btn" data-gt="${esc(d.mac)}">${d.guest?'设为家人':'设为访客'}</button>`);
 if(d.ip)b.push(`<button class="btn" data-vc="${esc(d.ip)}" data-vo="${d.online?1:0}">查看连接</button>`);
 if(d.wifi)b.push(`<button class="btn" data-kick="${esc(d.mac)}">踢下线</button>`);if(d.mac)b.push(`<button class="btn dan" data-ban="${esc(d.mac)}">拉黑</button>`);
 return `<div class="btns dg n${b.length}">${b.join('')}</div>`}
// 查看连接：切到日志页，复用现有的按设备筛选——在线设备打开它的连接抽屉（只列这台设备），离线设备进「24 小时」并选中这台设备
function viewConns(ip,online){S.tab=LS.tl_tab='lg';nav();if(online){S.lgv='dev';render();scrollTo(0,0);loadConns();setTimeout(()=>{if(S.cx?.devices.some(x=>x.ip==ip))openDrawer(ip)},60)}else{S.lgv='hist';S.hip=ip;S.hist=null;render();scrollTo(0,0);loadHist()}}
V.dv=()=>{const cx=S.cx;if(!cx)return'<h2>设备</h2><div class="card mut">读取中…</div>';const ds=cx.devices.filter(d=>!d.black),bl=cx.devices.filter(d=>d.black);
 return `<h2>设备 <span class="mut" style="font-size:13px;font-weight:400">${ds.filter(d=>d.online).length} 在线${ds.some(d=>d.state=='sleep')?` · ${ds.filter(d=>d.state=='sleep').length} 休眠`:''} · 共 ${ds.length} 台</span></h2>${ds.map(d=>`<div class="card ${dstC(d)}" data-k="${esc(d.mac||d.ip)}"><div class="dev"><div class="ico">${devIcon(d)}</div><div style="flex:1;min-width:0"><div class="row"><b style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(dname(d))}</b><span class="tag ${d.guest&&S.st.guest.direct_only?'t-dir':d.mode=='follow'?'':'t-px'}">${esc(dmode(d))}</span></div><div class="mono mut">${esc(d.ip||'—')} · ${esc(d.mac||'—')}</div>${d.state=='sleep'?`<div class="dst">休眠 · ${dago(d.last_active)}</div>`:''}</div></div>
<div class="kv"><div><span>今日流量</span><span class="mono" style="display:block;color:var(--tx);font-size:12.5px;line-height:1.35">↓ ${fmtB(d.today_down)}<br>↑ ${fmtB(d.today_up)}</span></div><div><span>连接方式</span>${d.wifi?`${sig(d)} ${esc(d.band)} · <em style="font-style:normal;white-space:nowrap">${d.signal} dBm</em>`:esc(d.conn||(d.online?'有线 / 未知':'—'))}</div><div><span>直连 / 代理</span>${d.direct} / ${d.proxy}</div><div><span>下行</span><b class="mono">${d.online?fmtR(d.nft_down_rate||d.down_rate):'—'}</b></div><div><span>上行</span><b class="mono">${d.online?fmtR(d.nft_up_rate||d.up_rate):'—'}</b></div><div><span>首次出现</span>${dday(d.first_seen)}</div></div>
${d.state=='sleep'?'<p class="mut dnote">设备休眠中（如合盖的 Mac），暂时没连在 Wi‑Fi 上，唤醒连上后才能踢下线；30 分钟没有活动才算离线。</p>':''}${devBtns(d)}</div>`).join('')||'<div class="card mut">没有发现设备</div>'}
${bl.length?`<h3 style="margin:18px 4px 10px">已拉黑</h3>`+bl.map(d=>`<div class="card off-c" data-k="b${esc(d.mac)}"><div class="dev"><div class="ico">⛔</div><div style="flex:1;min-width:0"><b>${esc(dname(d))}</b><div class="mono mut">${esc(d.ip||'')} ${esc(d.mac)}</div></div><button class="btn" data-unban="${esc(d.mac)}">解除拉黑</button></div></div>`).join(''):''}
<p class="mut" style="font-size:11.5px;margin:4px">按设备指定模式依赖固定 IP（DHCP 静态租约）。踢下线 = 让 Wi‑Fi 断开并在设定时间内拒绝重连（只对 Wi‑Fi 设备，Wi‑Fi 重启后失效）；拉黑 = 路由器丢弃该 MAC 的所有包（Wi‑Fi 仍可连上）。信号每 5 秒刷新。</p>`};
const APPS=[['抖音','douyin.com amemv.com snssdk.com douyinvod.com douyinpic.com bytedance.com ixigua.com pstatp.com byteimg.com zjcdn.com bytecdn.cn douyincdn.com'],['微信/QQ','weixin.qq.com wechat.com qq.com qpic.cn gtimg.com qlogo.cn'],['淘宝/阿里','taobao.com alicdn.com tmall.com alipay.com aliyun.com'],['哔哩哔哩','bilibili.com bilivideo.com hdslb.com biliapi.net'],['X','x.com twimg.com twitter.com t.co'],['Grok','x.ai grok.com'],['Instagram','instagram.com cdninstagram.com'],['Meta','facebook.com fbcdn.net fbsbx.com meta.ai meta.com messenger.com facebook.net muse.ai'],['WhatsApp','whatsapp.com whatsapp.net'],['YouTube','youtube.com googlevideo.com ytimg.com youtu.be'],['Google','google.com gstatic.com googleapis.com gvt1.com gvt2.com googleusercontent.com'],['Telegram','telegram.org t.me'],['GitHub','github.com githubusercontent.com github.io'],['Apple','apple.com icloud.com mzstatic.com aaplimg.com apple-dns.net cdn-apple.com'],['ChatGPT','openai.com chatgpt.com oaistatic.com oaiusercontent.com'],['Netflix','netflix.com nflxvideo.net nflximg.net'],['小红书','xiaohongshu.com xhscdn.com'],['百度','baidu.com bdstatic.com'],['知乎','zhihu.com zhimg.com'],['Cloudflare','cloudflare.com']].map(([n,s])=>[n,s.split(' ')]);
const appOf=h=>{for(const[n,l]of APPS)if(l.some(s=>h==s||h.endsWith('.'+s)))return n;return /^[\d.]+$/.test(h)?'IP 直连':h.split('.').slice(-2).join('.')};
function connRows(list){return list.slice(0,80).map(c=>`<div class="lr" data-k="${esc(c.id)}"><div class="row"><b style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(appOf(c.host))}</b>${c.kern?KTAG:outTag(c.out=='direct'?'direct':c.rule.includes('reject')?'block':c.group)}<button class="btn ib" aria-label="加规则" data-qr=""${esc(c.host)}">⋯</button></div><div class="mono" style="margin:3px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.host)}:${esc(c.port)}</div><div class="mut" style="font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${new Date(c.start).toLocaleTimeString('zh-CN',tz)} · ${esc(devName(c.src))} · ${c.out!='direct'&&c.group!=c.out?'→ '+esc(c.out)+' · ':''}${esc(c.net)} · ↓${fmtB(c.down)} ↑${fmtB(c.up)}${c.kern?'':' · '+esc(c.rule)}</div></div>`).join('')||'<p class="mut" style="padding:16px 0;text-align:center">没有匹配的连接</p>'}
function histBody(){const h=S.hist;if(!h)return'<div class="card mut">读取中…</div>';const kind=r=>r.r.includes('reject')?'block':r.o=='direct'?'direct':r.g;
 return `<div class="mut" style="font-size:12px;margin:0 4px 8px">共 ${h.total} 条${h.total>h.list.length?'，显示最新 '+h.list.length+' 条':''} · 最早 ${h.oldest?tfmt(h.oldest):'—'} · 占用 ${fmtB(h.bytes)} / ${fmtB(h.cap_bytes)}</div><div class="card">${h.list.map(r=>`<div class="lr" data-k="${r.t}|${esc(r.s)}|${esc(r.h)}|${esc(r.p)}${r.k?'|k':''}"><div class="row"><b style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(appOf(r.h))}</b>${r.k?KTAG:outTag(kind(r))}<button class="btn ib" aria-label="加规则" data-qr=""${esc(r.h)}">⋯</button></div><div class="mono" style="margin:3px 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.h)}:${esc(r.p)}</div><div class="mut" style="font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${tfmt(r.t)} · ${esc(devName(r.s))} · ${r.o!='direct'&&r.g!=r.o?'→ '+esc(r.o)+' · ':''}${esc(r.n)} · ${r.k?`↓${fmtB(r.d||0)} ↑${fmtB(r.u||0)}${r.e?' · 已结束':''}`:esc(r.r)}</div></div>`).join('')||'<p class="mut" style="padding:16px 0;text-align:center">没有记录</p>'}</div>`}
async function loadHist(){try{const q=new URLSearchParams({hours:24,ip:S.hip||'',q:S.hq||''});S.hist=await A('/history?'+q);upLog(true)}catch(e){toast('✗ '+e.message,1)}}
function devName(ip){const d=S.cx?.devices.find(x=>x.ip==ip);return d?dname(d):ip}
function filt(list){const q=S.q.toLowerCase();return q?list.filter(c=>(c.host+' '+appOf(c.host)+' '+c.out+' '+c.group+' '+devName(c.src)).toLowerCase().includes(q)):list}
function appView(list){const m={};list.forEach(c=>{const a=appOf(c.host),o=c.out=='direct'?'直连':c.group||c.out;(m[a]=m[a]||{t:0,o:{}});m[a].t++;m[a].o[o]=(m[a].o[o]||0)+1});const cols=['#22c55e','#2dd4bf','#a78bfa','#60a5fa','#f59e0b'];
 return Object.entries(m).sort((a,b)=>b[1].t-a[1].t).map(([a,v])=>{const es=Object.entries(v.o);return `<div class="mem" style="display:block"><div class="row"><b style="flex:1">${esc(a)}</b><span class="mut" style="font-size:12px">${v.t} 连接</span></div><div class="bar">${es.map(([o,c],i)=>`<i style="width:${c/v.t*100}%;background:${o=='直连'?cols[0]:cols[1+i%4]}"></i>`).join('')}</div><div class="mut" style="font-size:11.5px;margin-top:4px">${es.map(([o,c])=>`${esc(o)} ${Math.round(c/v.t*100)}%`).join(' · ')}</div></div>`}).join('')||'<p class="mut">暂无连接</p>'}
function lgBody(){const cx=S.cx;if(!cx)return'<div class="card mut">读取中…</div>';if(S.lgv=='ev')return`<div class="card">${evList(60)}</div>`;if(S.lgv=='hist')return histBody();
 if(S.lgv=='all'){const l=filt(cx.conns);return`<div class="card" id="logbox">${S.appView?appView(l):connRows(l)}</div>`}return devList()}
V.lg=()=>`<h2>日志</h2><div class="flt">${[['dev','按设备'],['all','全部连接'],['hist','24 小时'],['ev','事件']].map(([k,n])=>`<button class="chip ${S.lgv==k?'on':''}" data-lgv="${k}">${n}</button>`).join('')}${S.lgv=='all'?`<button class="chip ${S.appView?'on':''}" data-av>应用视图</button><input id="fq" placeholder="搜索域名/应用/节点" value="${esc(S.q)}"><button class="chip" data-a="pause">${S.paused?'▶ 继续':'⏸ 暂停'}</button>`:''}${S.lgv=='hist'?`<select id="hd" style="width:auto"><option value="">全部设备</option>${(S.cx?.devices||[]).filter(d=>d.ip).map(d=>`<option value="${esc(d.ip)}" ${S.hip==d.ip?'selected':''}>${esc(dname(d))}</option>`).join('')}</select><input id="hq" placeholder="搜索域名/节点" value="${esc(S.hq||'')}"><button class="chip" data-a="hload">刷新</button>`:''}</div><div id="lgb">${lgBody()}</div><p class="mut" style="font-size:11.5px;margin:0 4px">${S.lgv=='hist'?'24 小时历史：每 3 秒记录一次新连接（只记连接建立，3 秒内开关完的短连接可能漏记），存在路由器内存 /tmp，最多约 2 MB，路由器重启后清空。':`这里是当前活动连接（共 ${S.cx?.total??'…'} 条，最多显示 300；标「内核直连」的是不经代理内核的国内连接，每 5 秒采样，几秒内结束的短连接可能看不到）。`}应用按域名推断，点 ⋯ 一键加规则。往下翻时自动暂停刷新。</p>`;
function devList(){const ds=S.cx.devices.filter(d=>d.online&&d.conns);return ds.map(d=>{const t=d.direct+d.proxy+d.blocked||1,dp=Math.round(d.direct/t*100),bp=Math.round(d.blocked/t*100);return `<div class="card dl" data-k="${esc(d.ip)}" data-dl="${esc(d.ip)}"><div class="dev"><div class="ico">${devIcon(d)}</div><div style="flex:1;min-width:0"><div class="row"><b style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(dname(d))}</b><span class="mut">›</span></div><div class="mut" style="font-size:12px">${d.conns} 个连接 · ↓ ${fmtR(d.down_rate)} · ↑ ${fmtR(d.up_rate)}</div><div class="bar"><i style="width:${dp}%;background:var(--ok)"></i><i style="width:${100-dp-bp}%;background:var(--acc)"></i><i style="width:${bp}%;background:var(--bad)"></i></div><div class="mut" style="font-size:11.5px;margin-top:4px"><span style="color:var(--ok)">直连 ${dp}%</span> · <span style="color:var(--acc)">代理 ${100-dp-bp}%</span>${bp?` · <span style="color:var(--bad)">拦截 ${bp}%</span>`:''}</div></div></div></div>`}).join('')||'<div class="card mut">当前没有活动连接</div>'}
function drawerList(){const ip=S.drawer;if(!ip||!S.cx)return'';const q=(S.dq||'').toLowerCase(),fo=S.dout||'全部',m={};
 S.cx.conns.filter(c=>c.src==ip).forEach(c=>{const k=c.host+(c.kern?'#k':'');if(!m[k])m[k]={...c,n:0,app:appOf(c.host),kb:0};m[k].n++;if(c.kern)m[k].kb+=c.down+c.up});
 const kind=x=>x.rule.includes('reject')?'拦截':x.out=='direct'?'直连':'代理';
 let a=Object.values(m).filter(x=>(!q||(x.host+x.app).toLowerCase().includes(q))&&(fo=='全部'||kind(x)==fo));const dir=a.filter(x=>kind(x)=='直连').length;
 return `<div class="mut" style="font-size:12px;margin:2px 2px 6px">${a.length} 个域名 · 直连 ${dir} · 代理 ${a.length-dir}</div>`+(a.map(x=>`<div class="lr" data-k="${esc(x.host)}"><div class="row"><div style="flex:1;min-width:0"><div class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.host)}</div><div class="mut" style="font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.app)} · ${x.n} 连接${kind(x)=='代理'&&x.group!=x.out?' · → '+esc(x.out):''}${x.kern?' · '+fmtB(x.kb):' · '+esc(x.rule)}</div></div>${x.kern?KTAG:outTag(kind(x)=='直连'?'direct':kind(x)=='拦截'?'block':x.group)}<button class="btn ib" aria-label="加规则" data-qr=""${esc(x.host)}">⋯</button></div></div>`).join('')||'<p class="mut" style="padding:20px 0;text-align:center">没有匹配的连接</p>')}
function openDrawer(ip){const d=S.cx.devices.find(x=>x.ip==ip);S.drawer=ip;S.dq='';S.dout='全部';const m=sheet(`<div class="grab"></div><div class="row" style="margin-bottom:10px"><div class="ico">${devIcon(d)}</div><div style="flex:1;min-width:0"><b>${esc(dname(d))}</b><div class="mono mut">${esc(ip)} · ${esc(dmode(d))}</div></div><div class="spd" id="dspd"></div></div>
<input id="dq" placeholder="🔍 搜索域名或应用，如 x.com / 抖音" style="margin-bottom:8px"><div class="flt">${['全部','直连','代理','拦截'].map(o=>`<button class="chip ${o=='全部'?'on':''}" data-do="${o}">${o}</button>`).join('')}</div><div id="dlist">${drawerList()}</div>`,m=>{m.querySelector('.sheet').classList.add('tall');
 m.querySelector('#dq').oninput=e=>{S.dq=e.target.value;upDrawer()};
 m.querySelectorAll('[data-do]').forEach(b=>b.onclick=()=>{S.dout=b.dataset.do;m.querySelectorAll('[data-do]').forEach(x=>x.classList.toggle('on',x==b));upDrawer()});bind2()});
 m.onclick=e=>{if(e.target===m){S.drawer=null;m.remove()}};upDrawer()}
function upDrawer(){const e=$('#dlist');if(e){patch(e,drawerList());bind2()}const sp=$('#dspd'),d=S.cx?.devices.find(x=>x.ip==S.drawer);if(sp&&d)sp.innerHTML=`↓ ${fmtR(d.down_rate)}<br>↑ ${fmtR(d.up_rate)}`}
V.st=()=>`<h2>规则与设置</h2><div class="flt"><button class="chip ${S.sub!='set'?'on':''}" data-sub="rule">规则</button><button class="chip ${S.sub=='set'?'on':''}" data-sub="set">设置</button></div>`+(S.sub=='set'?setView():ruleView());
function rv(x){const ks=Object.keys(MT).filter(k=>x[k]?.length);return {tags:ks.map(k=>`<span class="tag">${MT[k]}</span>`).join(' '),vals:ks.flatMap(k=>x[k].map(v=>[k,String(v)]))}}
function ruleView(){const rules=S.rules||S.st.rules,dirty=!!S.rules,rs=S.st.rulesets;S.rx=S.rx||{};return `<button class="btn pri big" data-a="addrule">＋ 添加规则</button><div class="card"><h3>自定义规则 <span class="mut" style="font-size:12px;font-weight:400">${rules.length} 条 · 从上到下匹配</span></h3>
${dirty?`<div class="banner"><span>规则已修改，保存后内核热重载（现有连接会重连）</span><button class="btn pri" data-a="saverules">保存并应用</button><button class="btn" data-a="undorules">撤销</button></div>`:''}
<div class="dlist" data-rules="1">${rules.map((x,i)=>{const v=rv(x),open=S.rx[i],sh=open?v.vals:v.vals.slice(0,8),lk=!!x.pin;return `<div class="rule rc ${lk?'lock':'drow'} ${x.disabled?'off-c':''}" data-n="${i}" data-k="r${i}">${lk?'<div class="lk" title="固定规则：永远最先匹配，全局模式下也生效">🔒</div>':'<div class="hdl" title="长按拖动调整优先级">⋮⋮</div>'}<div class="body"><div class="row" style="gap:6px;flex-wrap:wrap"><b style="font-size:14px">${esc(relab(x.name||'未命名规则'))}</b><span style="white-space:nowrap">→ ${outTag(x.outbound)}</span>${x.pin?'<span class="tag" title="全局代理模式下也生效">📌 固定</span>':''}</div><div class="mut" style="font-size:11.5px;margin:3px 0 5px">${v.tags} · ${v.vals.length} 项${(()=>{const ap=[...new Set(v.vals.map(([k,t])=>k=='domain_keyword'?null:appOf(t)).filter(Boolean))];return ap.length>1?' · 涵盖 '+esc(ap.slice(0,10).join('、'))+(ap.length>10?' 等':''):''})()}</div><div class="vals">${sh.map(([k,t])=>`<span class="vchip${k=='domain_keyword'?' kw':k=='ip_cidr'?' ip':''}">${esc(t)}</span>`).join('')}${v.vals.length>8?`<button class="vchip more" data-rx="${i}">${open?'收起':'展开全部 '+v.vals.length+' 项'}</button>`:''}</div></div><div class="trail col"><div class="sw sm ${x.disabled?'':'on'}" data-ron="${i}"></div><button class="btn dan ib" aria-label="删除" data-rdel="${i}">✕</button></div></div>`}).join('')||'<p class="mut">还没有自定义规则，点上面「添加规则」</p>'}</div><p class="mut" style="font-size:11.5px;margin-top:6px">长按规则（或按住 ⋮⋮）拖动调整优先级，松手立即保存。🔒 固定规则永远排在最上面。</p>
<div class="mut" style="font-size:11px;margin-top:10px">颜色：<span class="vchip">域名（含子域名）</span><span class="vchip kw">关键词</span><span class="vchip ip">IP 段</span></div>
<h3 style="margin-top:16px">内置规则（固定顺序）</h3>${[['私有地址 / 局域网 / 远程运维链路','direct'],['访客设备（开启「仅直连」时）','direct'],['.cn 域名 + geosite:cn','direct'],['geoip:cn','direct'],['未匹配：先问国内 DNS，国内 IP 直连，其余走主线路',S.st.main_group]].map(x=>`<div class="rule sys"><div style="flex:1">${x[0]}</div>${outTag(x[1])}</div>`).join('')}</div>
${rsCard()}`}
function optCard(){const o=S.st.optimize;if(!o)return'';const q=o.sqm,nf=(k,l)=>`<div class="fld" style="margin:0"><label>${l}</label><input type="number" inputmode="numeric" min="1" max="10000" id="q_${k}" value="${q[k]}"></div>`;
 return `<div class="card"><h3>国内直连优化</h3>
<div class="set"><div>国内 IP 内核直连<div class="mut" style="font-size:11.5px">规则模式下国内网站不进代理内核，直接由路由器转发：更快、更省 CPU（共 ${o.cn4_count} 个网段；全局代理时自动关闭）</div></div><div class="sw sm ${o.kernel_cn_bypass?'on':''}" id="o_by"></div></div>
<div class="set"><div>记录内核直连<div class="mut" style="font-size:11.5px">把绕过代理内核的国内连接也显示在日志和设备里（标「内核直连」，每 5 秒读一次连接表；${o.kern?`当前 ${o.kern.active} 条活动、${o.kern.ended} 条最近结束`:'未运行'}${o.kern&&o.kern.skipped?'，连接表过大已暂停':''}）</div></div><div class="sw sm ${o.kernel_conn_log?'on':''}" id="o_kl"></div></div>
<div class="set"><div>直连连接超时<div class="mut" style="font-size:11.5px">线路偶尔丢包时多等一会儿再放弃，避免网页「转圈 5 秒后失败」</div></div><div class="trail"><input type="number" inputmode="numeric" min="1" max="120" id="o_to" value="${o.direct_connect_timeout_s}" style="width:72px;text-align:right"><span class="mut">秒</span></div></div>
<div class="set"><div>智能限速（cake-autorate）<div class="mut" style="font-size:11.5px">把排队放在本路由器上并按延迟自动调速：下载跑满时打游戏、开网页不卡${o.sqm_available?'':'（未安装）'}</div></div><div class="sw sm ${q.enabled?'on':''}" id="o_sq"></div></div>
<div id="o_rates" style="${q.enabled?'':'display:none'}"><p class="mut" style="font-size:11.5px;margin:4px 0 8px">单位 Mbit/s。「最低」是最差时的保底，「常用」是平时的速度，「最高」不超过宽带实测。</p>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px">${nf('dl_min','下行 最低')}${nf('dl_base','下行 常用')}${nf('dl_max','下行 最高')}${nf('ul_min','上行 最低')}${nf('ul_base','上行 常用')}${nf('ul_max','上行 最高')}</div>
<p class="mut" id="o_ms" style="font-size:11.5px"></p></div>
<div class="btns"><button class="btn pri" id="o_save">保存</button><button class="btn" id="o_meas">自动测速并填入建议值</button></div></div>`}
function setView(){const st=S.st,w=st.watchdog,b=st.basic,ro=v=>`<span class="rov">${esc(v)}</span>`;return rawBanner()+optCard()+`${guestCard()}<div class="cols"><div class="card"><h3>基础 <span class="tag">只读</span></h3><div class="set">局域网接口${ro(b.lan_iface)}</div><div class="set">透明代理端口${ro(b.tproxy_port)}</div><div class="set">测试代理${ro(b.mixed||'关闭')}</div><div class="set">IPv6 代理${ro('暂不支持')}</div></div>
<div class="card"><h3>DNS <span class="tag">只读</span></h3><div class="set">国内上游${ro(b.dns_cn.join(', '))}</div><div class="set">国外上游${ro(b.dns_foreign.join(', '))}</div><p class="mut" style="font-size:11.5px">经 dnsmasq（127.0.0.1#1053）接入；AAAA 回空。</p></div>
<div class="card"><h3>自动切换（看门狗）<span class="tag">只读</span></h3><div class="set">延迟检测${ro('每 '+w.interval_s+' 秒')}</div><div class="set">吞吐检测${ro('每 '+Math.round(w.heavy_interval_s/60)+' 分钟')}</div><div class="set">切走 / 切回${ro('连续失败 '+w.fail+' 次 / 连续正常 '+w.recover+' 次')}</div><div class="set">吞吐下限${ro('↓'+w.min_down_kbps+' ↑'+w.min_up_kbps+' KB/s')}</div><div class="set">手动选择后暂停${ro(w.hold_minutes+' 分钟')}</div></div>
<div class="card"><h3>面板与备份</h3><div class="set">面板登录<span class="mut" style="font-size:12px;text-align:right">与 LuCI 相同（root 密码 / LuCI 会话）<br><a href="//${location.hostname}/cgi-bin/luci/admin/system/admin" target="_top" style="color:var(--ac)">在 LuCI 修改 root 密码</a></span></div><div class="set">外观<div class="seg"><button data-th="auto" class="${S.theme=='auto'?'on':''}">自动</button><button data-th="light" class="${S.theme=='light'?'on':''}">浅色</button><button data-th="dark" class="${S.theme=='dark'?'on':''}">深色</button></div></div><div class="set">强调色<div class="seg"><button data-ac="blue" class="${S.accent!='teal'?'on':''}">蓝色</button><button data-ac="teal" class="${S.accent=='teal'?'on':''}">青色</button></div></div><div class="set">配置<div class="trail"><a class="btn" href="/api/export" download>导出 JSON</a><button class="btn" data-a="import">导入…</button></div></div><div class="set">登录<button class="btn" data-a="logout">退出登录</button></div></div>
<div class="card"><h3>系统</h3><div class="kv"><div><span>版本</span>${esc(st.version)}</div><div><span>内核内存</span>${fmtB(st.rss.core)}</div><div><span>面板+看门狗</span>${fmtB(st.rss.daemon)}</div><div><span>内核状态</span>${st.core_up?'运行中':'未响应'}</div><div><span>内核重启</span>${st.core_restarts} 次</div><div><span>自保状态</span>${st.fallback?'直连中':'正常'}</div></div></div></div>
<div class="card"><h3>高级模式</h3><div class="set"><div>原始配置<div class="mut sm2">查看 / 编辑 TinyLane JSON（含生成的 sing-box 配置只读视图）。保存前完整校验，应用后 90 秒内不确认自动回滚。</div></div><button class="btn" data-a="raw">打开</button></div></div>`}
function render(){if(!S.st||S.dragging)return;const v=$('#view');if(v.dataset.tab!==S.tab||!v.firstChild){v.innerHTML=V[S.tab]();v.dataset.tab=S.tab}else patch(v,V[S.tab]());head();bind();initDrag()}
function bind(){
 const on=(sel,fn)=>document.querySelectorAll('#view '+sel+',.sheet '+sel).forEach(e=>e.onclick=ev=>{ev.stopPropagation();fn(e,ev)});
 const st=S.st;
 on('[data-a=power]',e=>act('/enabled',{on:!st.enabled},st.enabled?'代理已停用，全部直连':'代理已启用',e));
 on('[data-mode]',e=>act('/mode',{mode:e.dataset.mode},'已切换为 '+MODES[e.dataset.mode]));
 on('[data-sel]',e=>{if(S.justDragged)return;const[gi,...n]=e.dataset.sel.split(','),G=st.groups[+gi],node=n.join(',');if(G.type=='failover'||node==G.now)return;act('/select',{group:G.name,node},gl(G)+' → '+node)});
 on('[data-auto]',e=>act('/auto',{group:st.groups[+e.dataset.auto].name},'已恢复自动切换',e));
 on('[data-ns]',e=>{const k=e.dataset.ns;LS.tl_ndsec=LS.tl_ndsec==k?'':k;render()});
 on('[data-nsd]',e=>act('/delay',{names:ndSecNodes(e.dataset.nsd).map(d=>d.name).slice(0,64)},'延迟测试完成',e));
 on('[data-test]',e=>act('/delay',{names:st.groups[+e.dataset.test].eff.filter(n=>nodeBy(n).name).slice(0,64)},'延迟测试完成',e));
 on('[data-egt]',e=>act('/node/egress',{names:[e.dataset.egt]},'正在重测出口'));
 on('[data-a=egall]',e=>act('/node/egress',{names:[]},'已开始重测全部出口（一次一个）',e));
 on('[data-a=addgroup]',()=>editGroup(-1));
 on('[data-a=ixdef]',()=>{const x=$('#ix');if(x){S.impEdit=1;x.value=st.import.default_exclude}});
 on('[data-a=impset]',e=>{S.impEdit=0;act('/import/settings',{import_exclude:$('#ix').value,egress_probe:$('#iep').classList.contains('on')},'导入设置已保存',e)});
 {const ie=$('#iep'),ix=$('#ix');if(ie)ie.onclick=()=>{S.impEdit=1;ie.classList.toggle('on')};if(ix)ix.oninput=()=>S.impEdit=1}
 on('[data-tn]',async e=>{const r=await act('/speed',{node:e.dataset.tn},null,e);if(r)toast(r.error?'✗ '+r.error:`${e.dataset.tn} ↓${kb(r.down_kbps)} ↑${kb(r.up_kbps)}`,!!r.error)});
 on('[data-dn]',e=>confirmSheet('删除手动节点 '+e.dataset.dn+'？','会同时从各组移除。',()=>act('/node/delete',{name:e.dataset.dn},'已删除')));
 on('[data-mtu]',e=>{const d=nodeBy(e.dataset.mtu);act('/node/mtu',{name:d.name,on:!d.mtu},'已保存（内核热重载）')});
 on('[data-eg]',e=>editGroup(+e.dataset.eg));
 on('[data-a=addnode]',addNode);
 on('[data-upd]',e=>subUpdate(+e.dataset.upd,e));
 on('[data-es]',e=>editSub(+e.dataset.es));
 on('[data-ds]',e=>{const i=+e.dataset.ds,s=st.subs[i],n=st.nodes.filter(x=>x.source=='sub:'+s.name||(i==0&&x.source=='clash')).length;confirmSheet('删除订阅「'+s.name+'」？',`会同时删除它导入的 ${n} 个节点，并从各组移除（规则或设备直接用到这些节点时会拒绝删除）。`,()=>act('/sub/delete',{index:i},'订阅和它的节点已删除'))});
 on('[data-ban]',e=>confirmSheet('拉黑这台设备？','路由器会丢弃它的所有包（含 DHCP/DNS），可随时解除。',()=>act('/device/block',{mac:e.dataset.ban,block:true},'已拉黑')));
 on('[data-unban]',e=>act('/device/block',{mac:e.dataset.unban,block:false},'已解除拉黑').then(loadConns));
 on('[data-ren]',e=>{const d=S.cx.devices.find(x=>x.mac==e.dataset.ren);sheet(`<h3>改名 / 类型</h3><div class="fld"><label>名称</label><input id="rn" value="${esc(d?.name||d?.hostname||'')}" maxlength="64"></div><div class="fld"><label>类型</label><select id="rt"><option value="">自动识别</option>${Object.entries(DT).map(([k,v])=>`<option value="${k}" ${d?.type==k?'selected':''}>${v[0]} ${v[1]}</option>`).join('')}</select></div><div class="btns"><button class="btn pri" id="ok">保存</button></div>`,m=>m.querySelector('#ok').onclick=()=>{act('/device/name',{mac:e.dataset.ren,name:m.querySelector('#rn').value,type:m.querySelector('#rt').value},'已保存').then(loadConns);m.remove()})});
 on('[data-dm]',e=>devMode(S.cx.devices.find(x=>x.ip==e.dataset.dm)));
 on('[data-gt]',e=>{const d=S.cx.devices.find(x=>x.mac==e.dataset.gt);act('/device/guest',{mac:d.mac,guest:!d.guest},dname(d)+(d.guest?' 已标记为家人':' 已标记为访客')).then(loadConns)});
 on('.dis',()=>toast('即将推出'));
 on('[data-kick]',e=>kickSheet(S.cx.devices.find(x=>x.mac==e.dataset.kick)));
 on('[data-rx]',e=>{S.rx[+e.dataset.rx]=!S.rx[+e.dataset.rx];render()});
 on('[data-a=addrule]',addRule);
 on('[data-a=hload]',loadHist);
 on('[data-lgv]',e=>{S.lgv=e.dataset.lgv;render();if(S.lgv=='hist')loadHist()});
 on('[data-dl]',e=>openDrawer(e.dataset.dl));
 on('[data-vc]',e=>viewConns(e.dataset.vc,e.dataset.vo=='1'));
 on('[data-av]',()=>{S.appView=!S.appView;render()});
 on('[data-a=pause]',()=>{S.paused=!S.paused;render()});
 on('[data-qr]',e=>quickRule(e.dataset.qr));
 on('[data-sub]',e=>{S.sub=e.dataset.sub;render()});
 const R=()=>S.rules||(S.rules=JSON.parse(JSON.stringify(st.rules)));
 on('[data-ron]',e=>{const x=R()[+e.dataset.ron];x.disabled=!x.disabled;render()});
 on('[data-rdel]',e=>{R().splice(+e.dataset.rdel,1);render()});
 on('[data-a=saverules]',e=>act('/rules',{rules:S.rules},'规则已保存并生效',e).then(r=>{if(r){S.rules=null;render()}}));
 on('[data-a=undorules]',()=>{S.rules=null;render()});
 on('[data-a=newrule]',newRule);
 on('[data-a=rsupd]',e=>act('/rulesets/update',{},'规则集已更新',e));
 const ob=$('#o_by'),oq=$('#o_sq');if(ob){const card=ob.closest('.card');card.oninput=()=>S.optEdit=1;ob.onclick=()=>{S.optEdit=1;ob.classList.toggle('on')};const okl=$('#o_kl');if(okl)okl.onclick=()=>{S.optEdit=1;okl.classList.toggle('on')};oq.onclick=()=>{S.optEdit=1;oq.classList.toggle('on');$('#o_rates').style.display=oq.classList.contains('on')?'':'none'};
  const K=['dl_min','dl_base','dl_max','ul_min','ul_base','ul_max'];
  $('#o_save').onclick=e=>{const q={enabled:oq.classList.contains('on'),iface:st.optimize.sqm.iface};K.forEach(k=>q[k]=+$('#q_'+k).value);S.optEdit=0;act('/optimize',{sqm:q,kernel_cn_bypass:ob.classList.contains('on'),direct_connect_timeout_s:+$('#o_to').value,...($('#o_kl')?{kernel_conn_log:$('#o_kl').classList.contains('on')}:{})},'已保存',e.target)};
  $('#o_meas').onclick=async e=>{S.optEdit=1;$('#o_rates').style.display='';$('#o_ms').textContent='测速中（约 30 秒，期间网速会被占满）…';const b=e.target;b.disabled=true;let r=null,em='';try{r=await A('/optimize/measure',{})}catch(x){em=x.message;toast('✗ '+em,1)}b.disabled=false;if(r&&r.suggest){K.forEach(k=>$('#q_'+k).value=r.suggest[k]);$('#o_ms').textContent=`实测 ↓${r.down_mbit} ↑${r.up_mbit} Mbit/s，已填入建议值（常用 = 实测 85%），确认后点「保存」。`}else $('#o_ms').textContent=em&&em.includes('内存')?'✗ '+em:'测速失败，请稍后再试'}}
 on('[data-gd]',()=>act('/guest',{direct_only:!st.guest.direct_only},st.guest.direct_only?'已取消访客直连限制':'访客已限制为仅直连'));
 on('[data-th]',e=>{theme(e.dataset.th);render()});
 on('[data-ac]',e=>{accent(e.dataset.ac);render()});
 on('[data-a=pw]',pwSheet);
 on('[data-a=logout]',()=>A('/logout',{}).finally(()=>location.reload()));
 const q=$('#fq');if(q)q.oninput=()=>{S.q=q.value;upLog(true)};
 const hd=$('#hd');if(hd)hd.onchange=()=>{S.hip=hd.value;loadHist()};const hq=$('#hq');if(hq)hq.oninput=()=>{S.hq=hq.value;clearTimeout(S.hqt);S.hqt=setTimeout(loadHist,400)};
 bindM6();
}
function bind2(){document.querySelectorAll('[data-qr]').forEach(e=>e.onclick=ev=>{ev.stopPropagation();quickRule(e.dataset.qr)})}
function confirmSheet(t,msg,fn){sheet(`<h3>${esc(t)}</h3><p class="mut">${esc(msg)}</p><div class="btns"><button class="btn pri dan" id="cb">确定</button><button class="btn" id="cn">取消</button></div>`,m=>{m.querySelector('#cb').onclick=()=>{m.remove();fn()};m.querySelector('#cn').onclick=()=>m.remove()})}
function outOpts(sel){const st=S.st;return `<option value="direct">直连</option><option value="block">拒绝</option>${st.groups.map(g=>`<option value="${esc(g.name)}">组：${esc(gl(g))}</option>`).join('')}${st.nodes.map(n=>`<option value="${esc(n.name)}">节点：${esc(n.name)}</option>`).join('')}`.replace(`value="${esc(sel)}"`,`value="${esc(sel)}" selected`)}
function editGroup(gi){const nw=gi<0,g=nw?{name:'',type:'failover',members:[],filter:'',exclude:'',strict:false}:S.st.groups[gi],w=S.st.watchdog,mem=g.members,all=[...mem.filter(n=>nodeBy(n).name),...S.st.nodes.map(n=>n.name).filter(n=>!mem.includes(n))];
 sheet(`<h3>${nw?'新建组':'编辑组 · '+esc(gl(g))}</h3>${nw?'<div class="fld"><label>名称</label><input id="gn" maxlength="40" placeholder="如 香港 / AI"></div>':''}<div class="fld"><label>类型</label><select id="gt"><option value="failover" ${g.type=='failover'?'selected':''}>故障切换（看门狗按顺序自动切换）</option><option value="select" ${g.type=='select'?'selected':''}>手动</option></select></div>
<div class="set"><div>断网保护<div class="mut sm2">组里没有可用节点时直接断网，不回落直连</div></div><div class="sw ${g.strict?'on':''}" id="gs"></div></div>
<div class="fld"><label>只用名称含（自动加入，| 分隔，或 /正则/）</label><input id="gf" value="${esc(g.filter||'')}" placeholder="如 香港|HK"></div>
<div class="fld"><label>排除名称含（手选的也排除）</label><input id="gx" value="${esc(g.exclude||'')}" placeholder="如 高倍|3x"></div>
<div class="fld"><label>手选成员（勾选 = 加入；顺序在节点页按住拖动调整）<span class="mut" id="gp"></span></label>${all.map(n=>`<label class="opt"><input type="checkbox" value="${esc(n)}" ${mem.includes(n)?'checked':''}>${esc(n)} <span class="tag gtg" style="display:none"></span></label>`).join('')}</div>
<p class="mut" style="font-size:11.5px;margin-bottom:8px">订阅更新后成员自动重算；删除节点会自动从组里移除。探测只针对组内成员：每 ${w.interval_s} 秒延迟、每 ${Math.round(w.heavy_interval_s/60)} 分钟吞吐；连续失败 ${w.fail} 次切走，高优先级连续正常 ${w.recover} 次切回。</p><div class="btns"><button class="btn pri" id="ok">${nw?'创建':'保存'}</button>${nw?'':'<button class="btn dan" id="gd">删除组</button>'}</div>`,
 m=>{const q=s=>m.querySelector(s),sw=q('#gs');sw.onclick=()=>sw.classList.toggle('on');
  const upd=()=>{const fi=nmRe(q('#gf').value),ex=nmRe(q('#gx').value);let n=0;m.querySelectorAll('label.opt').forEach(l=>{const c=l.querySelector('input'),t=l.querySelector('.gtg'),v=c.value,x=ex&&ex(v),a=!c.checked&&fi&&fi(v);t.style.display=x||a?'':'none';t.textContent=x?'已排除':'自动';t.className='tag gtg'+(x?' t-blk':'');if(!x&&(c.checked||a))n++});q('#gp').textContent=` · 实际成员 ${n} 个`};
  q('#gf').oninput=q('#gx').oninput=upd;m.querySelectorAll('label.opt input').forEach(c=>c.onchange=upd);upd();
  if(q('#gd'))q('#gd').onclick=()=>confirmSheet('删除组「'+gl(g)+'」？','引用它的规则、设备、规则集需要先改到其他组，否则会拒绝删除。',()=>act('/group/delete',{name:g.name},'组已删除').then(r=>{if(r){m.remove();render()}}));
  q('#ok').onclick=e=>{const members=[...m.querySelectorAll('input:checked')].map(x=>x.value),filter=q('#gf').value.trim();if(!members.length&&!filter){toast('请勾选成员，或填写「只用名称含」',1);return}
   const b={type:q('#gt').value,members,filter,exclude:q('#gx').value.trim(),strict:sw.classList.contains('on')};if(nw)b.name=q('#gn').value.trim();else b.name=g.name;
   act(nw?'/group/add':'/group',b,nw?'组已创建':'已保存',e.target).then(r=>{if(!r)return;m.remove();render()})}})}
function addNode(){sheet(`<h3>手动添加节点</h3><div class="fld"><label>分享链接</label><textarea rows="3" class="mono" id="lk" placeholder="hysteria2://… vless://… anytls://… trojan://… ss://… vmess://…"></textarea></div><div class="fld"><label>名称（可选）</label><input id="nn"></div><p class="mut" style="font-size:11.5px;margin-bottom:8px">支持 hy2 / VLESS / VMess / Trojan / SS / TUIC / AnyTLS 链接。添加后会经这个节点自动测一次出口 IP。</p><div class="btns"><button class="btn pri" id="ok">添加</button></div>`,
 m=>m.querySelector('#ok').onclick=e=>act('/node/add',{link:m.querySelector('#lk').value,name:m.querySelector('#nn').value},'已添加，正在检测出口',e.target).then(r=>{if(r)m.remove()}))}
function editSub(i){const s=i>=0?S.st.subs[i]:{name:'主订阅',url:'',exit:'',auto:'weekly'};sheet(`<h3>${i>=0?'编辑':'添加'}订阅</h3><div class="fld"><label>名称</label><input id="sn" value="${esc(s.name)}" ${i>=0?'disabled':''}></div><div class="fld"><label>订阅 URL</label><input class="mono" id="su" placeholder="https://" value="${esc(s.url)}"></div><div class="fld"><label>自动更新</label><select id="sa">${Object.entries(AUTO).map(([k,v])=>`<option value="${k}" ${s.auto==k?'selected':''}>${v}</option>`).join('')}</select></div><div class="btns"><button class="btn pri" id="ok">保存</button></div>`,
 m=>m.querySelector('#ok').onclick=e=>act('/sub/save',{index:i,name:m.querySelector('#sn').value,url:m.querySelector('#su').value,auto:m.querySelector('#sa').value},'已保存',e.target).then(r=>{if(r)m.remove()}))}
async function subUpdate(i,el){const d=await act('/sub/preview',{index:i},null,el);if(!d)return;const L=(a,c,p)=>a.map(x=>`<div class="${c}">${p} ${esc(x)}</div>`).join('');
 sheet(`<h3>订阅更新差异</h3><p class="mut" style="margin-bottom:8px">${esc(d.format)} · 共 ${d.total} 个 · +${d.added.length} 新增 · −${d.removed.length} 移除 · ${d.changed.length} 参数变化 · 手动节点保留</p><div class="diff">${L(d.added,'plus','+')}${L(d.removed,'chg','−')}${L(d.changed,'chg','~')}${d.kept.length?`<div class="mut">= 保留：${esc(d.kept.join('、'))}</div>`:''}${d.pruned.length?`<div class="chg">将从组中移除：${esc(d.pruned.join('、'))}</div>`:''}${d.filtered?.length?`<div class="mut">已过滤 ${d.filtered.length} 个信息条目：${esc(d.filtered.join('、'))}</div>`:''}${(d.warns||[]).map(w=>`<div class="mut">⚠ ${esc(w)}</div>`).join('')}${!d.added.length&&!d.removed.length&&!d.changed.length?'<div class="mut">节点没有变化</div>':''}</div><div class="btns"><button class="btn pri" id="ok">应用</button><button class="btn" id="cn">取消</button></div>`,
 m=>{m.querySelector('#cn').onclick=()=>m.remove();m.querySelector('#ok').onclick=e=>act('/sub/apply',{index:i},'订阅已应用',e.target).then(r=>{if(r)m.remove()})})}
function devMode(d){if(d.guest&&S.st.guest.direct_only){sheet(`<h3>${esc(dname(d))}</h3><p class="mut">这是访客设备，已开启「访客只允许直连」，不能指定代理。可在 设置 → 访客 里关闭，或把它设为家人。</p><div class="btns"><button class="btn pri" onclick="this.closest('.mask').remove()">知道了</button></div>`);return}
 const cur=d.mode=='global'?'global:'+(d.group||''):d.mode,opts=[['follow','跟随全局'],['global:','全局代理（'+lab(S.st.main_group)+'）'],['direct','全局直连'],...S.st.groups.filter(g=>g.name!=S.st.main_group).map(g=>['global:'+g.name,'全部走组：'+gl(g)])];
 sheet(`<h3>${esc(dname(d))} · 指定模式</h3><p class="mut" style="font-size:12px;margin-bottom:6px">按 IP ${esc(d.ip)} 生效，建议先在路由器设 DHCP 静态租约。</p>${opts.map(([v,n])=>`<label class="opt"><input type="radio" name="dm" value="${esc(v)}" ${cur==v?'checked':''}>${esc(n)}</label>`).join('')}<div class="btns"><button class="btn pri" id="ok">保存</button></div>`,
 m=>m.querySelector('#ok').onclick=e=>{const v=m.querySelector('input:checked')?.value||'follow',[mode,group]=v.split(':');act('/device/mode',{ip:d.ip,name:dname(d),mode,group:group||''},'已保存（内核热重载）',e.target).then(r=>{if(!r)return;m.remove();loadConns()})})}
function quickRule(dom){const st=S.st,opts=[['direct','以后直连'],...st.groups.map(g=>[g.name,'以后走 '+gl(g)]),['block','拒绝']];
 sheet(`<h3>快捷规则</h3><div class="mono" style="margin-bottom:10px;overflow-wrap:anywhere">${esc(dom)}</div>${opts.map(([o,n])=>`<button class="opt" style="width:100%" data-o="${esc(o)}">${esc(n)}</button>`).join('')}<p class="mut" style="font-size:11.5px;margin-top:8px">添加为「完整域名」规则，放在最前面，立即生效。</p>`,
 m=>m.querySelectorAll('[data-o]').forEach(b=>b.onclick=()=>{const isIP=/^[\d.]+$/.test(dom),r={name:'快捷：'+dom,outbound:b.dataset.o};if(isIP)r.ip_cidr=[dom+'/32'];else r.domain=[dom];
  const rules=[r,...(S.rules||st.rules)];m.remove();act('/rules',{rules},'已添加规则：'+dom).then(x=>{if(x)S.rules=null})}))}
function newRule(){sheet(`<h3>新建规则</h3><div class="fld"><label>匹配类型</label><select id="nt">${Object.entries(MT).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></div><div class="fld"><label>值（每行一个）</label><textarea rows="4" class="mono" id="nv" placeholder="example.com"></textarea></div><div class="fld"><label>备注</label><input id="nn"></div><div class="fld"><label>去向</label><select id="na">${outOpts('direct')}</select></div><label class="opt"><input type="checkbox" id="np">全局代理模式下也生效（📌 固定）</label><p class="mut" style="font-size:11.5px">新规则放在最前面；点「保存并应用」后生效。</p><div class="btns"><button class="btn pri" id="ok">添加</button></div>`,
 m=>m.querySelector('#ok').onclick=()=>{const t=m.querySelector('#nt').value,vals=m.querySelector('#nv').value.split(/[\n,，\s]+/).map(s=>s.trim()).filter(Boolean);if(!vals.length){toast('请填写值',1);return}
  const r={name:m.querySelector('#nn').value||undefined,outbound:m.querySelector('#na').value,pin:m.querySelector('#np').checked||undefined};r[t]=t=='port'?vals.map(Number):vals;(S.rules||(S.rules=JSON.parse(JSON.stringify(S.st.rules)))).unshift(r);m.remove();render()})}
function kickSheet(d){if(!d)return;sheet(`<h3>踢下线 · ${esc(dname(d))}</h3><p class="mut" style="font-size:12px;margin-bottom:8px">${esc(d.band||'')} · ${d.signal} dBm。断开 Wi‑Fi，并在下面的时间内拒绝它重新连接（Wi‑Fi 重启后失效）。</p>${[[0,'只断开一次（可马上重连）'],[300,'断开并禁止 5 分钟'],[3600,'断开并禁止 1 小时'],[86400,'断开并禁止 24 小时']].map(([v,n],i)=>`<label class="opt"><input type="radio" name="kb" value="${v}" ${i==1?'checked':''}>${n}</label>`).join('')}<div class="btns"><button class="btn pri dan" id="ok">踢下线</button><button class="btn" id="cn">取消</button></div>`,m=>{m.querySelector('#cn').onclick=()=>m.remove();m.querySelector('#ok').onclick=e=>act('/device/kick',{mac:d.mac,ban_s:+m.querySelector('input:checked').value},dname(d)+' 已踢下线',e.target).then(r=>{if(r!==undefined){m.remove();loadConns()}})})}
const RT=[['domain_suffix','域名','x.com\nfacebook.com','匹配这个域名和它的所有子域名（如 x.com 也匹配 api.x.com）'],['domain_keyword','关键词','twitter','域名里包含这个词就匹配'],['ip_cidr','IP / IP 段','1.2.3.4\n10.0.0.0/8','单个 IP 自动补 /32']];
function addRule(){const st=S.st,tg=[['direct','直连'],...st.groups.map(g=>[g.name,gl(g)]),['block','拒绝']];
 sheet(`<h3>添加规则</h3><div class="fld"><label>匹配方式</label><div class="seg" id="rt">${RT.map(([k,n],i)=>`<button data-k="${k}" class="${i?'':'on'}">${n}</button>`).join('')}</div><div class="mut" id="rth" style="font-size:11.5px;margin-top:5px">${RT[0][3]}</div></div>
<div class="fld"><label>要匹配的内容（每行一个，也可用逗号/空格分隔）</label><textarea rows="4" class="mono" id="rv" placeholder="${RT[0][2]}" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea></div>
<div class="fld"><label>去向</label><div class="tgt" id="ro">${tg.map(([v,n],i)=>`<button class="chip ${i?'':'on'}" data-v="${esc(v)}">${esc(n)}</button>`).join('')}</div></div>
<div class="fld"><label>名称（可选）</label><input id="rn" placeholder="例如：工作网站直连"></div>
<p class="mut" style="font-size:11.5px">保存后立即生效（内核热重载，现有连接会重连一次），放在自定义规则最前面。</p><div class="btns"><button class="btn pri" id="ok">保存并生效</button><button class="btn" id="cn">取消</button></div>`,m=>{
 let typ=RT[0][0],out='direct';const q=s=>m.querySelector(s);
 m.querySelectorAll('#rt button').forEach(b=>b.onclick=()=>{typ=b.dataset.k;m.querySelectorAll('#rt button').forEach(x=>x.classList.toggle('on',x==b));const r=RT.find(x=>x[0]==typ);q('#rth').textContent=r[3];q('#rv').placeholder=r[2]});
 m.querySelectorAll('#ro button').forEach(b=>b.onclick=()=>{out=b.dataset.v;m.querySelectorAll('#ro button').forEach(x=>x.classList.toggle('on',x==b))});
 q('#cn').onclick=()=>m.remove();
 q('#ok').onclick=e=>{let vals=q('#rv').value.split(/[\n,，\s]+/).map(s=>s.trim().replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^\*\./,'')).filter(Boolean);
  if(typ=='ip_cidr'){vals=q('#rv').value.split(/[\n,，\s]+/).map(s=>s.trim()).filter(Boolean).map(v=>v.includes('/')?v:v+'/32');const bad=vals.find(v=>!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v));if(bad){toast('IP 格式不对：'+bad,1);return}}
  else{vals=vals.map(v=>v.toLowerCase());const bad=vals.find(v=>!/^[a-z0-9\u00a1-\uffff_.-]+$/.test(v));if(bad){toast('格式不对：'+bad,1);return}}
  if(!vals.length){toast('请填写要匹配的内容',1);return}
  const r={name:q('#rn').value.trim()||undefined,outbound:out};r[typ]=[...new Set(vals)];
  act('/rules',{rules:[r,...st.rules]},'规则已添加并生效',e.target).then(x=>{if(x){S.rules=null;m.remove();render()}})}})}
function initDrag(){document.querySelectorAll('.dlist').forEach(L=>{if(DG.has(L))return;DG.add(L);
 const start=(row,y,touch)=>{const rows=[...L.children],idx=rows.indexOf(row);if(idx<0)return;const rects=rows.map(r=>r.getBoundingClientRect()),h=rects[idx].height;
  S.dragging={L,row,rows,idx,rects,h,y0:y,to:idx};row.classList.add('lift');L.classList.add('dragging');navigator.vibrate&&navigator.vibrate(12)};
 const move=y=>{const D=S.dragging;if(!D||D.L!==L)return;const dy=y-D.y0;D.row.style.transform=`translateY(${dy}px) scale(1.02)`;const c=D.rects[D.idx].top+D.h/2+dy;let to=D.idx;
  D.rects.forEach((r,i)=>{if(i<D.idx&&c<r.top+r.height/2)to=Math.min(to,i);if(i>D.idx&&c>r.top+r.height/2)to=Math.max(to,i)});const lk=D.rows.findIndex(r=>!r.classList.contains('lock'));if(lk>0)to=Math.max(to,lk);D.to=to;
  D.rows.forEach((r,i)=>{if(r===D.row)return;r.style.transform=i>D.idx&&i<=to?`translateY(${-D.h}px)`:i<D.idx&&i>=to?`translateY(${D.h}px)`:''})};
 const end=()=>{const D=S.dragging;if(!D||D.L!==L)return;D.rows.forEach(r=>r.style.transform='');D.row.classList.remove('lift');L.classList.remove('dragging');S.dragging=null;S.justDragged=1;setTimeout(()=>S.justDragged=0,350);
  if(D.to===D.idx)return;if(L.dataset.rules){const cur=S.rules||S.st.rules,ord=D.rows.map(r=>+r.dataset.n),[x]=ord.splice(D.idx,1);ord.splice(D.to,0,x);const nr=ord.map(i=>cur[i]);if(S.rules){S.rules=nr;render()}else act('/rules',{rules:nr},'规则优先级已保存');return}
  const G=S.st.groups[+L.dataset.gi],m=D.rows.map(r=>r.dataset.n),[x]=m.splice(D.idx,1);m.splice(D.to,0,x);
  if(D.to<D.idx)L.insertBefore(D.row,D.rows[D.to]);else L.insertBefore(D.row,D.rows[D.to].nextSibling);
  [...L.children].forEach((r,i)=>{const p=r.querySelector('.no');if(p)p.textContent=i+1});
  act('/group',{name:G.name,members:m},gl(G)+'：顺序已保存')};
 let tm=null,ty=0,tx=0,tr=null;
 L.addEventListener('touchstart',e=>{const row=e.target.closest('.mem,.drow');if(!row||e.touches.length>1)return;const t=e.touches[0];ty=t.clientY;tx=t.clientX;tr=row;
  const onH=!!e.target.closest('.hdl');clearTimeout(tm);if(onH){e.preventDefault();start(row,ty,1)}else tm=setTimeout(()=>{tm=null;start(row,ty,1)},280)},{passive:false});
 L.addEventListener('touchmove',e=>{const t=e.touches[0];if(S.dragging){e.preventDefault();move(t.clientY);return}if(tm&&(Math.abs(t.clientY-ty)>8||Math.abs(t.clientX-tx)>8)){clearTimeout(tm);tm=null}},{passive:false});
 const tend=e=>{clearTimeout(tm);tm=null;if(S.dragging){e.preventDefault();end()}};L.addEventListener('touchend',tend);L.addEventListener('touchcancel',tend);
 L.addEventListener('contextmenu',e=>{if(e.target.closest('.mem,.drow'))e.preventDefault()});
 L.addEventListener('mousedown',e=>{if(e.button||e.target.closest('button,.sw,a,input'))return;const row=e.target.closest('.mem,.drow');if(!row)return;e.preventDefault();const y=e.clientY,onH=!!e.target.closest('.hdl');let on=false;
  const mm=ev=>{if(!on&&(onH||Math.abs(ev.clientY-y)>4)){on=true;start(row,y)}if(on)move(ev.clientY)},mu=()=>{document.removeEventListener('mousemove',mm);document.removeEventListener('mouseup',mu);if(on)end()};
  document.addEventListener('mousemove',mm);document.addEventListener('mouseup',mu)})})}
function pwSheet(){sheet(`<h3>修改面板密码</h3><div class="fld"><label>原密码</label><input type="password" id="po" autocomplete="current-password"></div><div class="fld"><label>新密码（至少 8 位）</label><input type="password" id="pn" autocomplete="new-password"></div><div class="btns"><button class="btn pri" id="ok">保存</button></div>`,m=>m.querySelector('#ok').onclick=e=>act('/passwd',{old:m.querySelector('#po').value,new:m.querySelector('#pn').value},'密码已修改',e.target).then(r=>{if(r)m.remove()}))}
const MQ=matchMedia('(prefers-color-scheme: dark)');
function theme(t){if(t===undefined)t=document.documentElement.dataset.theme=='dark'?'light':'dark';S.theme=LS.tl_theme=t;document.documentElement.dataset.theme=t=='auto'?(MQ.matches?'dark':'light'):t}
MQ.addEventListener&&MQ.addEventListener('change',()=>{if(S.theme=='auto'){theme('auto');render()}});
function accent(a){S.accent=LS.tl_accent=a;document.documentElement.dataset.accent=a}
function upLog(force){const b=$('#lgb');if(!b||S.tab!='lg'||document.querySelector('.mask'))return;if(!force&&(S.paused||busyScroll()))return void(S.pend=1);S.pend=0;patch(b,lgBody());bind();bind2()}
function busyScroll(){return S.touching||Date.now()-(S.lastScroll||0)<1500||(S.lgv!='dev'&&scrollY>240)}
async function loadState(){try{S.st=await A('/state');if(document.querySelector('.mask')||S.dragging||(S.optEdit&&S.tab=='st')||(S.impEdit&&S.tab=='sb'))head();else if(S.tab=='lg'&&busyScroll()){head();S.pend=1}else render()}catch(e){}}
async function loadConns(){try{S.cx=await A('/conns');S.cx.conns=S.cx.conns||[];S.cx.devices=S.cx.devices||[];if(S.drawer&&!S.touching)upDrawer();if(document.querySelector('.mask'))return;if(S.tab=='dv'||S.tab=='ov'){if(!S.touching)render()}else if(S.tab=='lg')upLog()}catch(e){}}
async function loadLive(){try{S.lv=await A('/live');if(S.st&&(S.lv.enabled!=S.st.enabled||S.lv.fallback!=S.st.fallback))loadState();head();const c=$('#chart');if(c)c.innerHTML=chart()}catch(e){}}
function login(){if($('#login'))return;$('#view').innerHTML='';const m=sheet(`<div id="login"><div class="logo" style="justify-content:center;margin:6px 0 14px"><i></i>TinyLane</div><div class="fld"><label>路由器 root 密码（与 LuCI 相同）</label><input type="password" id="lp" autocomplete="current-password"></div><div class="btns"><button class="btn pri" id="lb">登录</button></div><p class="mut" id="lm" style="font-size:12px;margin-top:8px"></p></div>`,m=>{
 const go=async()=>{try{await A('/login',{password:m.querySelector('#lp').value});m.remove();start()}catch(e){m.querySelector('#lm').textContent=e.message}};m.querySelector('#lb').onclick=go;m.querySelector('#lp').onkeydown=e=>{if(e.key=='Enter')go()};setTimeout(()=>m.querySelector('#lp').focus(),50)});m.onclick=null}
let timers=[];
addEventListener('scroll',()=>{S.lastScroll=Date.now();if(S.tab=='lg'&&S.pend&&scrollY<=240)setTimeout(()=>{if(!busyScroll())upLog(true)},1600)},{passive:true});
addEventListener('touchstart',()=>{S.touching=1},{passive:true});addEventListener('touchend',()=>{S.touching=0;S.lastScroll=Date.now()},{passive:true});addEventListener('touchcancel',()=>{S.touching=0},{passive:true});
setInterval(()=>{if(S.pend&&S.tab=='lg'&&!busyScroll()){S.pend=0;if(!document.querySelector('.mask'))render()}},1000);
async function start(){timers.forEach(clearInterval);await loadState();loadLive();loadConns();
 timers=[setInterval(loadLive,2000),setInterval(loadState,10000),setInterval(()=>{if(['ov','dv','lg'].includes(S.tab)&&!document.hidden)loadConns()},3000)]}
$('#thm').onclick=()=>{theme();render()};$('#hsw').onclick=()=>S.st&&act('/enabled',{on:!S.st.enabled},S.st.enabled?'代理已停用，全部直连':'代理已启用');
theme(S.theme);accent(S.accent);nav();
(async()=>{const m=/(?:^#|&)sid=([0-9a-f]{32})/.exec(location.hash);if(m)history.replaceState(null,'',location.pathname+location.search);let s={};try{s=await A('/session')}catch(e){}
 if(!s.authed&&m){try{await A('/luci-login',{sid:m[1]});s.authed=true}catch(e){}}
 s.authed?start():login()})();
