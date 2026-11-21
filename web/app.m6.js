
// ===== M6：远程规则集 · 导入 · 高级模式 · 按设备流量 · 访客 Wi‑Fi · 新设备默认访客 =====
const UPD={daily:'每天',weekly:'每周',off:'不自动更新'};
function rsCard(){const st=S.st,rs=st.rulesets||{},list=st.rule_sets||[];
 return `<div class="card"><h3>规则集</h3>
<div class="list">${['geosite-cn.srs','geoip-cn.srs'].map(f=>`<div class="set"><div>${f}<div class="mut sm2">内置 · 每周一 04:30 自动更新 · 上次 ${rs[f]?tfmt(rs[f]):'—'}</div></div><span class="tag t-dir">直连</span></div>`).join('')}
${list.map((r,i)=>`<div class="set rsrow ${r.disabled?'off-c':''}" data-k="rs${esc(r.name)}"><div><div class="row" style="gap:6px;flex-wrap:wrap"><b>${esc(r.name)}</b>${outTag(r.outbound)}${r.loaded?'':'<span class="tag t-blk">未加载</span>'}</div><div class="mut sm2" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.url)}</div><div class="mut sm2">${r.format=='source'?'JSON 源格式':'.srs 二进制'} · ${r.count?r.count+' 条':'—'}${r.has_ip?' · 含 IP 段':''} · ${UPD[r.update]||r.update} · 上次 ${esc(r.updated||'从未')}</div>${r.last_error?`<div class="sm2" style="color:var(--bad)">✗ ${esc(r.last_error)}</div>`:''}</div><div class="rowbtns trail"><button class="btn" data-rsu="${i}">更新</button><button class="btn" data-rse="${i}">编辑</button></div></div>`).join('')}</div>
<p class="mut sm2" style="margin-top:8px">自定义规则集排在「自定义规则」之后、国内直连之前；固定规则永远最先匹配。已下载的在凌晨 04:00–06:00 按计划更新。</p>
<div class="btns"><button class="btn" data-a="rsupd">更新内置规则集</button><button class="btn pri" data-a="rsadd">＋ 添加规则集</button></div></div>`}
function rsSheet(i){const st=S.st,r=i>=0?st.rule_sets[i]:{name:'',url:'',outbound:st.main_group,update:'weekly',format:''};
 sheet(`<h3>${i>=0?'编辑规则集':'添加规则集'}</h3>
<div class="fld"><label>名称</label><input id="rn" maxlength="40" value="${esc(r.name)}" placeholder="如：Netflix"></div>
<div class="fld"><label>URL（.srs 二进制或 sing-box 源格式 .json）</label><input id="ru" inputmode="url" autocapitalize="off" spellcheck="false" value="${esc(r.url)}" placeholder="https://…/geosite-netflix.srs"></div>
<div class="fld"><label>去向</label><select id="ro">${outOpts(r.outbound)}</select></div>
<div class="fld"><label>格式</label><div class="seg" id="rf">${[['','自动'],['binary','.srs'],['source','.json']].map(([k,v])=>`<button data-v="${k}" class="${(r.format||'')==k?'on':''}">${v}</button>`).join('')}</div></div>
<div class="fld"><label>自动更新</label><div class="seg" id="rp">${Object.entries(UPD).map(([k,v])=>`<button data-v="${k}" class="${r.update==k?'on':''}">${v}</button>`).join('')}</div></div>
${i>=0?`<div class="set"><div>启用</div><div class="sw sm ${r.disabled?'':'on'}" id="ren"></div></div>`:''}
<p class="mut sm2">保存后立即下载并用内核同一套解析器校验，通过才加载；GitHub 地址直连失败会自动经代理再试。</p>
<div class="btns"><button class="btn pri" id="rs_ok">保存并下载</button>${i>=0?'<button class="btn dan" id="rs_del">删除</button>':''}<button class="btn" id="rs_x">取消</button></div>`,m=>{
  const segv=id=>m.querySelector('#'+id+' .on')?.dataset.v??'';
  m.querySelectorAll('.seg button').forEach(b=>b.onclick=()=>{b.parentNode.querySelectorAll('button').forEach(x=>x.classList.toggle('on',x==b))});
  const en=m.querySelector('#ren');if(en)en.onclick=()=>en.classList.toggle('on');
  m.querySelector('#rs_x').onclick=()=>m.remove();
  m.querySelector('#rs_ok').onclick=async e=>{const rs={name:m.querySelector('#rn').value.trim(),url:m.querySelector('#ru').value.trim(),outbound:m.querySelector('#ro').value,update:segv('rp')||'weekly',format:segv('rf'),disabled:en?!en.classList.contains('on'):false};
   const j=await act('/ruleset/save',{rs,old_name:i>=0?r.name:''},null,e.target);if(j){toast(j.warn?'⚠ '+j.warn:'✓ 已保存'+(j.rs?.count?'（'+j.rs.count+' 条）':''),!!j.warn);m.remove();render()}};
  const dl=m.querySelector('#rs_del');if(dl)dl.onclick=()=>{m.remove();confirmSheet('删除规则集「'+r.name+'」？','引用它的路由规则会一起去掉，内核热重载一次。',()=>act('/ruleset/delete',{name:r.name},'已删除'))}})}

// ---- 导入 ----
function importSheet(){sheet(`<h3>导入</h3><p class="mut sm2" style="margin-bottom:10px">支持：TinyLane 配置（整份替换）· Clash / mihomo YAML · sing-box JSON · 分享链接 / Base64 订阅 · Clash 规则行 · 域名列表。先预览，确认后才应用。</p>
<div class="seg" id="isrc" style="margin-bottom:10px"><button data-v="file" class="on">文件</button><button data-v="url">URL</button><button data-v="text">粘贴</button></div>
<div id="i_file" class="fld"><input type="file" id="if" accept=".json,.yaml,.yml,.txt,.conf,.list"></div>
<div id="i_url" class="fld" style="display:none"><input id="iu" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="https://…"></div>
<div id="i_text" class="fld" style="display:none"><textarea id="it" rows="7" class="mono" spellcheck="false" placeholder="粘贴配置、链接或规则"></textarea></div>
<div class="btns"><button class="btn pri" id="i_pv">预览</button><button class="btn" id="i_x">取消</button></div><div id="i_res"></div>`,m=>{
 const pick=v=>{m.querySelectorAll('#isrc button').forEach(b=>b.classList.toggle('on',b.dataset.v==v));['file','url','text'].forEach(k=>m.querySelector('#i_'+k).style.display=k==v?'':'none')};
 m.querySelectorAll('#isrc button').forEach(b=>b.onclick=()=>pick(b.dataset.v));
 m.querySelector('#i_x').onclick=()=>m.remove();
 m.querySelector('#i_pv').onclick=async e=>{const src=m.querySelector('#isrc .on').dataset.v;let body={};
  if(src=='file'){const f=m.querySelector('#if').files[0];if(!f)return toast('先选择文件',1);if(f.size>2e6)return toast('文件超过 2 MB',1);body.text=await f.text()}
  else if(src=='url'){body.url=m.querySelector('#iu').value.trim();if(!body.url)return toast('填写 URL',1)}else{body.text=m.querySelector('#it').value;if(!body.text.trim())return toast('内容为空',1)}
  const b=e.target;b.disabled=true;b.textContent='解析中…';let p;try{p=await A('/import/preview',body)}catch(er){toast('✗ '+er.message,1);b.disabled=false;b.textContent='预览';return}b.disabled=false;b.textContent='重新预览';
  const AC={add:'新增',same:'已存在',rename:'重名→改名',replace:'替换'};
  m.querySelector('#i_res').innerHTML=`<div class="card inset" style="margin-top:12px"><h3>${esc(p.kind)}</h3>${(p.summary||[]).map(x=>`<div class="sm2">• ${esc(x)}</div>`).join('')}${(p.warns||[]).map(x=>`<div class="sm2" style="color:var(--warn)">⚠ ${esc(x)}</div>`).join('')}
${p.nodes.length?`<div class="list" style="margin-top:8px;max-height:30vh;overflow:auto">${p.nodes.map(n=>`<div class="set"><div style="min-width:0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.name)} ${ptag(n.type)}</div><span class="mut sm2">${AC[n.action]||n.action}</span></div>`).join('')}</div>`:''}
${p.rules.length?`<div class="sm2 mut" style="margin-top:8px">规则：${p.rules.map(r=>esc(r.name)).join('、')}</div>${p.need_target?`<div class="fld" style="margin-top:8px"><label>「代理」类规则走哪个组</label><select id="itg">${outOpts(S.st.main_group)}</select></div>`:''}`:''}
<div class="btns"><button class="btn pri" id="i_ap">确认导入</button></div></div>`;
  m.querySelector('#i_ap').onclick=async ev=>{const tg=m.querySelector('#itg');const j=await act('/import/apply',{token:p.token,target:tg?tg.value:''},null,ev.target);if(j){toast(j.nodes_added!=null?`✓ 新增 ${j.nodes_added} 个节点、${j.rules_added} 条规则`:'✓ 配置已替换');m.remove();render()}}}})}

// ---- 高级模式 ----
async function rawSheet(){let r;try{r=await A('/raw')}catch(e){return toast('✗ '+e.message,1)}
 sheet(`<h3>高级模式 · 原始配置</h3><div class="seg" id="rv" style="margin-bottom:10px"><button data-v="cfg" class="on">TinyLane 配置（可编辑）</button><button data-v="sb">生成的 sing-box（只读）</button></div>
<textarea id="rt" class="mono code" spellcheck="false" autocapitalize="off" autocorrect="off" rows="16">${esc(r.text)}</textarea>
<div id="r_msg" class="sm2" style="margin-top:8px"></div>
<p class="mut sm2">密钥已用 ******** 代替，保存时自动还原。应用后有 90 秒确认期：没点「保留」会自动恢复原配置。禁止规则和固定规则受保护，这里删不掉。</p>
<div class="btns"><button class="btn" id="r_ck">校验</button><button class="btn pri" id="r_ap">校验并应用</button><button class="btn" id="r_x">关闭</button></div>`,m=>{
 const ta=m.querySelector('#rt'),msg=m.querySelector('#r_msg');let cur='cfg',edit=r.text;
 m.querySelectorAll('#rv button').forEach(b=>b.onclick=()=>{if(cur=='cfg')edit=ta.value;cur=b.dataset.v;m.querySelectorAll('#rv button').forEach(x=>x.classList.toggle('on',x==b));ta.value=cur=='cfg'?edit:r.singbox;ta.readOnly=cur!='cfg';m.querySelector('#r_ck').disabled=m.querySelector('#r_ap').disabled=cur!='cfg'});
 const show=(ok,t)=>{msg.style.color=ok?'var(--ok)':'var(--bad)';msg.innerHTML=t};
 m.querySelector('#r_x').onclick=()=>m.remove();
 m.querySelector('#r_ck').onclick=async()=>{try{const j=await A('/raw/check',{text:ta.value});show(1,'✓ 校验通过：'+j.summary.map(esc).join('；'))}catch(e){show(0,'✗ '+esc(e.message))}};
 m.querySelector('#r_ap').onclick=async e=>{let j;try{j=await A('/raw/apply',{text:ta.value})}catch(er){return show(0,'✗ '+esc(er.message))}m.remove();toast('已应用，请在 90 秒内确认');await loadState();render()}})}
function rawBanner(){const t=S.st?.raw_pending;if(!t)return'';const left=Math.max(0,Math.round(t-Date.now()/1e3));return `<div class="banner warn" data-k="rawpend"><div style="flex:1">高级模式改动已应用，<b>${left}</b> 秒内不确认会自动恢复原配置。</div><button class="btn pri" data-a="rawok">保留</button><button class="btn" data-a="rawundo">撤销</button></div>`}

// ---- 访客 ----
function guestCard(){const st=S.st,g=st.guest,w=st.guest_wifi||{},j=st.guest_job||{};
 return `<div class="card"><h3>访客</h3><div class="list">
<div class="set"><div>访客只允许直连<div class="mut sm2">访客设备不走代理，也不能被指定节点</div></div><div class="sw sm ${g.direct_only?'on':''}" data-gd></div></div>
<div class="set"><div>访客 Wi‑Fi<div class="mut sm2">${w.enabled?`「${esc(w.ssid)}」· ${w.band=='2g'?'2.4 GHz':w.band=='5g'?'5 GHz':'2.4 + 5 GHz'} · ${esc(w.subnet)}${w.applied?' · '+esc(w.applied)+' 生效':''}`:'独立名称和密码，只能上网：不能访问家里设备和路由器后台，访客之间也互相隔离'}${j.running?'<br><b>'+esc(j.msg)+'</b>':j.msg?'<br>'+esc(j.msg):''}</div></div><button class="btn" data-a="gwifi">${w.enabled?'设置':'开启'}</button></div>
<div class="set"><div>新设备默认算访客<div class="mut sm2">打开时现在的设备都记为家人；之后第一次出现的设备自动设为访客。注意：iPhone「私有无线局域网地址」轮换时会被当成新设备。</div></div><div class="sw sm ${g.new_device_default?'on':''}" data-a="gnew"></div></div>
<div class="set"><div>已标记访客<div class="mut sm2">在「设备」页按 MAC 设为访客 / 家人</div></div><span class="mut">${(g.macs||[]).length} 台</span></div></div></div>`}
function gwifiSheet(){const w=S.st.guest_wifi||{},rnd=()=>{const a='abcdefghjkmnpqrstuvwxyz23456789';let s='';crypto.getRandomValues(new Uint32Array(10)).forEach(x=>s+=a[x%a.length]);return s};
 sheet(`<h3>访客 Wi‑Fi</h3>
<div class="fld"><label>名称（SSID）</label><input id="gs" maxlength="32" value="${esc(w.ssid||'TinyLane-Guest')}"></div>
<div class="fld"><label>密码（8–63 位）</label><div class="row"><input id="gk" autocapitalize="off" spellcheck="false" value="${esc(w.key||rnd())}"><button class="btn" id="gr">随机</button></div></div>
<div class="fld"><label>频段</label><div class="seg" id="gb">${[['both','2.4 + 5 GHz'],['2g','2.4 GHz'],['5g','5 GHz']].map(([k,v])=>`<button data-v="${k}" class="${(w.band||'both')==k?'on':''}">${v}</button>`).join('')}</div></div>
<p class="mut sm2">应用时 Wi‑Fi 会重启一次（所有设备断开约 10–30 秒后自动重连）。路由器会自检主 Wi‑Fi 和远程运维链路，任一项没恢复就自动撤回。</p>
<div class="btns"><button class="btn pri" id="g_on">${w.enabled?'保存并应用':'开启'}</button>${w.enabled?'<button class="btn dan" id="g_off">关闭访客 Wi‑Fi</button>':''}<button class="btn" id="g_x">取消</button></div>`,m=>{
 m.querySelector('#gr').onclick=()=>m.querySelector('#gk').value=rnd();
 m.querySelectorAll('#gb button').forEach(b=>b.onclick=()=>m.querySelectorAll('#gb button').forEach(x=>x.classList.toggle('on',x==b)));
 m.querySelector('#g_x').onclick=()=>m.remove();
 const go=on=>async e=>{const wifi={enabled:on,ssid:m.querySelector('#gs').value.trim(),key:m.querySelector('#gk').value,band:m.querySelector('#gb .on').dataset.v};const j=await act('/guest/wifi',{wifi},null,e.target);if(j){m.remove();render();toast(on?'正在开启访客 Wi‑Fi…':'正在关闭访客 Wi‑Fi…');pollGuest()}};
 m.querySelector('#g_on').onclick=go(true);const off=m.querySelector('#g_off');if(off)off.onclick=go(false)})}
function pollGuest(){let n=0;const t=setInterval(async()=>{n++;try{const j=await A('/guest/wifi');if(!j.running||n>60){clearInterval(t);await loadState();if(j.msg)toast(j.msg,!j.msg.startsWith('OK'))}}catch(e){if(n>60)clearInterval(t)}},3000)}

// ---- 绑定 ----
function bindM6(){const on=(sel,fn)=>document.querySelectorAll('#view '+sel+',.sheet '+sel).forEach(e=>e.onclick=ev=>{ev.stopPropagation();fn(e,ev)});const st=S.st;
 on('[data-a=rsadd]',()=>rsSheet(-1));
 on('[data-rse]',e=>rsSheet(+e.dataset.rse));
 on('[data-rsu]',e=>act('/ruleset/update',{name:st.rule_sets[+e.dataset.rsu].name},'规则集已更新',e));
 on('[data-a=import]',importSheet);
 on('[data-a=raw]',rawSheet);
 on('[data-a=rawok]',e=>act('/raw/confirm',{},'已保留改动',e));
 on('[data-a=rawundo]',e=>act('/raw/rollback',{},'已恢复原配置',e));
 on('[data-a=gwifi]',gwifiSheet);
 on('[data-a=gnew]',()=>{const v=!st.guest.new_device_default;if(v)confirmSheet('打开「新设备默认算访客」？','现在在线和有租约的设备都会记为家人。之后新出现的设备只能直连上网，直到你在设备页把它设为家人。',()=>act('/guest/newdefault',{on:true},'已开启'));else act('/guest/newdefault',{on:false},'已关闭')});
}
setInterval(()=>{const b=document.querySelector('[data-k=rawpend] b');if(b&&S.st?.raw_pending){b.textContent=Math.max(0,Math.round(S.st.raw_pending-Date.now()/1e3))}},1000);
// ---- iOS 大标题折叠：往下滚时导航栏出现细线和居中小标题 ----
(()=>{const hd=document.querySelector('header'),nt=document.getElementById('ntitle');let on=null;
 const up=()=>{const s=scrollY>28;if(s!==on){on=s;hd.classList.toggle('scrolled',s)}if(s&&nt){const h=document.querySelector('#view h2');const t=h?(h.firstChild?.textContent||'').trim():'';if(nt.textContent!==t)nt.textContent=t}};
 addEventListener('scroll',up,{passive:true});setInterval(up,800);
 const f=document.getElementById('ftr');setInterval(()=>{if(f&&S.st&&!f.dataset.v){f.dataset.v=1;f.textContent='TinyLane '+S.st.version+' · sing-box 1.14.4'}},1500)})();
