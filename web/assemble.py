#!/usr/bin/env python3
# web/app.html = app.tpl.html + _proto.css（原型样式）+ app.extra.css + apple.css（M6 Apple 风格，覆盖前两者）+ app.js + app.m6.js
import os
d=os.path.dirname(os.path.abspath(__file__))
r=lambda f:open(os.path.join(d,f),encoding='utf-8').read() if os.path.exists(os.path.join(d,f)) else ''
h=r('app.tpl.html').replace('/*CSS*/',r('_proto.css')+r('app.extra.css')+r('apple.css')).replace('/*JS*/',r('app.js')+r('app.m6.js'))
import base64
b64=lambda f,m:'data:'+m+';base64,'+base64.b64encode(open(os.path.join(d,'icons',f),'rb').read()).decode()
h=h.replace('__ICON24__',b64('c-small-24.png','image/png')).replace('__ICONL__',b64('c-large.svg','image/svg+xml'))  # M6b 图标内联（不外链）
open(os.path.join(d,'app.html'),'w',encoding='utf-8').write(h)
