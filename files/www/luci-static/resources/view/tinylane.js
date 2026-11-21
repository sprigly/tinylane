'use strict';
'require view';

// 服务 → TinyLane：直接跳到 http://<当前主机>:9999（带 LuCI 会话，免二次登录）。
// 面板在 /cgi-bin/luci/tinylane-sso 读 sysauth cookie 校验；cookie 不可用时用 #sid 片段（不发给服务器）。
return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	render: function() {
		var host = window.location.hostname;
		if (host.indexOf(':') >= 0)
			host = '[' + host + ']';
		var url = 'http://' + host + ':9999/cgi-bin/luci/tinylane-sso#sid=' + encodeURIComponent(L.env.sessionid || '');
		window.location.replace(url);
		return E('p', {}, E('a', { 'href': url }, '正在打开 TinyLane…'));
	}
});
