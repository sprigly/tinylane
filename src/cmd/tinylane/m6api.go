package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// M6 面板接口
func (p *Panel) routesM6() map[string]handler {
	d := p.d
	return map[string]handler{
		// ---- 远程规则集 ----
		"POST /ruleset/save": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var x CustomRuleSet
			if err := json.Unmarshal(in["rs"], &x); err != nil {
				return nil, fmt.Errorf("参数无效")
			}
			old := gets(in, "old_name")
			x.Name, x.URL = strings.TrimSpace(x.Name), strings.TrimSpace(x.URL)
			var urlChanged bool
			err := d.applyEdit(applyOpts{desc: "规则集「" + x.Name + "」已保存"}, func(m map[string]any) error {
				list, _ := m["rule_sets"].([]any)
				entry := map[string]any{"name": x.Name, "url": x.URL, "outbound": x.Outbound, "update": x.Update}
				if x.Format != "" {
					entry["format"] = x.Format
				}
				if x.Disabled {
					entry["disabled"] = true
				}
				found := false
				for i, e := range list {
					o, _ := e.(map[string]any)
					if o != nil && old != "" && o["name"] == old {
						if o["url"] != x.URL || o["name"] != x.Name {
							urlChanged = true
						} else {
							for _, k := range []string{"updated", "count", "has_domain", "has_ip", "last_error"} {
								if v, ok := o[k]; ok {
									entry[k] = v
								}
							}
						}
						list[i] = entry
						found = true
					} else if o != nil && o["name"] == x.Name {
						return fmt.Errorf("已有同名规则集")
					}
				}
				if !found {
					if old != "" {
						return fmt.Errorf("规则集 %q 不存在", old)
					}
					list = append(list, entry)
					urlChanged = true
				}
				m["rule_sets"] = list
				return nil
			})
			if err != nil {
				return nil, err
			}
			if urlChanged && !x.Disabled {
				rs, err := d.rsm.Update(x.Name)
				if err != nil {
					return map[string]any{"ok": true, "warn": "已保存，但下载失败：" + err.Error(), "rs": rs}, nil
				}
				return map[string]any{"ok": true, "rs": rs}, nil
			}
			return nil, nil
		},
		"POST /ruleset/delete": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			name := gets(in, "name")
			c := d.conf()
			x, ok := findRS(c, name)
			if !ok {
				return nil, fmt.Errorf("没有规则集 %q", name)
			}
			path := customRSPath(c, x)
			err := d.applyEdit(applyOpts{desc: "规则集「" + name + "」已删除"}, func(m map[string]any) error {
				list, _ := m["rule_sets"].([]any)
				var keep []any
				for _, e := range list {
					if o, _ := e.(map[string]any); o != nil && o["name"] == name {
						continue
					}
					keep = append(keep, e)
				}
				if len(keep) == 0 {
					delete(m, "rule_sets")
				} else {
					m["rule_sets"] = keep
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			os.Remove(path)
			return nil, nil
		},
		"POST /ruleset/update": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			rs, err := d.rsm.Update(gets(in, "name"))
			if err != nil {
				return nil, err
			}
			return map[string]any{"ok": true, "rs": rs}, nil
		},
		"POST /ruleset/order": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var names []string
			json.Unmarshal(in["names"], &names)
			return nil, d.applyEdit(applyOpts{desc: "规则集顺序已调整"}, func(m map[string]any) error {
				list, _ := m["rule_sets"].([]any)
				if len(names) != len(list) {
					return fmt.Errorf("数量不一致，请刷新")
				}
				by := map[string]any{}
				for _, e := range list {
					if o, _ := e.(map[string]any); o != nil {
						by[fmt.Sprint(o["name"])] = e
					}
				}
				var out []any
				for _, n := range names {
					e, ok := by[n]
					if !ok {
						return fmt.Errorf("规则集 %q 不存在", n)
					}
					out = append(out, e)
				}
				m["rule_sets"] = out
				return nil
			})
		},
		// ---- 导入 ----
		"POST /import/preview": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return d.imp.Preview(d, gets(in, "text"), strings.TrimSpace(gets(in, "url")))
		},
		"POST /import/apply": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			wn, wr := true, true
			if _, ok := in["nodes"]; ok {
				wn = getb(in, "nodes")
			}
			if _, ok := in["rules"]; ok {
				wr = getb(in, "rules")
			}
			return d.imp.Apply(d, gets(in, "token"), gets(in, "target"), wn, wr)
		},
		// ---- 高级模式 ----
		"GET /raw": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			t, sb, err := d.rawText()
			if err != nil {
				return nil, err
			}
			return map[string]any{"text": t, "singbox": sb, "pending": d.rawPending()}, nil
		},
		"POST /raw/check": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return d.rawCheck(gets(in, "text"))
		},
		"POST /raw/apply": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			win := 90 * time.Second
			if v, err := strconv.Atoi(os.Getenv("TINYLANE_RAW_WINDOW_S")); err == nil && v > 0 { // 测试用
				win = time.Duration(v) * time.Second
			}
			return d.rawApply(gets(in, "text"), win)
		},
		"POST /raw/confirm": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, d.rawConfirm()
		},
		"POST /raw/rollback": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, d.rawRollback("手动撤销")
		},
		// ---- 流量 ----
		"GET /traffic": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			return d.acct.status(), nil
		},
		// ---- 访客 ----
		"POST /guest/wifi": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			var g GuestWifi
			if err := json.Unmarshal(in["wifi"], &g); err != nil {
				return nil, fmt.Errorf("参数无效")
			}
			g.SSID = strings.TrimSpace(g.SSID)
			if g.Band == "" {
				g.Band = "both"
			}
			if g.Subnet == "" {
				g.Subnet = d.conf().GuestWifi.Subnet
			}
			g.CheckPing = d.conf().GuestWifi.CheckPing // 只能在配置文件 / 高级模式里改
			if err := g.check(); err != nil {
				return nil, err
			}
			if !fileExists(d.guestScript()) {
				return nil, fmt.Errorf("缺少 %s", d.guestScript())
			}
			if err := d.applyEdit(applyOpts{desc: map[bool]string{true: "访客 Wi‑Fi「" + g.SSID + "」：开启中", false: "访客 Wi‑Fi：关闭中"}[g.Enabled]}, func(m map[string]any) error {
				prev, _ := m["guest_wifi"].(map[string]any)
				e := map[string]any{"enabled": g.Enabled, "ssid": g.SSID, "key": g.Key, "band": g.Band, "subnet": g.Subnet}
				if g.CheckPing != "" {
					e["check_ping"] = g.CheckPing
				}
				if prev != nil && prev["applied"] != nil {
					e["applied"] = prev["applied"]
				}
				m["guest_wifi"] = e
				return nil
			}); err != nil && err != errNoChange {
				return nil, err
			}
			if err := d.applyGuestWifi(g); err != nil {
				return nil, err
			}
			return d.guestStatus(), nil
		},
		"GET /guest/wifi": func(r *http.Request, _ map[string]json.RawMessage) (any, error) {
			return d.guestStatus(), nil
		},
		"POST /guest/newdefault": func(r *http.Request, in map[string]json.RawMessage) (any, error) {
			return nil, d.setNewDefault(getb(in, "on"))
		},
	}
}

// stateM6：附加到 /state
func (p *Panel) stateM6(st map[string]any) {
	d := p.d
	c := d.conf()
	rs := c.CustomRuleSets
	if rs == nil {
		rs = []CustomRuleSet{}
	}
	type rsv struct {
		CustomRuleSet
		Loaded bool   `json:"loaded"`
		Size   int64  `json:"size"`
		Tag    string `json:"tag"`
	}
	var list []rsv
	for _, r := range rs {
		v := rsv{CustomRuleSet: r, Tag: customRSTag(r)}
		if fi, err := os.Stat(customRSPath(c, r)); err == nil {
			v.Loaded, v.Size = true, fi.Size()
		}
		list = append(list, v)
	}
	if list == nil {
		list = []rsv{}
	}
	st["rule_sets"] = list
	st["guest_wifi"] = c.GuestWifi
	st["guest_job"] = d.guestStatus()
	st["raw_pending"] = d.rawPending()
	st["traffic"] = d.acct.status()
}

// tinylane config-set [-i 配置] <a.b.c> <值>：改一个标量键（值按 JSON 解析，解析不了就当字符串），校验通过才写。
// 例：tinylane config-set guest_wifi.check_ping 10.0.0.1
func cmdConfigSet(args []string) error {
	fs := flag.NewFlagSet("config-set", flag.ExitOnError)
	in := fs.String("i", "/etc/tinylane/tinylane.json", "TinyLane 配置")
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("用法：tinylane config-set <a.b.c> <值>")
	}
	keys := strings.Split(fs.Arg(0), ".")
	var val any
	if err := json.Unmarshal([]byte(fs.Arg(1)), &val); err != nil {
		val = fs.Arg(1)
	}
	return editRawFile(*in, func(m map[string]any) error {
		cur := m
		for _, k := range keys[:len(keys)-1] {
			nx, ok := cur[k].(map[string]any)
			if !ok {
				nx = map[string]any{}
				cur[k] = nx
			}
			cur = nx
		}
		cur[keys[len(keys)-1]] = val
		return nil
	})
}
