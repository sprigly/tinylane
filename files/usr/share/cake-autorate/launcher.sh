#!/usr/bin/env bash
# TinyLane：cake-autorate v3.2.2 启动器。配置由 tinylane-sqm.sh 写在 tmpfs。
export CAKE_AUTORATE_SCRIPT_PREFIX=/usr/share/cake-autorate
export CAKE_AUTORATE_CONFIG_PREFIX=/var/run/tinylane/sqm
[ -f /var/run/tinylane/sqm/config.primary.sh ] || { sleep 30; exit 0; }
exec /usr/share/cake-autorate/cake-autorate.sh /var/run/tinylane/sqm/config.primary.sh
