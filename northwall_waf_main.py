# coding: utf-8
"""
NorthWall WAF - aaPanel Official Plugin Backend Controller
Author: NorthDigits
Version: 1.0.0
"""

import os
import sys
import json
import time
import re
import threading
from datetime import datetime

# aaPanel official public library
sys.path.insert(0, '/www/server/panel/class')
try:
    import public
except ImportError:
    public = None

try:
    import requests
except ImportError:
    requests = None


class northwall_waf_main:
    __plugin_path   = "/www/server/panel/plugin/northwall_waf"
    __config_path   = "/www/server/panel/plugin/northwall_waf/config.json"
    __rules_path    = "/www/server/panel/plugin/northwall_waf/core/rules/filter_rules.json"
    __log_path      = "/www/server/panel/plugin/northwall_waf/logs/blocked.log"
    __error_log     = "/www/server/panel/plugin/northwall_waf/logs/error.log"
    __lua_waf_path  = "/www/server/panel/plugin/northwall_waf/core/lua/waf.lua"

    def __init__(self):
        for path in [
            os.path.join(self.__plugin_path, "logs"),
            os.path.join(self.__plugin_path, "core/rules"),
            os.path.join(self.__plugin_path, "core/lua"),
        ]:
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)

        if not os.path.exists(self.__config_path):
            self._save_config(self._default_config())

    def _default_config(self):
        return {
            "status":           True,
            "cc_defense":       True,
            "sqli_defense":     True,
            "xss_defense":      True,
            "scan_defense":     True,
            "cmd_defense":      True,
            "file_inc_defense": True,
            "cc_limit":         100,
            "cc_ban_seconds":   3600,
            "telegram_alert":   False,
            "telegram_token":   "",
            "telegram_chat_id": "",
            "whitelist_ips":    ["127.0.0.1", "43.231.20.0/24"],
            "blacklist_ips":    [],
            "installed_sites":  [],
            "version":          "1.0.0"
        }

    def _get_config(self):
        try:
            if public and hasattr(public, 'ReadFile'):
                content = public.ReadFile(self.__config_path)
                if content:
                    return json.loads(content)
            with open(self.__config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return self._default_config()

    def _save_config(self, conf):
        try:
            payload = json.dumps(conf, indent=4, ensure_ascii=False)
            if public and hasattr(public, 'WriteFile'):
                public.WriteFile(self.__config_path, payload)
                return True
            with open(self.__config_path, "w", encoding="utf-8") as f:
                f.write(payload)
            return True
        except Exception:
            return False

    # =====================================================
    # OFFICIAL INDEX RENDERER (Called by aaPanel)
    # =====================================================
    def index(self, args):
        html_file = os.path.join(self.__plugin_path, "index.html")
        if os.path.exists(html_file):
            if public and hasattr(public, 'ReadFile'):
                return public.ReadFile(html_file)
            with open(html_file, "r", encoding="utf-8") as f:
                return f.read()
        return "<h3>NorthWall WAF index.html not found!</h3>"

    # =====================================================
    # API: GET STATUS (POST)
    # =====================================================
    def get_status(self, args):
        conf = self._get_config()
        stats = self._get_stats()
        return {
            "status": True,
            "data": {
                "config": conf,
                "stats": stats
            }
        }

    # =====================================================
    # API: UPDATE CONFIG (POST)
    # =====================================================
    def update_config(self, args):
        conf = self._get_config()
        fields_bool = [
            "status", "cc_defense", "sqli_defense", "xss_defense",
            "scan_defense", "cmd_defense", "file_inc_defense", "telegram_alert"
        ]
        fields_str = ["telegram_token", "telegram_chat_id"]
        fields_int = ["cc_limit", "cc_ban_seconds"]

        for f in fields_bool:
            if hasattr(args, f):
                conf[f] = getattr(args, f) in [True, "true", "True", 1, "1"]
        for f in fields_str:
            if hasattr(args, f):
                conf[f] = str(getattr(args, f)).strip()
        for f in fields_int:
            if hasattr(args, f):
                try:
                    conf[f] = int(getattr(args, f))
                except Exception:
                    pass

        if self._save_config(conf):
            return {"status": True, "msg": "NorthWall WAF settings saved successfully!"}
        return {"status": False, "msg": "Failed to save configuration"}

    # =====================================================
    # API: WHITELIST & BLACKLIST (POST)
    # =====================================================
    def add_whitelist(self, args):
        ip = str(getattr(args, "ip", "")).strip()
        if not ip: return {"status": False, "msg": "Please provide an IP address"}
        conf = self._get_config()
        if ip not in conf["whitelist_ips"]:
            conf["whitelist_ips"].append(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} added to whitelist"}

    def remove_whitelist(self, args):
        ip = str(getattr(args, "ip", "")).strip()
        conf = self._get_config()
        if ip in conf["whitelist_ips"]:
            conf["whitelist_ips"].remove(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} removed from whitelist"}

    def add_blacklist(self, args):
        ip = str(getattr(args, "ip", "")).strip()
        if not ip: return {"status": False, "msg": "Please provide an IP address"}
        conf = self._get_config()
        if ip not in conf["blacklist_ips"]:
            conf["blacklist_ips"].append(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} blocked and added to blacklist"}

    def remove_blacklist(self, args):
        ip = str(getattr(args, "ip", "")).strip()
        conf = self._get_config()
        if ip in conf["blacklist_ips"]:
            conf["blacklist_ips"].remove(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} removed from blacklist"}

    # =====================================================
    # API: GET LOGS (POST)
    # =====================================================
    def get_logs(self, args):
        if not os.path.exists(self.__log_path):
            return {"status": True, "data": []}
        try:
            with open(self.__log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            logs = []
            for l in reversed(lines[-50:]):
                try: logs.append(json.loads(l.strip()))
                except Exception: pass
            return {"status": True, "data": logs}
        except Exception as e:
            return {"status": False, "msg": str(e)}

    def clear_logs(self, args):
        try:
            with open(self.__log_path, "w", encoding="utf-8") as f:
                f.write("")
            return {"status": True, "msg": "Logs cleared successfully"}
        except Exception as e:
            return {"status": False, "msg": str(e)}

    # =====================================================
    # API: SITE PROTECTION INJECTION (POST)
    # =====================================================
    def get_sites(self, args):
        vhost_path = "/www/server/panel/vhost/nginx/"
        sites = []
        conf = self._get_config()
        if os.path.exists(vhost_path):
            for f in os.listdir(vhost_path):
                if f.endswith(".conf"):
                    name = f.replace(".conf", "")
                    sites.append({
                        "name": name,
                        "waf_active": name in conf.get("installed_sites", [])
                    })
        return {"status": True, "data": sites}

    def install_to_site(self, args):
        site = str(getattr(args, "site", "")).strip()
        site_conf = f"/www/server/panel/vhost/nginx/{site}.conf"
        if not os.path.exists(site_conf):
            return {"status": False, "msg": f"Config not found for site: {site}"}

        inject = f"    access_by_lua_file {self.__lua_waf_path};\n"
        with open(site_conf, "r", encoding="utf-8") as f:
            c = f.read()

        if inject.strip() not in c:
            new_c = c.replace("server {", f"server {{\n{inject}", 1)
            with open(site_conf, "w", encoding="utf-8") as f:
                f.write(new_c)

        if public and hasattr(public, 'ExecShell'):
            public.ExecShell("nginx -s reload")
        else:
            os.system("nginx -s reload")

        conf = self._get_config()
        if site not in conf["installed_sites"]:
            conf["installed_sites"].append(site)
            self._save_config(conf)

        return {"status": True, "msg": f"NorthWall WAF activated on {site}!"}

    def remove_from_site(self, args):
        site = str(getattr(args, "site", "")).strip()
        site_conf = f"/www/server/panel/vhost/nginx/{site}.conf"
        if not os.path.exists(site_conf):
            return {"status": False, "msg": f"Config not found for site: {site}"}

        inject = f"    access_by_lua_file {self.__lua_waf_path};\n"
        with open(site_conf, "r", encoding="utf-8") as f:
            c = f.read()

        new_c = c.replace(inject, "")
        with open(site_conf, "w", encoding="utf-8") as f:
            f.write(new_c)

        if public and hasattr(public, 'ExecShell'):
            public.ExecShell("nginx -s reload")
        else:
            os.system("nginx -s reload")

        conf = self._get_config()
        if site in conf["installed_sites"]:
            conf["installed_sites"].remove(site)
            self._save_config(conf)

        return {"status": True, "msg": f"NorthWall WAF disabled on {site}"}

    # =====================================================
    # API: TELEGRAM ALERT (POST)
    # =====================================================
    def test_telegram(self, args):
        conf = self._get_config()
        if not conf.get("telegram_token") or not conf.get("telegram_chat_id"):
            return {"status": False, "msg": "Please configure Telegram Bot Token and Chat ID first"}

        if requests is None:
            return {"status": False, "msg": "Python 'requests' module not installed"}

        message = (
            "🛡️ *NorthWall WAF Test Alert*\n"
            "━━━━━━━━━━━━━━━━━\n"
            "✅ Telegram notifications are working perfectly!\n"
            f"⏰ Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            "━━━━━━━━━━━━━━━━━\n"
            "🔒 _NorthDigits Security_"
        )
        try:
            api_url = f"https://api.telegram.org/bot{conf['telegram_token']}/sendMessage"
            requests.post(api_url, data={
                "chat_id": conf["telegram_chat_id"],
                "text": message,
                "parse_mode": "Markdown"
            }, timeout=5)
            return {"status": True, "msg": "Test alert sent to your Telegram!"}
        except Exception as e:
            return {"status": False, "msg": f"Telegram error: {e}"}

    # Internal stats calculator
    def _get_stats(self):
        stats = {
            "total_blocked": 0,
            "today_blocked": 0,
            "attack_types":  {},
            "top_ips":       {}
        }
        if not os.path.exists(self.__log_path):
            return stats

        today = datetime.now().strftime("%Y-%m-%d")
        try:
            with open(self.__log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for l in lines:
                try:
                    e = json.loads(l.strip())
                    stats["total_blocked"] += 1
                    if e.get("time", "").startswith(today):
                        stats["today_blocked"] += 1
                    at = e.get("attack", "Unknown")
                    stats["attack_types"][at] = stats["attack_types"].get(at, 0) + 1
                except Exception:
                    pass
        except Exception:
            pass
        return stats
