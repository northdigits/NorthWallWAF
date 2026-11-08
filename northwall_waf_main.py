# coding: utf-8
"""
NorthWall WAF - aaPanel Plugin Backend Controller
Author: NorthDigits
Version: 1.0.0
"""

import os
import sys
import json
import time
import re
import subprocess
import threading
import hashlib
from datetime import datetime, timedelta

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
    __nginx_conf    = "/www/server/nginx/conf/nginx.conf"
    __lua_waf_path  = "/www/server/panel/plugin/northwall_waf/core/lua/waf.lua"

    # =====================================================
    # INIT
    # =====================================================
    def __init__(self):
        for path in [
            os.path.join(self.__plugin_path, "logs"),
            os.path.join(self.__plugin_path, "core/rules"),
            os.path.join(self.__plugin_path, "core/lua"),
        ]:
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
            "cc_limit":         100,         # রিকোয়েস্ট সংখ্যা per minute
            "cc_ban_seconds":   3600,        # কত সেকেন্ড ব্যান
            "telegram_alert":   False,
            "telegram_token":   "",
            "telegram_chat_id": "",
            "whitelist_ips":    ["127.0.0.1"],
            "blacklist_ips":    [],
            "geo_block":        [],          # block করা দেশের কোড তালিকা
            "installed_sites":  [],          # যে সাইটগুলোতে WAF ইনজেক্ট করা আছে
            "version":          "1.0.0"
        }

    # =====================================================
    # CONFIG HELPERS
    # =====================================================
    def _get_config(self):
        try:
            with open(self.__config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return self._default_config()

    def _save_config(self, conf):
        try:
            with open(self.__config_path, "w", encoding="utf-8") as f:
                json.dump(conf, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            self._write_error(str(e))
            return False

    def _write_error(self, msg):
        try:
            with open(self.__error_log, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    # =====================================================
    # API: GET STATUS (aaPanel UI তে সব ডাটা দেখানোর জন্য)
    # =====================================================
    def get_status(self, get):
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
    # API: UPDATE CONFIG (UI থেকে সেটিংস পরিবর্তন)
    # =====================================================
    def update_config(self, get):
        conf = self._get_config()
        fields_bool = [
            "status", "cc_defense", "sqli_defense", "xss_defense",
            "scan_defense", "cmd_defense", "file_inc_defense", "telegram_alert"
        ]
        fields_str = ["telegram_token", "telegram_chat_id"]
        fields_int = ["cc_limit", "cc_ban_seconds"]

        for f in fields_bool:
            if hasattr(get, f):
                conf[f] = getattr(get, f) in [True, "true", "True", 1, "1"]
        for f in fields_str:
            if hasattr(get, f):
                conf[f] = str(getattr(get, f)).strip()
        for f in fields_int:
            if hasattr(get, f):
                try:
                    conf[f] = int(getattr(get, f))
                except Exception:
                    pass

        if self._save_config(conf):
            return {"status": True, "msg": "NorthWall WAF configuration saved!"}
        return {"status": False, "msg": "Failed to save configuration"}

    # =====================================================
    # API: IP WHITELIST / BLACKLIST MANAGEMENT
    # =====================================================
    def add_whitelist(self, get):
        ip = str(get.ip).strip()
        if not self._validate_ip_or_cidr(ip):
            return {"status": False, "msg": "Invalid IP address or CIDR format"}
        conf = self._get_config()
        if ip not in conf["whitelist_ips"]:
            conf["whitelist_ips"].append(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} added to whitelist"}

    def remove_whitelist(self, get):
        ip = str(get.ip).strip()
        conf = self._get_config()
        if ip in conf["whitelist_ips"]:
            conf["whitelist_ips"].remove(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} removed from whitelist"}

    def add_blacklist(self, get):
        ip = str(get.ip).strip()
        if not self._validate_ip_or_cidr(ip):
            return {"status": False, "msg": "Invalid IP address or CIDR format"}
        conf = self._get_config()
        if ip not in conf["blacklist_ips"]:
            conf["blacklist_ips"].append(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} added to blacklist"}

    def remove_blacklist(self, get):
        ip = str(get.ip).strip()
        conf = self._get_config()
        if ip in conf["blacklist_ips"]:
            conf["blacklist_ips"].remove(ip)
            self._save_config(conf)
        return {"status": True, "msg": f"{ip} removed from blacklist"}

    def _validate_ip_or_cidr(self, ip):
        cidr_pattern = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        return bool(re.match(cidr_pattern, ip))

    # =====================================================
    # API: GET BLOCKED LOGS (aaPanel UI Log ট্যাবের জন্য)
    # =====================================================
    def get_logs(self, get):
        if not os.path.exists(self.__log_path):
            return {"status": True, "data": [], "total": 0}
        try:
            page     = int(getattr(get, "page", 1))
            per_page = int(getattr(get, "per_page", 20))
            search   = str(getattr(get, "search", "")).strip().lower()

            with open(self.__log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            entries = []
            for line in reversed(lines):
                try:
                    entry = json.loads(line.strip())
                    if search and search not in json.dumps(entry).lower():
                        continue
                    entries.append(entry)
                except Exception:
                    continue

            total  = len(entries)
            start  = (page - 1) * per_page
            end    = start + per_page
            return {
                "status": True,
                "data": entries[start:end],
                "total": total,
                "page": page,
                "per_page": per_page
            }
        except Exception as e:
            return {"status": False, "msg": str(e)}

    def clear_logs(self, get):
        try:
            with open(self.__log_path, "w", encoding="utf-8") as f:
                f.write("")
            return {"status": True, "msg": "Logs cleared successfully"}
        except Exception as e:
            return {"status": False, "msg": str(e)}

    # =====================================================
    # API: GET STATISTICS (Overview ড্যাশবোর্ডের জন্য)
    # =====================================================
    def _get_stats(self):
        stats = {
            "total_blocked": 0,
            "today_blocked": 0,
            "attack_types":  {},
            "top_ips":       {},
            "top_countries": {},
            "hourly":        [0] * 24
        }
        if not os.path.exists(self.__log_path):
            return stats

        today_str = datetime.now().strftime("%Y-%m-%d")
        try:
            with open(self.__log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                try:
                    entry = json.loads(line.strip())
                    stats["total_blocked"] += 1

                    if entry.get("time", "").startswith(today_str):
                        stats["today_blocked"] += 1
                        hour = int(entry.get("time", "00:00:00 00")[-8:-6])
                        if 0 <= hour < 24:
                            stats["hourly"][hour] += 1

                    atype = entry.get("attack", "Unknown")
                    stats["attack_types"][atype] = stats["attack_types"].get(atype, 0) + 1

                    ip = entry.get("ip", "")
                    if ip:
                        stats["top_ips"][ip] = stats["top_ips"].get(ip, 0) + 1
                except Exception:
                    continue

            # Sort top IPs (top 10)
            stats["top_ips"] = dict(
                sorted(stats["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
            )
        except Exception as e:
            self._write_error(f"Stats error: {e}")

        return stats

    # =====================================================
    # API: TELEGRAM ALERT
    # =====================================================
    def send_telegram_alert(self, ip, attack_type, url, method="GET"):
        conf = self._get_config()
        if not conf.get("telegram_alert"):
            return False
        if not conf.get("telegram_token") or not conf.get("telegram_chat_id"):
            return False
        if requests is None:
            return False

        message = (
            f"🛡️ *NorthWall WAF Alert*\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"⚠️ *Attack:* `{attack_type}`\n"
            f"🌐 *Attacker IP:* `{ip}`\n"
            f"📡 *Method:* `{method}`\n"
            f"🎯 *URL:* `{url}`\n"
            f"⏰ *Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"🔒 _NorthWall WAF by NorthDigits_"
        )

        def send():
            try:
                api_url = f"https://api.telegram.org/bot{conf['telegram_token']}/sendMessage"
                requests.post(api_url, data={
                    "chat_id": conf["telegram_chat_id"],
                    "text": message,
                    "parse_mode": "Markdown"
                }, timeout=5)
            except Exception as e:
                self._write_error(f"Telegram alert failed: {e}")

        threading.Thread(target=send, daemon=True).start()
        return True

    def test_telegram(self, get):
        """UI থেকে টেলিগ্রাম টেস্ট বাটন চাপলে এই ফাংশন কল হবে"""
        conf = self._get_config()
        if not conf.get("telegram_token") or not conf.get("telegram_chat_id"):
            return {"status": False, "msg": "Please set Telegram Bot Token and Chat ID first"}
        
        result = self.send_telegram_alert(
            ip="1.2.3.4",
            attack_type="TEST - SQL Injection",
            url="/test?id=1' OR '1'='1",
            method="GET"
        )
        if result:
            return {"status": True, "msg": "✅ Test alert sent! Check your Telegram."}
        return {"status": False, "msg": "Failed to send test alert. Check token/chat_id."}

    # =====================================================
    # API: INSTALL WAF INTO A SPECIFIC NGINX SITE
    # =====================================================
    def install_to_site(self, get):
        site = str(get.site).strip()
        site_conf = f"/www/server/panel/vhost/nginx/{site}.conf"
        if not os.path.exists(site_conf):
            return {"status": False, "msg": f"Site config not found: {site}.conf"}

        inject_line = f"    access_by_lua_file {self.__lua_waf_path};\n"

        with open(site_conf, "r", encoding="utf-8") as f:
            content = f.read()

        if inject_line.strip() in content:
            return {"status": True, "msg": f"NorthWall WAF is already active on {site}"}

        # 'server {' এর পরে ইনজেক্ট করা
        new_content = content.replace("server {", f"server {{\n{inject_line}", 1)
        with open(site_conf, "w", encoding="utf-8") as f:
            f.write(new_content)

        # Nginx reload
        os.system("nginx -s reload")

        conf = self._get_config()
        if site not in conf["installed_sites"]:
            conf["installed_sites"].append(site)
            self._save_config(conf)

        return {"status": True, "msg": f"✅ NorthWall WAF activated on {site}"}

    def remove_from_site(self, get):
        site = str(get.site).strip()
        site_conf = f"/www/server/panel/vhost/nginx/{site}.conf"
        if not os.path.exists(site_conf):
            return {"status": False, "msg": f"Site config not found: {site}.conf"}

        inject_line = f"    access_by_lua_file {self.__lua_waf_path};\n"

        with open(site_conf, "r", encoding="utf-8") as f:
            content = f.read()

        new_content = content.replace(inject_line, "")
        with open(site_conf, "w", encoding="utf-8") as f:
            f.write(new_content)

        os.system("nginx -s reload")

        conf = self._get_config()
        if site in conf["installed_sites"]:
            conf["installed_sites"].remove(site)
            self._save_config(conf)

        return {"status": True, "msg": f"NorthWall WAF removed from {site}"}

    # =====================================================
    # API: GET ALL NGINX SITES LIST
    # =====================================================
    def get_sites(self, get):
        vhost_path = "/www/server/panel/vhost/nginx/"
        sites = []
        conf = self._get_config()
        try:
            for f in os.listdir(vhost_path):
                if f.endswith(".conf"):
                    site_name = f.replace(".conf", "")
                    sites.append({
                        "name": site_name,
                        "waf_active": site_name in conf.get("installed_sites", [])
                    })
        except Exception as e:
            return {"status": False, "msg": str(e)}
        return {"status": True, "data": sites}

