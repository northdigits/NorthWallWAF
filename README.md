# NorthWall WAF — aaPanel Plugin

> 🛡️ Enterprise-grade Open-Source Web Application Firewall for aaPanel  
> **Author:** NorthDigits | **Version:** 1.0.0

---

## 📦 File Structure

```
northwall_waf/
├── info.json                   # Plugin metadata for aaPanel
├── index.html                  # Frontend UI Dashboard
├── northwall_waf_main.py       # Python backend controller
├── install.sh                  # One-click install/uninstall script
├── README.md                   # This file
├── logs/
│   ├── blocked.log             # All blocked requests (JSON lines)
│   └── error.log               # WAF internal errors
└── core/
    ├── rules/
    │   └── filter_rules.json   # SQLi, XSS, Scanner, CMDi regex patterns
    └── lua/
        └── waf.lua             # Nginx Lua WAF engine
```

---

## 🚀 Features

| Feature | Description |
|---|---|
| 💉 SQL Injection | Blocks SELECT, UNION, DROP, CAST, XP_CMDSHELL, etc. |
| ⚡ XSS Protection | Detects script tags, event handlers, javascript: URIs |
| 🤖 Scanner Block | Blocks Shodan, Censys, Nikto, SQLMap, Nmap bots |
| 📁 File Inclusion | Blocks LFI/RFI and path traversal (../../etc/passwd) |
| 💥 CMD Injection | Detects OS command injection attempts |
| ✅ IP Whitelist | CIDR/IP whitelist — always passes through WAF |
| 🚫 IP Blacklist | Permanently blocks with 444 Connection Closed |
| 🌊 CC Defense | Rate limiting per IP per minute |
| 🌐 Per-site Control | Enable/disable WAF per individual Nginx site |
| 🔔 Telegram Alerts | Instant notification on attack block |
| 📊 Dashboard | Overview with stats, charts, top attacking IPs |
| 📄 Log Viewer | Paginated, searchable blocked request logs |

---

## 🔧 Server-side Installation

SSH into your server and run:

```bash
# Upload plugin to server
scp -r NorthWall_WAF root@your_server_ip:/www/server/panel/plugin/northwall_waf

# Run installer
bash /www/server/panel/plugin/northwall_waf/install.sh install
```

---

## ⚙️ Requirements

- aaPanel (BaoTa Panel) installed
- Nginx web server
- Python 3.x
- (Optional) OpenResty or nginx-lua module for Lua-based filtering

---

## 🔔 Telegram Setup

1. Create a bot from [@BotFather](https://t.me/BotFather)
2. Copy your **Bot Token**
3. Send any message to your bot
4. Visit `https://api.telegram.org/bot<TOKEN>/getUpdates` to get **Chat ID**
5. Enter both in **NorthWall WAF → Telegram Alert** tab

---

## 📄 License

MIT License — Free to use, modify, and distribute.

# NorthWallWAF
