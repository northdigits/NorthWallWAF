# 🛡️ NorthWall WAF — aaPanel Plugin

> **Enterprise-grade Open-Source Web Application Firewall for aaPanel**  
> Author: **NorthDigits** &nbsp;|&nbsp; Version: **1.0.0** &nbsp;|&nbsp; License: **MIT**

---

## ⚡ One-Command Install (from GitHub)

SSH into your aaPanel server and run a single command:

```bash
bash <(curl -sL https://raw.githubusercontent.com/northdigits/NorthWallWAF/main/install.sh) install
```

---

## 🔄 Update to Latest Version

```bash
bash /www/server/panel/plugin/northwall_waf/install.sh update
```

---

## 🗑️ Uninstall

```bash
bash /www/server/panel/plugin/northwall_waf/install.sh uninstall
```

---

## 📦 File Structure

```
northwall_waf/
├── .gitignore
├── info.json                   # aaPanel plugin registration metadata
├── index.html                  # Frontend UI Dashboard
├── northwall_waf_main.py       # Python backend controller (API, alerts, config)
├── install.sh                  # Git-based one-command installer
├── README.md                   # This file
└── core/
    ├── rules/
    │   └── filter_rules.json   # Attack detection regex rule sets
    └── lua/
        └── waf.lua             # Nginx Lua WAF engine (request interceptor)
```

> 📌 `logs/` directory and `config.json` are excluded from Git (see `.gitignore`).  
> They are created automatically on the server during installation.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 💉 **SQL Injection Block** | Detects and blocks SELECT, UNION, DROP, CAST, XP_CMDSHELL and all common SQLi patterns in URL and POST body |
| ⚡ **XSS Protection** | Blocks `<script>` tags, inline event handlers (`onload=`, `onerror=`) and `javascript:` URIs |
| 🤖 **Scanner & Bot Block** | Automatically blocks known malicious bots: Shodan, Censys, Nikto, SQLMap, Nmap, Masscan, Acunetix |
| 📁 **File Inclusion Block** | Blocks LFI/RFI attacks and path traversal attempts (`../../etc/passwd`) |
| 💥 **Command Injection Block** | Detects OS command injection in URL parameters and POST data |
| ✅ **IP Whitelist** | Add trusted IPs or CIDR ranges that always bypass the WAF |
| 🚫 **IP Blacklist** | Permanently block IPs with `444 Connection Closed` (no response sent) |
| 🌊 **CC / Rate Limit Defense** | Limit excessive requests per IP per minute to prevent DDoS/CC attacks |
| 🌐 **Per-site WAF Control** | Enable or disable WAF individually for each Nginx-hosted website |
| 🔔 **Telegram Real-time Alerts** | Instant Telegram notification with attacker IP, attack type and URL when a request is blocked |
| 📊 **Overview Dashboard** | Live stats: total blocked, today's blocked, attack type breakdown chart, top attacking IPs |
| 📄 **Log Viewer** | Paginated, searchable blocked request logs with one-click IP blocking |

---

## ⚙️ Requirements

| Requirement | Status |
|---|---|
| aaPanel (BaoTa Panel) | Required |
| Nginx web server | Required |
| Python 3.x + pip | Required |
| git | Required (auto-installed if missing) |
| OpenResty / nginx-lua module | Optional — enables full Lua-based request filtering |

> Without the Lua module, NorthWall WAF still provides Python-level filtering and all panel features.  
> With the Lua module, every HTTP request is inspected at the Nginx level before it reaches PHP/application.

---

## 🔔 Telegram Alert Setup

1. Open Telegram and start a chat with [@BotFather](https://t.me/BotFather)
2. Send `/newbot` and follow the steps to create a bot — copy your **Bot Token**
3. Send any message to your newly created bot
4. Visit this URL in your browser:
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
5. Find `"chat": {"id": 123456789}` in the response — that number is your **Chat ID**
6. In aaPanel → **NorthWall WAF** → **Telegram Alert** tab, enter the Token and Chat ID, then click **Send Test Alert**

---

## 🛠️ Manual Install (without Git)

If you prefer to upload files manually via SCP:

```bash
# 1. Clone the repository on your local machine
git clone https://github.com/northdigits/NorthWallWAF.git

# 2. Upload to your server via SCP (run from your local machine)
scp -r NorthWallWAF root@YOUR_SERVER_IP:/www/server/panel/plugin/northwall_waf

# 3. Then SSH into the server and run
chmod -R 755 /www/server/panel/plugin/northwall_waf
bash /www/server/panel/plugin/northwall_waf/install.sh install
```

---

## 📋 How the Lua WAF Engine Works

```
Incoming HTTP Request
        │
        ▼
  ┌─────────────────────────────────┐
  │      Nginx (port 80 / 443)      │
  └───────────────┬─────────────────┘
                  │  access_by_lua_file waf.lua
                  ▼
  ┌─────────────────────────────────┐
  │         NorthWall WAF           │
  │  1. Check IP Whitelist          │
  │  2. Check IP Blacklist → 444    │
  │  3. Scanner User-Agent → 403    │
  │  4. Scanner Path → 403          │
  │  5. SQL Injection → 403         │
  │  6. XSS Detection → 403         │
  │  7. Command Injection → 403     │
  └───────────────┬─────────────────┘
                  │  Clean request passes through
                  ▼
  ┌─────────────────────────────────┐
  │    Your Website / Application   │
  └─────────────────────────────────┘
```

---

## 🤝 Contributing

Pull requests and issues are welcome!  
If you find a bug or want to add new attack detection rules, feel free to open an issue or submit a PR.

---

## 📄 License

MIT License — Free to use, modify, and distribute.  
© 2026 NorthDigits
