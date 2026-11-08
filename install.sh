#!/bin/bash
# ============================================================
# NorthWall WAF - Git-based Installer for aaPanel
# Author: NorthDigits
# Version: 1.0.0
#
# USAGE:
#   Install:
#     bash <(curl -sL https://raw.githubusercontent.com/YOUR_USERNAME/NorthWall_WAF/main/install.sh) install
#
#   Uninstall:
#     bash /www/server/panel/plugin/northwall_waf/install.sh uninstall
#
#   Update (pull latest from Git):
#     bash /www/server/panel/plugin/northwall_waf/install.sh update
# ============================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# ============================================================
# CONFIGURATION - আপনার GitHub repo URL এখানে দিন
# ============================================================
GIT_REPO="https://github.com/northdigits/NorthWallWAF.git"
GIT_BRANCH="main"
PLUGIN_PATH="/www/server/panel/plugin/northwall_waf"
PANEL_PATH="/www/server/panel"

# ============================================================
# COLORS
# ============================================================
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "${GREEN}✅${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠️ ${NC} $1"; }
error()   { echo -e "${RED}❌${NC} $1"; exit 1; }
info()    { echo -e "${CYAN}ℹ️ ${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}$1${NC}\n$(printf '=%.0s' {1..50})"; }

# ============================================================
# CHECK ROOT
# ============================================================
check_root() {
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root. Use: sudo bash install.sh install"
    fi
}

# ============================================================
# CHECK DEPENDENCIES
# ============================================================
check_deps() {
    header "🔍 Checking Dependencies"

    # git
    if ! command -v git &>/dev/null; then
        warn "git not found. Installing..."
        apt-get install -y git 2>/dev/null || yum install -y git 2>/dev/null
        command -v git &>/dev/null || error "Failed to install git. Please install it manually."
    fi
    log "git is available."

    # python3
    if ! command -v python3 &>/dev/null; then
        warn "python3 not found. Installing..."
        apt-get install -y python3 python3-pip 2>/dev/null || yum install -y python3 python3-pip 2>/dev/null
    fi
    log "python3 is available."

    # pip
    if ! command -v pip3 &>/dev/null; then
        warn "pip3 not found. Installing..."
        apt-get install -y python3-pip 2>/dev/null || yum install -y python3-pip 2>/dev/null
    fi

    # requests (for Telegram alerts)
    python3 -c "import requests" 2>/dev/null || {
        info "Installing Python 'requests' library..."
        pip3 install requests --quiet
    }
    log "Python dependencies OK."

    # nginx
    if ! command -v nginx &>/dev/null; then
        warn "Nginx not found. WAF requires Nginx."
    else
        log "Nginx is available."
        # Check Lua module
        if nginx -V 2>&1 | grep -q "lua"; then
            log "Nginx Lua module detected — full WAF protection enabled."
            echo "LUA_AVAILABLE=true" > "$PLUGIN_PATH/.env" 2>/dev/null
        else
            warn "Nginx Lua module NOT found. Python-level filtering only."
            warn "For full Lua filtering: install nginx-extras or OpenResty."
            echo "LUA_AVAILABLE=false" > "$PLUGIN_PATH/.env" 2>/dev/null
        fi
    fi
}

# ============================================================
# INSTALL
# ============================================================
Install() {
    check_root
    header "🛡️  Installing NorthWall WAF v1.0.0"
    info "Repository: $GIT_REPO"
    info "Branch: $GIT_BRANCH"
    info "Install path: $PLUGIN_PATH"
    echo ""

    # 1. Clone or pull from GitHub
    if [ -d "$PLUGIN_PATH/.git" ]; then
        warn "Existing installation found. Pulling latest changes from Git..."
        cd "$PLUGIN_PATH" && git pull origin "$GIT_BRANCH"
        log "Repository updated."
    else
        info "Cloning NorthWall WAF from GitHub..."
        rm -rf "$PLUGIN_PATH"
        git clone --branch "$GIT_BRANCH" --depth 1 "$GIT_REPO" "$PLUGIN_PATH"
        if [ $? -ne 0 ]; then
            error "Git clone failed. Check your repository URL and internet connection."
        fi
        log "Repository cloned successfully."
    fi

    # 2. Check dependencies
    check_deps

    # 3. Create runtime directories (not in git)
    mkdir -p "$PLUGIN_PATH/logs"
    touch "$PLUGIN_PATH/logs/blocked.log"
    touch "$PLUGIN_PATH/logs/error.log"
    log "Log directories created."

    # 4. Set permissions
    chown -R www:www "$PLUGIN_PATH" 2>/dev/null || \
    chown -R nobody:nobody "$PLUGIN_PATH" 2>/dev/null || \
    chown -R root:root "$PLUGIN_PATH"

    chmod -R 755 "$PLUGIN_PATH"
    chmod 644 "$PLUGIN_PATH"/*.py 2>/dev/null
    chmod 644 "$PLUGIN_PATH"/*.json 2>/dev/null
    chmod 644 "$PLUGIN_PATH"/*.html 2>/dev/null
    chmod 600 "$PLUGIN_PATH/logs/"* 2>/dev/null
    log "Permissions set."

    # 5. Inject Lua WAF into Nginx (if Lua is available)
    setup_nginx_lua

    # 6. Reload aaPanel
    reload_aapanel

    echo ""
    header "🎉 Installation Complete!"
    echo -e "  ${GREEN}NorthWall WAF is now installed.${NC}"
    echo -e "  Open aaPanel → App Store → Installed → ${BOLD}NorthWall WAF${NC}"
    echo ""
    echo -e "  ${CYAN}To update later:${NC}"
    echo -e "  bash $PLUGIN_PATH/install.sh update"
    echo ""
}

# ============================================================
# UPDATE (Git pull + reload)
# ============================================================
Update() {
    check_root
    header "🔄 Updating NorthWall WAF"

    if [ ! -d "$PLUGIN_PATH/.git" ]; then
        error "NorthWall WAF is not installed via Git. Run install first:\nbash install.sh install"
    fi

    # Preserve config.json before update
    CONFIG_BACKUP=""
    if [ -f "$PLUGIN_PATH/config.json" ]; then
        CONFIG_BACKUP=$(cat "$PLUGIN_PATH/config.json")
        log "Config backed up."
    fi

    # Pull latest
    cd "$PLUGIN_PATH"
    git fetch origin
    git reset --hard origin/"$GIT_BRANCH"
    git pull origin "$GIT_BRANCH"

    if [ $? -ne 0 ]; then
        error "Git pull failed. Check your internet connection."
    fi
    log "Code updated from GitHub."

    # Restore config.json
    if [ -n "$CONFIG_BACKUP" ] && [ ! -f "$PLUGIN_PATH/config.json" ]; then
        echo "$CONFIG_BACKUP" > "$PLUGIN_PATH/config.json"
        log "Config restored."
    fi

    # Ensure logs dir exists
    mkdir -p "$PLUGIN_PATH/logs"

    # Reset permissions
    chmod -R 755 "$PLUGIN_PATH"

    # Reload
    reload_aapanel

    log "NorthWall WAF updated to latest version!"
}

# ============================================================
# NGINX LUA SETUP
# ============================================================
setup_nginx_lua() {
    NGINX_CONF="/www/server/nginx/conf/nginx.conf"
    if [ ! -f "$NGINX_CONF" ]; then
        warn "Nginx config not found at $NGINX_CONF. Skipping Lua setup."
        return
    fi

    if nginx -V 2>&1 | grep -q "lua"; then
        LUA_LINE="    lua_package_path '$PLUGIN_PATH/core/lua/?.lua;;'; # NorthWall WAF"
        if ! grep -q "NorthWall WAF" "$NGINX_CONF"; then
            # Insert after 'http {'
            sed -i "s|http {|http {\n${LUA_LINE}|" "$NGINX_CONF"
            log "Lua package path injected into nginx.conf"
            nginx -t 2>/dev/null && nginx -s reload 2>/dev/null && log "Nginx reloaded."
        else
            log "Nginx Lua path already configured."
        fi
    fi
}

# ============================================================
# RELOAD AAPANEL
# ============================================================
reload_aapanel() {
    # Clear aaPanel plugin caches so the new plugin is scanned immediately
    rm -f /www/server/panel/data/plugin.json 2>/dev/null
    rm -f /www/server/panel/data/plugin_bin.json 2>/dev/null
    if [ -f /etc/init.d/bt ]; then
        /etc/init.d/bt reload > /dev/null 2>&1
        /etc/init.d/bt restart > /dev/null 2>&1
        log "aaPanel reloaded & cache refreshed."
    elif command -v bt &>/dev/null; then
        bt reload > /dev/null 2>&1
        bt restart > /dev/null 2>&1
        log "aaPanel reloaded & cache refreshed."
    else
        warn "Could not reload aaPanel automatically. Please restart it manually."
    fi
}

# ============================================================
# UNINSTALL
# ============================================================
Uninstall() {
    check_root
    header "🗑️  Uninstalling NorthWall WAF"

    read -p "Are you sure you want to uninstall NorthWall WAF? (y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { info "Uninstall cancelled."; exit 0; }

    # Remove Lua from nginx.conf
    NGINX_CONF="/www/server/nginx/conf/nginx.conf"
    if grep -q "NorthWall WAF" "$NGINX_CONF" 2>/dev/null; then
        sed -i "/NorthWall WAF/d" "$NGINX_CONF"
        nginx -s reload 2>/dev/null
        log "Removed Lua path from nginx.conf"
    fi

    # Remove WAF from all site configs
    for conf in /www/server/panel/vhost/nginx/*.conf; do
        if grep -q "northwall_waf" "$conf" 2>/dev/null; then
            sed -i "/access_by_lua_file.*northwall_waf/d" "$conf"
            log "Removed WAF from: $(basename $conf)"
        fi
    done
    nginx -s reload 2>/dev/null

    # Remove plugin directory
    rm -rf "$PLUGIN_PATH"
    log "Plugin directory removed."

    reload_aapanel

    log "NorthWall WAF uninstalled successfully."
}

# ============================================================
# ENTRY POINT
# ============================================================
action="${1:-install}"

case "${action}" in
    'install')   Install   ;;
    'update')    Update    ;;
    'uninstall') Uninstall ;;
    *)
        echo ""
        echo -e "${BOLD}NorthWall WAF Installer${NC}"
        echo "Usage: bash install.sh {install|update|uninstall}"
        echo ""
        echo "  install   — Clone from GitHub & install"
        echo "  update    — Pull latest changes from GitHub"
        echo "  uninstall — Remove NorthWall WAF from server"
        echo ""
        exit 1
        ;;
esac
