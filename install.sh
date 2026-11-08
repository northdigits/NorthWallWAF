#!/bin/bash
# ============================================================
# NorthWall WAF - aaPanel Plugin Installer
# Author: NorthDigits
# Version: 1.0.0
# ============================================================
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

PLUGIN_PATH="/www/server/panel/plugin/northwall_waf"
NGINX_MODULES_DIR="/www/server/nginx"
LUA_WAF_CONF="/www/server/nginx/conf/lua_waf.conf"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[NorthWall]${NC} $1"; }
warn()  { echo -e "${YELLOW}[Warning]${NC} $1"; }
error() { echo -e "${RED}[Error]${NC} $1"; }

# ============================================================
# INSTALL
# ============================================================
Install() {
    log "============================================"
    log "   Installing NorthWall WAF v1.0.0"
    log "============================================"

    # 1. Create required directories
    log "Creating directory structure..."
    mkdir -p "$PLUGIN_PATH/logs"
    mkdir -p "$PLUGIN_PATH/core/rules"
    mkdir -p "$PLUGIN_PATH/core/lua"
    chmod -R 755 "$PLUGIN_PATH"
    log "✅ Directories created."

    # 2. Install Python requests library (for Telegram)
    log "Installing Python dependencies..."
    pip3 install requests --quiet 2>/dev/null || pip install requests --quiet 2>/dev/null
    log "✅ Python dependencies installed."

    # 3. Check if Nginx has Lua module support
    log "Checking Nginx Lua support..."
    if nginx -V 2>&1 | grep -q "lua"; then
        log "✅ Nginx Lua module detected."
        NGINX_HAS_LUA=true
    else
        warn "Nginx Lua module not found. Lua-based filtering will be unavailable."
        warn "Install OpenResty or nginx-extras for full WAF functionality."
        NGINX_HAS_LUA=false
    fi

    # 4. If Lua is available, inject WAF into Nginx http block
    if [ "$NGINX_HAS_LUA" = true ]; then
        log "Setting up Lua WAF integration..."
        NGINX_CONF="/www/server/nginx/conf/nginx.conf"
        LUA_INCLUDE="    lua_package_path '$PLUGIN_PATH/core/lua/?.lua;;';"
        
        if ! grep -q "northwall_waf" "$NGINX_CONF" 2>/dev/null; then
            sed -i "s|http {|http {\n    # NorthWall WAF Lua Path\n    ${LUA_INCLUDE}|" "$NGINX_CONF"
            log "✅ Lua path injected into nginx.conf"
        fi
    fi

    # 5. Set correct permissions
    chown -R www:www "$PLUGIN_PATH" 2>/dev/null || chown -R nobody:nobody "$PLUGIN_PATH" 2>/dev/null
    chmod 755 "$PLUGIN_PATH"
    chmod 644 "$PLUGIN_PATH"/*.py
    chmod 644 "$PLUGIN_PATH"/*.json
    chmod 644 "$PLUGIN_PATH"/*.html

    # 6. Reload aaPanel
    log "Reloading aaPanel..."
    if [ -f /etc/init.d/bt ]; then
        /etc/init.d/bt reload > /dev/null 2>&1
        log "✅ aaPanel reloaded."
    fi

    echo ""
    log "============================================"
    log "   NorthWall WAF installed successfully!"
    log "   Open aaPanel → App Store → Installed"
    log "   to find NorthWall WAF plugin."
    log "============================================"
    echo ""
}

# ============================================================
# UNINSTALL
# ============================================================
Uninstall() {
    log "Uninstalling NorthWall WAF..."

    # Remove Lua injection from nginx.conf if present
    NGINX_CONF="/www/server/nginx/conf/nginx.conf"
    if grep -q "northwall_waf" "$NGINX_CONF" 2>/dev/null; then
        sed -i "/northwall_waf/d" "$NGINX_CONF"
        sed -i "/NorthWall WAF Lua Path/d" "$NGINX_CONF"
        log "Removed Lua path from nginx.conf"
        nginx -s reload 2>/dev/null || true
    fi

    # Remove WAF from all site configs
    for conf in /www/server/panel/vhost/nginx/*.conf; do
        if grep -q "northwall_waf" "$conf" 2>/dev/null; then
            sed -i "/access_by_lua_file.*northwall_waf/d" "$conf"
            log "Removed WAF from: $(basename $conf)"
        fi
    done

    # Remove plugin directory
    rm -rf "$PLUGIN_PATH"
    log "Plugin directory removed."

    # Reload aaPanel
    if [ -f /etc/init.d/bt ]; then
        /etc/init.d/bt reload > /dev/null 2>&1
    fi

    log "✅ NorthWall WAF uninstalled successfully."
}

# ============================================================
# ENTRY POINT
# ============================================================
action=$1
case "${action}" in
    'install')   Install   ;;
    'uninstall') Uninstall ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        exit 1
        ;;
esac

