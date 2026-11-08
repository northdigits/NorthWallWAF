-- NorthWall WAF - Nginx Lua Interceptor Engine
-- Author: NorthDigits
-- File: /www/server/panel/plugin/northwall_waf/core/lua/waf.lua

local cjson = require "cjson"
local nw_config_path = "/www/server/panel/plugin/northwall_waf/config.json"
local nw_rules_path  = "/www/server/panel/plugin/northwall_waf/core/rules/filter_rules.json"
local nw_log_path    = "/www/server/panel/plugin/northwall_waf/logs/blocked.log"

-- ========================================
-- HELPER: Read file content
-- ========================================
local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

-- ========================================
-- HELPER: Append to log file
-- ========================================
local function write_log(data)
    local f = io.open(nw_log_path, "a")
    if f then
        f:write(cjson.encode(data) .. "\n")
        f:close()
    end
end

-- ========================================
-- HELPER: Check if IP is in CIDR range
-- ========================================
local function ip_in_cidr(ip, cidr)
    local base_ip, prefix = cidr:match("^([^/]+)/(%d+)$")
    if not base_ip then
        return ip == cidr
    end
    local function ip_to_num(addr)
        local n = 0
        for octet in addr:gmatch("%d+") do
            n = n * 256 + tonumber(octet)
        end
        return n
    end
    local mask = 0xFFFFFFFF - (2^(32 - tonumber(prefix)) - 1)
    return (ip_to_num(ip) & math.floor(mask)) == (ip_to_num(base_ip) & math.floor(mask))
end

-- ========================================
-- MAIN WAF LOGIC
-- ========================================
local function run_waf()
    -- Load config
    local cfg_raw = read_file(nw_config_path)
    if not cfg_raw then return end
    local cfg = cjson.decode(cfg_raw)
    if not cfg or cfg.status ~= true then return end

    local client_ip = ngx.var.remote_addr
    local req_uri   = ngx.var.request_uri
    local req_method = ngx.var.request_method
    local user_agent = ngx.var.http_user_agent or ""

    -- 1. WHITELIST CHECK - whitelisted IPs always pass through
    if cfg.whitelist_ips then
        for _, wip in ipairs(cfg.whitelist_ips) do
            if ip_in_cidr(client_ip, wip) then
                return
            end
        end
    end

    -- 2. BLACKLIST CHECK - block permanently
    if cfg.blacklist_ips then
        for _, bip in ipairs(cfg.blacklist_ips) do
            if ip_in_cidr(client_ip, bip) then
                write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="Blacklist", url=req_uri, method=req_method})
                ngx.exit(444)
                return
            end
        end
    end

    -- Load rules
    local rules_raw = read_file(nw_rules_path)
    if not rules_raw then return end
    local rules = cjson.decode(rules_raw)
    if not rules then return end

    -- 3. SCANNER USER-AGENT DETECTION
    if cfg.scan_defense then
        for _, pattern in ipairs(rules.scanner_agents or {}) do
            if ngx.re.find(user_agent, pattern, "joi") then
                write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="Bad Scanner Bot", url=req_uri, method=req_method, ua=user_agent})
                ngx.exit(403)
                return
            end
        end
    end

    -- 4. SCANNER PATH DETECTION
    if cfg.scan_defense then
        for _, pattern in ipairs(rules.scanner_paths or {}) do
            if ngx.re.find(req_uri, pattern, "joi") then
                write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="Scanner Path", url=req_uri, method=req_method})
                ngx.exit(403)
                return
            end
        end
    end

    -- 5. SQL INJECTION DETECTION (GET params + POST body)
    if cfg.sqli_defense then
        local args = ngx.req.get_uri_args()
        for _, val in pairs(args) do
            if type(val) == "string" then
                for _, pattern in ipairs(rules.sqli or {}) do
                    if ngx.re.find(val, pattern, "joi") then
                        write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="SQL Injection", url=req_uri, method=req_method})
                        ngx.exit(403)
                        return
                    end
                end
            end
        end

        if req_method == "POST" then
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            if body then
                for _, pattern in ipairs(rules.sqli or {}) do
                    if ngx.re.find(body, pattern, "joi") then
                        write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="SQL Injection (POST)", url=req_uri, method=req_method})
                        ngx.exit(403)
                        return
                    end
                end
            end
        end
    end

    -- 6. XSS DETECTION
    if cfg.xss_defense then
        local args = ngx.req.get_uri_args()
        for _, val in pairs(args) do
            if type(val) == "string" then
                for _, pattern in ipairs(rules.xss or {}) do
                    if ngx.re.find(val, pattern, "joi") then
                        write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="XSS", url=req_uri, method=req_method})
                        ngx.exit(403)
                        return
                    end
                end
            end
        end
    end

    -- 7. COMMAND INJECTION DETECTION
    if cfg.sqli_defense then
        for _, pattern in ipairs(rules.cmd_injection or {}) do
            if ngx.re.find(req_uri, pattern, "joi") then
                write_log({time=os.date("%Y-%m-%d %H:%M:%S"), ip=client_ip, attack="Command Injection", url=req_uri, method=req_method})
                ngx.exit(403)
                return
            end
        end
    end

end

-- Run WAF
local ok, err = pcall(run_waf)
if not ok then
    -- Fail open (allow request) but log the error
    local f = io.open("/www/server/panel/plugin/northwall_waf/logs/error.log", "a")
    if f then
        f:write(os.date("%Y-%m-%d %H:%M:%S") .. " WAF Error: " .. tostring(err) .. "\n")
        f:close()
    end
end

