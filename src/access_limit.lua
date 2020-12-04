local config = require "config"
local _M = {}
local log = ngx.log
local ERR = ngx.ERR

function ipToDecimal(ckip)
    local n = 4
    local decimalNum = 0
    local pos = 0
    for s, e in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        decimalNum = decimalNum + string.sub(ckip, pos, s-1) * (256 ^ n)
        pos = e + 1
        if n == 1 then decimalNum = decimalNum + string.sub(ckip, pos, string.len(ckip)) end
    end
    return decimalNum
end

function whiteip()
    local headers = ngx.req.get_headers()
    local cIP = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
    local red=open_redis()
    local redisRes=red:get("allowList")
    local ipWhitelist={redisRes}
    if next(ipWhitelist) ~= nil then
        local numIP = 0
        if cIP ~= "unknown" then numIP = tonumber(ipToDecimal(cIP))  end
        for _,ip in pairs(ipWhitelist) do
            local s, e = string.find(ip, '-', 0, true)
            if s == nil and cIP == ip then
                return true
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                   return true
                end
            end
        end
    end
    return false
end


function open_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000) -- 1 sec
    local ok, err = red:connect(config["redis_host"], config["redis_port"])
    if not ok then
        log(ERR, "failed to connect: ", err)
    end
    return red, err
end

function return_redis(red)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle time
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        log(ERR, "failed to set keepalive: ", err)
        return
    end
end

function _M.checkIp()
    if whiteip()==false then
        ngx.exit(403)
    end
end

function _M.checkAccessLimit(uri, uriSeconds, uriTimes, ipUriSeconds, ipUriTimes)

    
    if uriSeconds == 0 and ipUriSeconds == 0 then
        return
    end

    local red, err = open_redis()
    if err then
        return
    end

    -- 针对整个接口限流
    if uriSeconds > 0 then
        local value, _ = red:get(uri)
        if value == ngx.null then
            red:setex(uri, uriSeconds, 1)
        else
            local count = tonumber(value)
            if count >= uriTimes then
                return_redis(red)
                ngx.exit(403)
            end
            red:incr(uri)
        end
    end

    -- 针对IP接口限流
    if ipUriSeconds > 0 then
        local headers = ngx.req.get_headers()
        local ip = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or "0.0.0.0"
        local value, _ = red:get(ip .. uri)
        if value ~= ngx.null then
            local count = tonumber(value)
            if count >= ipUriTimes then
                return_redis(red)
                ngx.exit(403)
            end
            red:incr(ip .. uri)
        else
            red:setex(ip .. uri, ipUriSeconds, 1)
        end
    end

    return_redis(red)
end

return _M