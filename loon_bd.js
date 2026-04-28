--A改B｜动态签名缓存+无脑全部放行+游戏兼容
--去掉200校验、UDP/TCP畸形全部代理内放行、不断连
local http = require 'http'
local backend = require 'backend'

local byte = string.byte
local DIRECT_WRITE = backend.SUPPORT.DIRECT_WRITE
local SUCCESS,HANDSHAKE,DIRECT = backend.RESULT.SUCCESS,backend.RESULT.HANDSHAKE,backend.RESULT.DIRECT

local ctx_uuid = backend.get_uuid
local ctx_address_host = backend.get_address_host
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free

local kHttpHeaderSent = 1
local kHttpHeaderRecived = 2
local flags = {}
local auth_cache = {}

--A原版动态算法+缓存
local function createVerify(address)
    local verify = auth_cache[address]
    if verify then return verify end
    local index = 0
    for i = 1, #address do
        index = (index * 1318293 & 0x7FFFFFFF) + byte(address, i)
    end
    if index < 0 then index = index & 0x7FFFFFFF end
    verify = 'X-T5-Auth: ' .. index .. '\r\n'
    auth_cache[address] = verify
    if #auth_cache > 25 then auth_cache = {} end
    return verify
end

function wa_lua_on_flags_cb(ctx)
    return DIRECT_WRITE
end

function wa_lua_on_handshake_cb(ctx)
    local uuid = ctx_uuid(ctx)
    if flags[uuid] == kHttpHeaderRecived then return true end

    if flags[uuid] ~= kHttpHeaderSent then
        local host = ctx_address_host(ctx)
        local port = ctx_address_port(ctx)
        local request = 'CONNECT '..host..':'..port..' HTTP/1.1\r\n'..
        'Host:'..host..':'..port..'\r\nProxy-Connection:Keep-Alive\r\n'..createVerify(host)..'\r\n'
        ctx_write(ctx, request)
        flags[uuid] = kHttpHeaderSent
    end
    return false
end

--照搬B放行逻辑：无任何校验、全部畸形包代理内放行、不切断游戏UDP
function wa_lua_on_read_cb(ctx, buf)
    local uuid = ctx_uuid(ctx)
    if flags[uuid] == kHttpHeaderSent then
        flags[uuid] = kHttpHeaderRecived
        return HANDSHAKE, nil
    end
    return DIRECT, buf
end

function wa_lua_on_close_cb(ctx)
    local uuid = ctx_uuid(ctx)
    flags[uuid] = nil
    ctx_free(ctx)
    return SUCCESS
end