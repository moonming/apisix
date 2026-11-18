--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local load_storage = require("resty.session.utils").load_storage
local lrucache = require("resty.lrucache")
local min = math.min
local setmetatable = setmetatable
local now = ngx.now

local _M = {}
local mt = { __index = _M }


function _M:get(name, key, ...)
    local cache_key = name .. ":" .. key
    local entry = self.cache:get(cache_key)
    if entry then
        return entry.data, entry.err
    end

    local generation = self.generation
    local data, err = self.store:get(name, key, ...)
    local ttl = err and self.error_ttl or self.ttl
    -- A lookup that yielded before a write completed must not replace its result.
    if ttl > 0 and generation == self.generation then
        self.cache:set(cache_key, {data = data, err = err}, ttl)
    end
    return data, err
end


function _M:set(name, key, data, ttl, ...)
    local started_at = now()
    local ok, err = self.store:set(name, key, data, ttl, ...)
    self.generation = self.generation + 1

    local cache_key = name .. ":" .. key
    self.cache:delete(cache_key)
    local cache_ttl
    if ok then
        -- The cache must not outlive the revocation record written to Redis.
        cache_ttl = min(self.ttl, ttl - (now() - started_at))
    else
        data = nil
        cache_ttl = self.error_ttl
    end
    if cache_ttl > 0 then
        self.cache:set(cache_key, {data = data, err = err}, cache_ttl)
    end
    return ok, err
end


function _M.new(session_conf)
    return setmetatable({
        store = load_storage("redis", session_conf),
        cache = assert(lrucache.new(1024)),
        ttl = session_conf.revocation_cache_ttl or 5,
        error_ttl = session_conf.revocation_error_cache_ttl or 5,
        generation = 0,
    }, mt)
end


return _M
