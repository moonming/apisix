#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

use t::APISIX 'no_plan';

repeat_each(1);
no_long_string();
no_root_location();

add_block_preprocessor(sub {
    my ($block) = @_;
    $block->set_value("request", "GET /t");
    if (!defined $block->error_log) {
        $block->set_value("no_error_log", "[error]");
    }
});

run_tests();

__DATA__

=== TEST 1: cache Redis misses and update the same Redis key on revocation
--- config
    location /t {
        content_by_lua_block {
            local backend = require("apisix.plugins.openid-connect.revocation").new({
                redis = {host = "127.0.0.1", port = 6379, prefix = "oidc-store"},
            })
            local key = require("apisix.core").utils.generate_uuid_v4()
            local get = backend.store.get
            local lookups = 0
            backend.store.get = function(self, ...)
                lookups = lookups + 1
                return get(self, ...)
            end

            for _ = 1, 2 do
                local data, err = backend:get("session", key)
                assert(data == nil and err == nil, err)
            end
            assert(lookups == 1)
            assert(backend:set("session", key, "1", 30, ngx.time()))
            assert(backend:get("session", key) == "1")
            assert(lookups == 1)
            assert(get(backend.store, "session", key) == "1")
            assert(backend.store:delete("session", key, ngx.time()))
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 2: separate Redis namespaces cannot reuse another backend's cached miss
--- config
    location /t {
        content_by_lua_block {
            local revocation = require("apisix.plugins.openid-connect.revocation")
            local key = require("apisix.core").utils.generate_uuid_v4()
            local first = revocation.new({
                redis = {host = "127.0.0.1", port = 6379, prefix = "oidc-store-a"},
            })
            local second = revocation.new({
                redis = {host = "127.0.0.1", port = 6379, prefix = "oidc-store-b"},
            })

            assert(second.store:set("session", key, "1", 30, ngx.time()))
            local data, err = first:get("session", key)
            assert(data == nil and err == nil, err)
            assert(second:get("session", key) == "1")
            assert(first:get("session", key) == nil)
            assert(second.store:delete("session", key, ngx.time()))
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 3: cache real connection errors and replace stale misses after failed writes
--- config
    location /t {
        content_by_lua_block {
            local revocation = require("apisix.plugins.openid-connect.revocation")
            local key = require("apisix.core").utils.generate_uuid_v4()
            local backend = revocation.new({
                redis = {host = "127.0.0.1", port = 6379},
            })
            local data, err = backend:get("session", key)
            assert(data == nil and err == nil, err)
            backend.store.port = 1
            local ok, write_err = backend:set("session", key, "1", 30, ngx.time())
            -- APISIX disables cosocket error logs; inspect the actual Redis error.
            assert(not ok and write_err and write_err:find("connection refused", 1, true), write_err)
            backend.store.port = 6379
            data, err = backend:get("session", key)
            assert(data == nil and err == write_err)

            for _, error_ttl in ipairs({5, 0}) do
                local failed = revocation.new({
                    redis = {host = "127.0.0.1", port = 1},
                    revocation_error_cache_ttl = error_ttl,
                })
                local _, read_err = failed:get("session", key)
                assert(read_err and read_err:find("connection refused", 1, true), read_err)
                failed.store.port = 6379
                data, err = failed:get("session", key)
                assert(data == nil)
                assert(err == (error_ttl > 0 and read_err or nil))
            end
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 4: a successful write cannot cache a revocation beyond its Redis TTL
--- config
    location /t {
        content_by_lua_block {
            local backend = require("apisix.plugins.openid-connect.revocation").new({
                redis = {host = "127.0.0.1", port = 6379, prefix = "oidc-store"},
                revocation_cache_ttl = 5,
            })
            local key = require("apisix.core").utils.generate_uuid_v4()
            local set = backend.store.set
            backend.store.set = function(self, ...)
                local ok, err = set(self, ...)
                ngx.sleep(1)
                return ok, err
            end
            assert(backend:set("session", key, "1", 2, ngx.time()))
            ngx.sleep(1.1)
            local data, err = backend:get("session", key)
            assert(data == nil and err == nil, err)
            ngx.say("done")
        }
    }
--- response_body
done



=== TEST 5: an in-flight Redis miss cannot overwrite a completed revocation
--- config
    location /t {
        content_by_lua_block {
            local backend = require("apisix.plugins.openid-connect.revocation").new({
                redis = {host = "127.0.0.1", port = 6379, prefix = "oidc-store"},
            })
            local key = require("apisix.core").utils.generate_uuid_v4()
            local semaphore = require("ngx.semaphore")
            local read_complete = semaphore.new()
            local resume_read = semaphore.new()
            local get = backend.store.get
            backend.store.get = function(self, ...)
                local data, err = get(self, ...)
                read_complete:post()
                assert(resume_read:wait(5))
                return data, err
            end

            local thread = ngx.thread.spawn(function()
                return backend:get("session", key)
            end)
            assert(read_complete:wait(5))
            assert(backend:set("session", key, "1", 30, ngx.time()))
            resume_read:post()
            local ok, data, err = ngx.thread.wait(thread)
            assert(ok and data == nil and err == nil, err)
            assert(backend:get("session", key) == "1")
            assert(backend.store:delete("session", key, ngx.time()))
            ngx.say("done")
        }
    }
--- response_body
done
