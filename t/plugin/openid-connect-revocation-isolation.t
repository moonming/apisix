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

run_tests();

__DATA__

=== TEST 1: shared cookies do not share revocation failures across route policies
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local json = require("toolkit.json")
            local keycloak = require("lib.keycloak")
            local test_admin = require("lib.test_admin").test
            local base = "http://127.0.0.1:" .. ngx.var.server_port
            local httpc = http.new()

            local function configure(mode, port)
                local code, body = test_admin("/apisix/admin/routes/" .. mode,
                    ngx.HTTP_PUT, json.encode({
                        uri = "/" .. mode .. "/*",
                        plugins = {
                            ["openid-connect"] = {
                                discovery = "http://127.0.0.1:8080/realms/University/"
                                            .. ".well-known/openid-configuration",
                                client_id = "course_management",
                                client_secret = "d1ec69e9-55d2-4109-a3ea-befa071579d5",
                                redirect_uri = base .. "/" .. mode .. "/callback",
                                ssl_verify = false,
                                session = {
                                    secret = "jwcE5v3pM9VhqLxmxFOH9uZaLo8u7KQK",
                                    revocation = "redis",
                                    revocation_fail_mode = mode,
                                    redis = {
                                        host = "127.0.0.1",
                                        port = port,
                                        prefix = "oidc:isolation:",
                                    },
                                },
                            },
                            ["response-rewrite"] = {
                                headers = { ["X-Redis-Port"] = tostring(port) },
                            },
                            ["proxy-rewrite"] = {uri = "/uri"},
                        },
                        upstream = {
                            nodes = { ["127.0.0.1:1980"] = 1 },
                            type = "roundrobin",
                        },
                    }))
                assert(code < 300, body)
            end

            local function wait_route(mode, port)
                for _ = 1, 50 do
                    -- No cookie: this observes config propagation without
                    -- priming the authenticated cookie's revocation cache.
                    local res = assert(httpc:request_uri(base .. "/" .. mode .. "/uri"))
                    if res.headers["X-Redis-Port"] == tostring(port) then
                        return
                    end
                    ngx.sleep(0.1)
                end
                error("route configuration did not propagate: " .. mode)
            end

            configure("open", 6379)
            configure("closed", 6379)
            wait_route("open", 6379)
            wait_route("closed", 6379)
            local res, err = keycloak.login_keycloak(base .. "/open/uri",
                                                    "teacher@gmail.com", "123456")
            assert(res, err)
            local cookie = keycloak.concatenate_cookies(res.headers["Set-Cookie"])
            local function request(mode)
                return assert(httpc:request_uri(base .. "/" .. mode .. "/uri", {
                    headers = {Cookie = cookie},
                }))
            end
            assert(request("open").status == 200)
            assert(request("closed").status == 200)

            -- Point both routes at a closed TCP port; no shared service is stopped.
            configure("open", 1)
            configure("closed", 1)
            wait_route("open", 1)
            wait_route("closed", 1)
            local started = ngx.now()
            res = request("open")
            assert(res.status == 200, res.status)
            ngx.say("open during store failure: ", res.status)
            res = request("closed")
            assert(ngx.now() - started < 5, "the cached failure must still be live")
            assert(res.status == 503, "closed reused an open result: " .. res.status)
            assert(not res.headers["Set-Cookie"], "store failure must preserve the cookie")
            ngx.say("closed with the same cookie: ", res.status)

            configure("closed", 6379)
            wait_route("closed", 6379)
            res = request("closed")
            assert(res.status == 200, res.status)
            ngx.say("same cookie after store recovery: ", res.status)
        }
    }
--- request
GET /t
--- response_body
open during store failure: 200
closed with the same cookie: 503
same cookie after store recovery: 200
--- error_log
OIDC session revocation store unavailable
--- timeout: 30s
