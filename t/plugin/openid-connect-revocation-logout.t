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

=== TEST 1: logout revokes the presented cookie without rolling it first
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local json = require("toolkit.json")
            local keycloak = require("lib.keycloak")
            local test_admin = require("lib.test_admin").test
            local base = "http://127.0.0.1:" .. ngx.var.server_port

            local code, body = test_admin("/apisix/admin/routes/1", ngx.HTTP_PUT,
                json.encode({
                    uri = "/*",
                    plugins = {
                        ["openid-connect"] = {
                            discovery = "http://127.0.0.1:8080/realms/University/"
                                        .. ".well-known/openid-configuration",
                            client_id = "course_management",
                            client_secret = "d1ec69e9-55d2-4109-a3ea-befa071579d5",
                            redirect_uri = base .. "/authenticated",
                            logout_path = "/signout",
                            ssl_verify = false,
                            session = {
                                secret = "jwcE5v3pM9VhqLxmxFOH9uZaLo8u7KQK",
                                revocation = "redis",
                                revocation_fail_mode = "closed",
                                rolling_timeout = 40,
                                redis = {
                                    host = "127.0.0.1",
                                    port = 6379,
                                    prefix = "oidc:logout:rolling:",
                                },
                            },
                        },
                    },
                    upstream = {
                        nodes = { ["127.0.0.1:1980"] = 1 },
                        type = "roundrobin",
                    },
                }))
            assert(code < 300, body)

            local httpc = http.new()
            local res
            for _ = 1, 50 do
                res = assert(httpc:request_uri(base .. "/signout?from=menu"))
                if res.status == 302 and res.headers.Location
                    and res.headers.Location:find("/protocol/openid-connect/logout", 1, true)
                then
                    break
                end
                ngx.sleep(0.1)
            end
            assert(res.status == 302 and res.headers.Location
                   and res.headers.Location:find("/protocol/openid-connect/logout", 1, true),
                   "route did not become ready")

            -- Missing and invalid cookies still follow the provider logout path.
            for _, cookie in ipairs({"", "session=invalid"}) do
                res = assert(httpc:request_uri(base .. "/signout?from=menu", {
                    headers = {Cookie = cookie},
                }))
                assert(res.status == 302, res.status)
                assert(res.headers.Location:find("/protocol/openid-connect/logout", 1, true),
                       res.headers.Location)
            end

            local err
            local login_started = ngx.now()
            res, err = keycloak.login_keycloak(base .. "/uri", "teacher@gmail.com", "123456")
            assert(res, err)
            local cookie = keycloak.concatenate_cookies(res.headers["Set-Cookie"])
            res = assert(httpc:request_uri(base .. "/uri?next=/signout", {
                headers = {Cookie = cookie},
            }))
            assert(res.status == 200, res.status)

            -- The real clock crosses 75% of the rolling timeout, with nine
            -- seconds left for logout and replay before the original expires.
            ngx.sleep(31)
            res = assert(httpc:request_uri(base .. "/signout?from=menu", {
                headers = {Cookie = cookie},
            }))
            assert(res.status == 302, res.status)
            assert(res.headers.Location:find("/protocol/openid-connect/logout", 1, true),
                   res.headers.Location)

            res = assert(httpc:request_uri(base .. "/uri", {headers = {Cookie = cookie}}))
            assert(ngx.now() - login_started < 38,
                   "the cookie must not expire before its revocation is tested")
            assert(res.status == 302, "cookie replay reached upstream: " .. res.status)
            assert(res.headers.Location:find("/protocol/openid-connect/auth", 1, true),
                   res.headers.Location)
            ngx.say("logout without a valid cookie: 302")
            ngx.say("authenticated: 200")
            ngx.say("replayed after rolling-timeout logout: ", res.status)
        }
    }
--- request
GET /t
--- response_body
logout without a valid cookie: 302
authenticated: 200
replayed after rolling-timeout logout: 302
--- no_error_log
[error]
--- timeout: 60s



=== TEST 2: fail-closed logout preserves the cookie when Redis cannot be reached
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local json = require("toolkit.json")
            local keycloak = require("lib.keycloak")
            local test_admin = require("lib.test_admin").test
            local base = "http://127.0.0.1:" .. ngx.var.server_port
            local route = {
                uri = "/*",
                plugins = {
                    ["openid-connect"] = {
                        discovery = "http://127.0.0.1:8080/realms/University/"
                                    .. ".well-known/openid-configuration",
                        client_id = "course_management",
                        client_secret = "d1ec69e9-55d2-4109-a3ea-befa071579d5",
                        redirect_uri = base .. "/authenticated",
                        ssl_verify = false,
                        session = {
                            secret = "jwcE5v3pM9VhqLxmxFOH9uZaLo8u7KQK",
                            revocation = "redis",
                            revocation_fail_mode = "closed",
                            revocation_cache_ttl = 0,
                            redis = {
                                host = "127.0.0.1",
                                port = 6379,
                                prefix = "oidc:logout:closed:",
                            },
                        },
                    },
                },
                upstream = {
                    nodes = { ["127.0.0.1:1980"] = 1 },
                    type = "roundrobin",
                },
            }
            local function configure(port)
                route.plugins["openid-connect"].session.redis.port = port
                local code, body = test_admin("/apisix/admin/routes/1", ngx.HTTP_PUT,
                                             json.encode(route))
                assert(code < 300, body)
            end
            local httpc = http.new()
            local function wait_status(status, cookie)
                for _ = 1, 50 do
                    local res = assert(httpc:request_uri(base .. "/uri", {
                        headers = {Cookie = cookie},
                    }))
                    if res.status == status then
                        return res
                    end
                    ngx.sleep(0.1)
                end
                error("route did not return " .. status)
            end

            configure(6379)
            local ready
            for _ = 1, 50 do
                local res = assert(httpc:request_uri(base .. "/logout?from=menu"))
                ready = res.status == 302 and res.headers.Location
                        and res.headers.Location:find("/protocol/openid-connect/logout", 1, true)
                if ready then
                    break
                end
                ngx.sleep(0.1)
            end
            assert(ready, "route did not become ready")
            local res, err = keycloak.login_keycloak(base .. "/uri",
                                                    "teacher@gmail.com", "123456")
            assert(res, err)
            local cookie = keycloak.concatenate_cookies(res.headers["Set-Cookie"])
            wait_status(200, cookie)

            -- Only this route points at a closed port; the real Redis service
            -- and other tests' connections remain unchanged.
            configure(1)
            wait_status(503, cookie)
            res = assert(httpc:request_uri(base .. "/logout?from=menu", {
                headers = {Cookie = cookie},
            }))
            assert(res.status == 503, res.status)
            assert(not res.headers["Set-Cookie"], "failed logout must preserve the cookie")
            ngx.say("logout while Redis is unavailable: ", res.status)

            configure(6379)
            wait_status(200, cookie)
            res = assert(httpc:request_uri(base .. "/logout?from=menu", {
                headers = {Cookie = cookie},
            }))
            assert(res.status == 302, res.status)
            res = assert(httpc:request_uri(base .. "/uri", {headers = {Cookie = cookie}}))
            assert(res.status == 302, "cookie replay reached upstream: " .. res.status)
            ngx.say("same cookie after Redis recovers: 200")
            ngx.say("replayed after successful logout: ", res.status)
        }
    }
--- request
GET /t
--- response_body
logout while Redis is unavailable: 503
same cookie after Redis recovers: 200
replayed after successful logout: 302
--- error_log
OIDC session revocation store unavailable
--- timeout: 30s



=== TEST 3: fail-closed logout can retry after Redis write permission is restored
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local json = require("toolkit.json")
            local keycloak = require("lib.keycloak")
            local redis = require("resty.redis")
            local uuid = require("resty.jit-uuid")
            local test_admin = require("lib.test_admin").test
            local base = "http://127.0.0.1:" .. ngx.var.server_port
            local username = "revocation-logout-" .. uuid.generate_v4()
            local password = uuid.generate_v4()
            local prefix = "oidc:logout:acl:" .. username
            local red = redis:new()
            assert(red:connect("127.0.0.1", 6379, {pool = username .. "-admin"}))
            assert(red:acl("SETUSER", username, "reset", "on", ">" .. password,
                           "~" .. prefix .. ":*", "+get", "+select"))

            local ok, err = pcall(function()
                local code, body = test_admin("/apisix/admin/routes/1", ngx.HTTP_PUT,
                    json.encode({
                        uri = "/*",
                        plugins = {
                            ["openid-connect"] = {
                                discovery = "http://127.0.0.1:8080/realms/University/"
                                            .. ".well-known/openid-configuration",
                                client_id = "course_management",
                                client_secret = "d1ec69e9-55d2-4109-a3ea-befa071579d5",
                                redirect_uri = base .. "/authenticated",
                                logout_path = "/acl-signout",
                                ssl_verify = false,
                                session = {
                                    secret = "jwcE5v3pM9VhqLxmxFOH9uZaLo8u7KQK",
                                    revocation = "redis",
                                    revocation_fail_mode = "closed",
                                    revocation_cache_ttl = 0,
                                    redis = {
                                        host = "127.0.0.1",
                                        port = 6379,
                                        prefix = prefix,
                                        username = username,
                                        password = password,
                                        pool = username,
                                        force_auth = true,
                                    },
                                },
                            },
                        },
                        upstream = {
                            nodes = { ["127.0.0.1:1980"] = 1 },
                            type = "roundrobin",
                        },
                    }))
                assert(code < 300, body)

                local httpc = http.new()
                local ready
                for _ = 1, 50 do
                    local res = assert(httpc:request_uri(base .. "/acl-signout"))
                    local location = res.headers.Location or ""
                    ready = res.status == 302
                            and location:find("/protocol/openid-connect/logout", 1, true)
                    if ready then
                        break
                    end
                    ngx.sleep(0.1)
                end
                assert(ready, "route did not become ready")

                local res, login_err = keycloak.login_keycloak(base .. "/uri",
                                                              "teacher@gmail.com", "123456")
                assert(res, login_err)
                local cookie = keycloak.concatenate_cookies(res.headers["Set-Cookie"])
                local request_opts = {headers = {Cookie = cookie}}
                res = assert(httpc:request_uri(base .. "/uri", request_opts))
                assert(res.status == 200, "Redis GET must succeed: " .. res.status)

                -- GET is permitted; only the revocation SET fails at destroy().
                res = assert(httpc:request_uri(base .. "/acl-signout?from=menu", request_opts))
                assert(res.status == 503, res.status)
                assert(not res.headers["Set-Cookie"], "failed logout must preserve the cookie")
                res = assert(httpc:request_uri(base .. "/uri", request_opts))
                assert(res.status == 200, "failed logout must leave the original session usable")

                -- Keep the route and cookie unchanged when the store recovers.
                assert(red:acl("SETUSER", username, "+set"))
                res = assert(httpc:request_uri(base .. "/acl-signout?from=menu", request_opts))
                assert(res.status == 302, res.status)
                assert(res.headers.Location:find("/protocol/openid-connect/logout", 1, true),
                       res.headers.Location)
                res = assert(httpc:request_uri(base .. "/uri", request_opts))
                assert(res.status == 302, "cookie replay reached upstream: " .. res.status)
                assert(res.headers.Location:find("/protocol/openid-connect/auth", 1, true),
                       res.headers.Location)
            end)

            -- Clean up this test's ACL user and keys even if an assertion fails.
            local deleted, delete_err = red:acl("DELUSER", username)
            local keys, keys_err = red:keys(prefix .. ":*")
            if keys then
                for _, key in ipairs(keys) do
                    assert(red:del(key))
                end
            end
            red:close()
            assert(deleted == 1, delete_err or "the dedicated Redis user was not deleted")
            assert(keys, keys_err)
            assert(ok, err)
            ngx.say("logout with Redis GET allowed and SET denied: 503")
            ngx.say("same cookie after failed logout: 200")
            ngx.say("logout after restoring SET: 302")
            ngx.say("replayed after successful logout: 302")
        }
    }
--- request
GET /t
--- response_body
logout with Redis GET allowed and SET denied: 503
same cookie after failed logout: 200
logout after restoring SET: 302
replayed after successful logout: 302
--- error_log
unable to mark session revoked
--- timeout: 30s
