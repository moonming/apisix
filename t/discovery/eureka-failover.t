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
log_level('info');
no_root_location();
no_shuffle();

# 1. Define the Mock Servers (Eureka Nodes + Upstream Service)
add_block_preprocessor(sub {
    my ($block) = @_;

    my $http_config = $block->http_config // <<_EOC_;

    # Mock Eureka Node 1: Unhealthy (Simulates downtime)
    server {
        listen 18761;
        location / {
            return 500 "Internal Error";
        }
    }

    # Mock Eureka Node 2: Healthy
    server {
        listen 18762;
        location /eureka/apps {
            default_type application/json;
            # Return a valid Eureka JSON response registering 'USER-SERVICE'
            return 200 '
            {
              "applications": {
                "application": [
                  {
                    "name": "USER-SERVICE",
                    "instance": [
                      {
                        "app": "USER-SERVICE",
                        "status": "UP",
                        "ipAddr": "127.0.0.1",
                        "hostName": "localhost",
                        "port": { "\\u0024": 18080, "\\u0040enabled": "true" },
                        "securePort": { "\\u0024": 443, "\\u0040enabled": "false" },
                        "metadata": { "weight": "100" }
                      }
                    ]
                  }
                ]
              }
            }';
        }
    }

    # Mock Actual Upstream Service (The target we want to reach)
    server {
        listen 18080;
        location / {
            return 200 "hello from discovered service";
        }
    }
_EOC_

    $block->set_value("http_config", $http_config);
});

our $yaml_config = <<_EOC_;
apisix:
  node_listen: 1984
deployment:
  role: data_plane
  role_data_plane:
    config_provider: yaml
discovery:
  eureka:
    host:
      - "http://127.0.0.1:18761"
      - "http://127.0.0.1:18762"
    prefix: "/eureka/"
    fetch_interval: 1
    weight: 100
    timeout:
      connect: 200
      send: 200
      read: 200
_EOC_

run_tests();

__DATA__

=== TEST 1: Failover to second Eureka node
The test request should succeed because APISIX should skip the 500 error from 18761 and fetch the registry from 18762.

--- yaml_config eval: $::yaml_config
--- apisix_yaml
routes:
  -
    uri: /hello
    upstream:
      service_name: USER-SERVICE
      discovery_type: eureka
      type: roundrobin
#END
--- request
GET /hello
--- response_body
hello from discovered service
--- grep_error_log eval
qr/failed to fetch registry.*|eureka uri:.*18761.*|eureka uri:.*18762.*/
--- grep_error_log_out
failed to fetch registry
eureka uri:http://127.0.0.1:18761/eureka/.
eureka uri:http://127.0.0.1:18762/eureka/.
--- no_error_log
[alert]
