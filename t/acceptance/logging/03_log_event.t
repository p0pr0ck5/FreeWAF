use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(3);
plan tests => repeat_each() * 4 * blocks();

my $pwd = cwd();

our $HttpConfig = qq{
	lua_package_path "$pwd/lib/?.lua;$pwd/t/?.lua;;";
	lua_package_cpath "$pwd/lib/?.lua;;";
};

no_shuffle();
run_tests();


__DATA__

=== TEST 1: Do not log a rule with nolog set
--- http_config eval: $::HttpConfig
--- config
	location /t {
		access_by_lua_block {
			local lua_resty_waf = require "resty.waf"
			local waf           = lua_resty_waf:new()

			waf:set_option("debug", true)
			waf:set_option("add_ruleset", "log")
			waf:exec()
		}

		content_by_lua_block {ngx.exit(ngx.HTTP_OK)}

		log_by_lua_block {
			local lua_resty_waf = require "resty.waf"
			local waf           = lua_resty_waf:new()

			waf:write_log_events()
		}
	}
--- request
GET /t?arg=foo
--- more_headers
User-Agent: testy mctesterson
Accept: */*
--- error_code: 200
--- error_log
Not logging a request that had no rule alerts
--- no_error_log
[error]
"alerts":[{"match":"foo","id":"12345"}]

=== TEST 2: Do not log chain rules that are not the chain end
--- http_config eval: $::HttpConfig
--- config
	location /t {
		access_by_lua_block {
			local lua_resty_waf = require "resty.waf"
			local waf           = lua_resty_waf:new()

			waf:set_option("debug", true)
			waf:set_option("add_ruleset", "log")
			waf:exec()
		}

		content_by_lua_block {ngx.exit(ngx.HTTP_OK)}

		log_by_lua_block {
			local lua_resty_waf = require "resty.waf"
			local waf           = lua_resty_waf:new()

			waf:write_log_events()
		}
	}
--- request
GET /t?arg=foo2&otherarg=bar
--- more_headers
User-Agent: testy mctesterson
Accept: */*
--- error_code: 200
--- error_log
"alerts":[{"match":"bar","id":"12346"}]
--- no_error_log
[error]
"match":"foo2","id":"12346"
