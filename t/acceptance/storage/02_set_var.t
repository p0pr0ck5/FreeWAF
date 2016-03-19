use Test::Nginx::Socket::Lua;

repeat_each(3);
plan tests => repeat_each() * 4 * blocks();

no_shuffle();
run_tests();

__DATA__

=== TEST 1: Set a var - confirm the set value
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["COUNT"])
		';
	}
--- request
GET /t
--- error_code: 200
--- response_body
1
--- error_log
Setting FOO:COUNT to 1
--- no_error_log
[error]

=== TEST 2: Set a var - confirm the __altered flag is set
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["__altered"])
		';
	}
--- request
GET /t
--- error_code: 200
--- response_body
true
--- error_log
Setting FOO:COUNT to 1
--- no_error_log
[error]

=== TEST 3: Override an existing value
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }
			local var = require("cjson").encode({ COUNT = 5 })
			local shm = ngx.shared[fw._storage_zone]
			shm:set("FOO", var)

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["COUNT"])
		';
	}
--- request
GET /t
--- error_code: 200
--- response_body
1
--- error_log
Setting FOO:COUNT to 1
--- no_error_log
[error]

=== TEST 4: Increment an existing value
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }
			local var = require("cjson").encode({ COUNT = 5 })
			local shm = ngx.shared[fw._storage_zone]
			shm:set("FOO", var)

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1, inc = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["COUNT"])
		';
	}
--- request
GET /t
--- error_code: 200
--- response_body
6
--- error_log
Setting FOO:COUNT to 6
--- no_error_log
[error]

=== TEST 5: Increment an non-existing value
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }
			local var = require("cjson").encode({ blah = 5 })
			local shm = ngx.shared[fw._storage_zone]
			shm:set("FOO", var)

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1, inc = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["COUNT"])
		';
	}
--- request
GET /t
--- error_code: 200
--- response_body
1
--- error_log
Incrementing a non-existing value
Setting FOO:COUNT to 1
--- no_error_log
[error]

=== TEST 6: Fail to increment a non-numeric value
--- http_config
	lua_shared_dict store 10m;
	init_by_lua '
		local FreeWAF = require "fw"
		FreeWAF.default_option("storage_zone", "store")
		FreeWAF.default_option("debug", true)
	';
--- config
    location = /t {
        access_by_lua '
			local FreeWAF = require "fw"
			local fw      = FreeWAF:new()

			local ctx = { storage = {}, col_lookup = { FOO = "FOO" } }
			local var = require("cjson").encode({ COUNT = "blah" })
			local shm = ngx.shared[fw._storage_zone]
			shm:set("FOO", var)

			local storage = require "lib.storage"
			storage.initialize(fw, ctx.storage, "FOO")

			local element = { col = "FOO", key = "COUNT", value = 1, inc = 1 }
			storage.set_var(fw, ctx, element, element.value)

			ngx.ctx = ctx.storage["FOO"]
		';

		content_by_lua '
			ngx.say(ngx.ctx["COUNT"])
		';
	}
--- request
GET /t
--- error_code: 500
--- error_log
Cannot increment a value that was not previously a number
--- no_error_log
Setting FOO:COUNT to 6
