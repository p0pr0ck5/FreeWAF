local _M = {}

local actions       = require "resty.waf.actions"
local base          = require "resty.waf.base"
local calc          = require "resty.waf.rule_calc"
local collections_t = require "resty.waf.collections"
local logger        = require "resty.waf.log"
local operators     = require "resty.waf.operators"
local options       = require "resty.waf.options"
local phase_t       = require "resty.waf.phase"
local random        = require "resty.waf.random"
local storage       = require "resty.waf.storage"
local transform_t   = require "resty.waf.transform"
local translate     = require "resty.waf.translate"
local util          = require "resty.waf.util"
local table_insert = table.insert
local table_sort   = table.sort
local string_lower = string.lower

local ngx_INFO = ngx.INFO
local ngx_HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN

local ok, tab_new = pcall(require, "table.new")
if not ok then
	tab_new = function(narr, nrec) return {} end
end

local mt = { __index = _M }

_M.version = base.version

-- default list of rulesets
local _global_rulesets = {
	"11000_whitelist",
	"20000_http_violation",
	"21000_http_anomaly",
	"35000_user_agent",
	"40000_generic_attack",
	"41000_sqli",
	"42000_xss",
	"90000_custom",
	"99000_scoring"
}
_M.global_rulesets = _global_rulesets

-- ruleset table cache
local _ruleset_defs = {}
local _ruleset_def_cnt = 0

-- lookup tables for msg and tag exceptions
-- public so it can be accessed via metatable
_M._meta_exception = {
	msgs = {},
	tags = {},
	meta_ids = {},
}

-- this function runs when a new ruleset has been introduced to
-- _ruleset_defs. it reads over all the rules, looking for msg and tag
-- elements, and building a lookup table for exceptions
local function _build_exception_table()
	-- build a rule.id -> { rule.id, ... } lookup table based on the exception
	-- action for the rule

	for r, ruleset in pairs(_ruleset_defs) do
		for phase, rules in pairs(ruleset) do
			for i, rule in ipairs(rules) do
				util.rule_exception(_M._meta_exception, rule)
			end
		end
	end
end

-- get a subset or superset of request data collection
local function _parse_collection(self, collection, var)
	local parse = var.parse

	if type(collection) ~= "table" and parse then
		-- if a collection isn't a table it can't be parsed,
		-- so we shouldn't return the original collection as
		-- it may have an illegal operator called on it
		return nil
	end

	if type(collection) ~= "table" or not parse then
		-- this collection isnt parseable but it's not unsafe to use
		return collection
	end

	local key   = parse[1]--"all"
	local value = parse[2]-- 1

	-- if this var has an ignore, we need to copy this collection table
	-- as we're going to be removing some of its elements, so we can no
	-- longer use it simply as a reference
	if var.ignore then
		local collection_copy = util.table_copy(collection)

		for _, ignore in ipairs(var.ignore) do
			local ikey   = ignore[1]
			local ivalue = ignore[2]

			util.sieve_collection[ikey](self, collection_copy, ivalue)
		end

		return util.parse_collection[key](self, collection_copy, value)
	end

	-- since we didn't have to ignore, we can just parse the collection
	-- based on the parse key (specific, keys, values, etc)
	return util.parse_collection[key](self, collection, value)
end

-- buffer a single log event into the per-request ctx table
-- all event logs will be written out at the completion of the transaction if either:
-- 1. the transaction was altered (e.g. a rule matched with an ACCEPT or DENY action), or
-- 2. the event_log_altered_only option is unset
local function _log_event(self, rule, value, ctx, match_var, match_var_name)
	local t = {
		id    = rule.id,
		match = value,
		match_var = match_var,
		match_var_name= match_var_name,
	}

	if rule.msg then
		t.msg = util.parse_dynamic_value(self, rule.msg, ctx.collections)
	end

	if rule.logdata then
		t.logdata = util.parse_dynamic_value(self, rule.logdata, ctx.collections)
	end

	ctx.log_entries_n = ctx.log_entries_n + 1
	ctx.log_entries[ctx.log_entries_n] = t
end

local function _transaction_id_header(self, ctx)
	-- upstream request header
	if self._req_tid_header then
		ngx.req.set_header("X-Lua-Resty-WAF-ID", self.transaction_id)
	end

	-- downstream response header
	if self._res_tid_header then
		ngx.header["X-Lua-Resty-WAF-ID"] = self.transaction_id
	end

	ctx.t_header_set = true
end

-- cleanup
local function _finalize(self, ctx)
	-- set X-Lua-Resty-WAF-ID headers as appropriate
	if not ctx.t_header_set then
		_transaction_id_header(self, ctx)
	end

	-- save our options for the next phase
	ctx.opts = self

	-- persistent variable storage
	storage.persist(self, ctx.storage)

	-- store the local copy of the ctx table
	ngx.ctx.lua_resty_waf = ctx

	if ctx.phase == 'log' then
		self:write_log_events(true, ctx)
	end
end

-- use the lookup table to figure out what to do
local function _rule_action(self, action, ctx, collections)
	if not action then
		return
	end

	if util.table_has_key(action, actions.alter_actions) then
		ctx.altered = true
		_finalize(self, ctx)
	end

	if self._hook_actions[action] then
		self._hook_actions[action](self, ctx)
	else
		actions.disruptive_lookup[action](self, ctx)
	end
end

-- transform collection values based on rule opts
local function _do_transform(self, collection, transform)
	local t = {}

	if type(transform) == "table" then
		t = collection

		for k, v in ipairs(transform) do
			t = _do_transform(self, t, transform[k])
		end
	else
		-- if the collection is a table, loop through it and add the values to the tmp table
		-- otherwise, this returns directly to _process_rule or a recursed call from multiple transforms
		if type(collection) == "table" then
			for k, v in pairs(collection) do
				t[k] = _do_transform(self, collection[k], transform)
			end
		else
			if not collection then
				return collection -- dont transform if the collection was nil, i.e. a specific arg key dne
			end

			if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "doing transform of type " .. transform .. " on collection value " .. tostring(collection)) end
			return transform_t.lookup[transform](self, collection)
		end
	end

	return t
end

local function _build_collection(self, rule, var, collections, ctx, opts)
	if var.unconditional then
		return true
	end

	local collection_key = var.collection_key
	local collection

	if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Checking for collection_key " .. collection_key) end

	if not var.storage and not ctx.transform_key[collection_key] then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Collection cache miss") end
		collection = _parse_collection(self, collections[var.type], var)

		if opts.transform then
			collection = _do_transform(self, collection, opts.transform)
		end

		ctx.transform[collection_key]     = collection
		ctx.transform_key[collection_key] = true
	elseif var.storage then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Forcing cache miss") end
		collection = _parse_collection(self, collections[var.type], var)
	else
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Collection cache hit!") end
		collection = ctx.transform[collection_key]
	end

	if var.length then
		if type(collection) == 'table' then
			collection = #collection
		elseif(collection) then
			collection = 1
		else
			collection = 0
		end
	end

	return collection
end

-- process an individual rule
local function _process_rule(self, rule, collections, ctx)
	local opts    = rule.opts or {}
	local pattern = rule.pattern
	local offset  = rule.offset_nomatch

	ctx.id = rule.id

	ctx.rule_status = nil

	for k, v in ipairs(rule.vars) do
		local var

		if self.target_update_map[rule.id] then
			var = self.target_update_map[rule.id][k]
		else
			var = rule.vars[k]
		end

		local collection = _build_collection(self, rule, var, collections, ctx, opts)
		if not collection then
			if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "No values for this collection") end
			offset = rule.offset_nomatch
		else
			if opts.parsepattern then
				if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Parsing dynamic pattern: " .. pattern) end
				pattern = util.parse_dynamic_value(self, pattern, collections)
			end

			local match, value, match_var

			if var.unconditional then
				match = true
				value = 1
			else
				match, value, match_var = operators.lookup[rule.operator](self, collection, pattern, ctx)
			end

			if rule.op_negated then
				match = not match
			end

			if match then
				if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Match of rule " .. rule.id) end

				-- store this match as the most recent match
				collections.MATCHED_VAR      = value or ''
				collections.MATCHED_VAR_NAME = var.type
				-- also add the match to our list of matches for the transaction
				if value then
					local match_n = ctx.match_n + 1
					collections.MATCHED_VARS[match_n] = value
					collections.MATCHED_VAR_NAMES[match_n] = var
					ctx.match_n = match_n
				end

				-- auto populate collection elements
				if not rule.op_negated then
					if rule.operator == "REGEX" then
						collections.TX["0"] = value[0]
						for i in ipairs(value) do
							collections.TX[tostring(i)] = value[i]
						end
					else
						collections.TX["0"] = value
					end
				end
				collections.RULE = rule

				local nondisrupt = rule.actions.nondisrupt or {}
				for _, action in ipairs(nondisrupt) do
					actions.nondisruptive_lookup[action.action](self, action.data, ctx, collections)
				end

				-- log the event
				if rule.actions.disrupt ~= "CHAIN" and not opts.nolog then

					_log_event(self, rule, value, ctx, match_var, collections.MATCHED_VAR_NAME)
				end

				-- wrapper for the rules action
				_rule_action(self, rule.actions.disrupt, ctx, collections)

				offset = rule.offset_match

				break
			else
				offset = rule.offset_nomatch
			end
		end
	end

	if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Returning offset " .. tostring(offset)) end
	return offset
end

-- calculate rule jump offsets
local function _calculate_offset(ruleset)
	for phase, i in pairs(phase_t.phases) do
		if ruleset[phase] then
			calc.calculate(ruleset[phase], _M._meta_exception)
		else
			ruleset[phase] = {}
		end
	end
end

-- merge the default and any custom rules
local function _merge_rulesets(self)
	local default = _global_rulesets
	local t = {}

	for k, v in ipairs(default) do
		t[v] = true
	end

	local rebuild_exception_table = false

	if self then
		local added   = self._add_ruleset
		local added_s = self._add_ruleset_string
		local ignored = self._ignore_ruleset

		for k, v in ipairs(added) do
			if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Adding ruleset " .. v) end
			t[v] = true
		end

		for k, v in pairs(added_s) do
			if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Adding ruleset string " .. k) end

			if not _ruleset_defs[k] then
				local rs, err = util.parse_ruleset(v)

				if err then
					logger.fatal_fail("Could not load " .. k)
				else
					if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Doing offset calculation of " .. k) end
					_calculate_offset(rs)

					_ruleset_defs[k] = rs
					_ruleset_def_cnt = _ruleset_def_cnt + 1

					rebuild_exception_table = true
				end
			end

			t[k] = true
		end

		for k, v in ipairs(ignored) do
			if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Ignoring ruleset " .. v) end
			t[v] = nil
		end
	end

	if rebuild_exception_table then _build_exception_table() end

	t = util.table_keys(t)

	-- rulesets will be processed in numeric order
	table_sort(t)

	self._active_rulesets = t
end

-- main entry point
function _M.exec(self, opts)
	if self._mode == "INACTIVE" then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Operational mode is INACTIVE, not running") end
		return
	end

	opts = opts or {}

	local phase = opts.phase or ngx.get_phase()

	if not phase_t.is_valid_phase(phase) then
		logger.fatal_fail("lua-resty-waf should not be run in phase " .. phase)
	end

	local ctx         = ngx.ctx.lua_resty_waf or tab_new(0, 20)
	local collections = ctx.collections or tab_new(0, 41)

	ctx.lrw_initted   = true
	ctx.col_lookup    = ctx.col_lookup or tab_new(0, 3)
	ctx.log_entries   = ctx.log_entries or {}
	ctx.log_entries_n = ctx.log_entries_n or 0
	ctx.storage       = ctx.storage or {}
	ctx.transform     = ctx.transform or {}
	ctx.transform_key = ctx.transform_key or {}
	ctx.t_header_set  = ctx.t_header_set or false
	ctx.phase         = phase
	ctx.match_n       = ctx.match_n or 0
	ctx.nameservers   = self._nameservers

	-- pre-initialize the TX collection
	ctx.storage["TX"]    = ctx.storage["TX"] or {}
	ctx.col_lookup["TX"] = "TX"

	-- see https://groups.google.com/forum/#!topic/openresty-en/LVR9CjRT5-Y
	-- also https://github.com/p0pr0ck5/lua-resty-waf/issues/229
	if ctx.altered == true and self._mode == 'ACTIVE' then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Transaction was already altered, not running!") end

		if phase == 'log' then
			self:write_log_events(true, ctx)
		end

		return
	end

	-- populate the collections table
	if opts.collections then
		for k, v in pairs(opts.collections) do
			collections[k] = v
		end
	else
		collections_t.lookup[phase](self, collections, ctx)
	end

	-- don't run through the rulesets if we're going to be here again
	-- (e.g. multiple chunks are going through body_filter)
	if ctx.short_circuit then return end

	for i = 1, self.var_count do
		local data  = self.var[i]
		local value = util.parse_dynamic_value(self, data.value, collections)

		storage.set_var(self, ctx, data, value)
	end

	-- store the collections table in ctx, which will get saved to ngx.ctx
	ctx.collections = collections

	-- build rulesets
	if self.need_merge == true then
		_merge_rulesets(self)
	else
		self._active_rulesets = _global_rulesets
	end

	-- set up tracking tables and flags if we're using redis for persistent storage
	if self._storage_backend == 'redis' then
		self._storage_redis_delkey_n = 0
		self._storage_redis_setkey_t = false
		self._storage_redis_delkey   = {}
		self._storage_redis_setkey   = {}
	end

	if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Beginning run of phase " .. phase) end

	for _, ruleset in ipairs(self._active_rulesets) do
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Beginning ruleset " .. ruleset) end

		local rs = _ruleset_defs[ruleset]

		if not rs then
			local err
			rs, err = util.load_ruleset_file(ruleset)

			if err then
				logger.fatal_fail(err)
			else
				if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Doing offset calculation of " .. ruleset) end
				_calculate_offset(rs)

				_ruleset_defs[ruleset] = rs
				_ruleset_def_cnt = _ruleset_def_cnt + 1

				_build_exception_table()
			end
		end

		local offset = 1
		local rule   = rs[phase][offset]

		while rule do
			if not util.table_has_key(rule.id, self._ignore_rule) then
				if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Processing rule " .. rule.id) end

				local returned_offset = _process_rule(self, rule, collections, ctx)
				if returned_offset then
					offset = offset + returned_offset
				else
					offset = nil
				end
			else
				if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Ignoring rule " .. rule.id) end

				local rule_nomatch = rule.offset_nomatch

				if rule_nomatch then
					offset = offset + rule_nomatch
				else
					offset = nil
				end
			end

			if not offset then break end

			rule = rs[phase][offset]
		end
	end

	_finalize(self, ctx)
end

-- instantiate a new instance of the module
function _M.new()
	local ctx = ngx.ctx.lua_resty_waf or tab_new(0, 21)

	-- restore options and self from a previous phase
	if ctx.opts then
		return setmetatable(ctx.opts, mt)
	end

	-- we're new to this transaction get us some opts and get movin!
	local t = {
		_add_ruleset                 = {},
		_add_ruleset_string          = {},
		_allow_unknown_content_types = false,
		_allowed_content_types       = {},
		_debug                       = false,
		_debug_log_level             = ngx_INFO,
		_deny_status                 = ngx_HTTP_FORBIDDEN,
		_event_log_altered_only      = true,
		_event_log_buffer_size       = 4096,
		_event_log_level             = ngx_INFO,
		_event_log_ngx_vars          = {},
		_event_log_periodic_flush    = nil,
		_event_log_request_arguments = false,
		_event_log_request_body      = false,
		_event_log_request_headers   = false,
		_event_log_ssl               = false,
		_event_log_ssl_sni_host      = nil,
		_event_log_ssl_verify        = false,
		_event_log_socket_proto      = 'udp',
		_event_log_target            = 'error',
		_event_log_target_host       = nil,
		_event_log_target_path       = nil,
		_event_log_target_port       = nil,
		_event_log_verbosity         = 1,
		_hook_actions                = {},
		_ignore_rule                 = {},
		_ignore_ruleset              = {},
		_mode                        = 'SIMULATE',
		_nameservers                 = {},
		_pcre_flags                  = 'oij',
		_process_multipart_body      = true,
		_req_tid_header              = false,
		_res_body_max_size           = (1024 * 1024),
		_res_body_mime_types         = { ["text/plain"] = true, ["text/html"] = true },
		_res_tid_header              = false,
		_score_threshold             = 5,
		_storage_backend             = 'dict',
		_storage_keepalive           = true,
		_storage_keepalive_pool_size = 100,
		_storage_keepalive_timeout   = 10000,
		_storage_memcached_host      = '127.0.0.1',
		_storage_memcached_port      = 11211,
		_storage_redis_host          = '127.0.0.1',
		_storage_redis_port          = 6379,
		_storage_zone                = nil,
		target_update_map            = {},
		transaction_id               = random.random_bytes(10),
		var_count                    = 0,
		var                          = {},
	}

	if _ruleset_def_cnt == 0 then
		t.need_merge = true
	else
		t.need_merge = false
	end

	return setmetatable(t, mt)
end

function _M.set_var(self, key, value)
	local data = {
		col   = "TX",
		key   = key,
		value = value,
	}

	self.var_count = self.var_count + 1
	self.var[self.var_count] = data
end

-- configuraton wrapper for per-instance options
function _M.set_option(self, option, value, data)
	if type(value) == "table" then
		for _, v in ipairs(value) do
			_M.set_option(self, option, v, data)
		end
	else
		if options.lookup[option] then
			options.lookup[option](self, value, data)
		else
			local _option = "_" .. option
			self[_option] = value
		end
	end
end

-- init_by_lua handler precomputations
function _M.init()
	-- do offset jump calculations for default rulesets
	-- this is also lazily handled in exec() for rulesets
	-- that dont appear here
	for _, ruleset in ipairs(_global_rulesets) do
		local rs, err, calc

		rs, err = util.load_ruleset_file(ruleset)

		if err then
			ngx.log(ngx.ERR, err)
		else
			_calculate_offset(rs)

			_ruleset_defs[ruleset] = rs
			_ruleset_def_cnt = _ruleset_def_cnt + 1

			_build_exception_table()
		end
	end
end

-- translate and add a SecRule files to ruleset defs
function _M.load_secrules(ruleset, opts, err_tab)
	local rules_tab = {}
	local rules_cnt = 0
	local f = assert(io.open(ruleset, 'r'))

	while true do
		local line = f:read("*line")

		if line == nil then break end

		rules_cnt = rules_cnt + 1
		rules_tab[rules_cnt] = line
	end

	f:close()

	local chains, errs = translate.translate(rules_tab, opts)

	if errs then
		for i = 1, #errs do
			if type(err_tab) ~= 'table' then
				ngx.log(ngx.WARN, errs[i].err)
				ngx.log(ngx.WARN, table.concat(errs[i].orig, "\n") .. "\n\n")
			else
				table_insert(err_tab, errs[i])
			end
		end
	end

	local name = string.gsub(ruleset, "(.*/)(.*)", "%2")

	_calculate_offset(chains)

	_ruleset_defs[name] = chains
	_ruleset_def_cnt = _ruleset_def_cnt + 1
end

-- add extra sieve elements to a rule on a per-instance basis
function _M.sieve_rule(self, id, sieves)
	-- pointer to our rule
	local orig_rule

	-- get a copy of the rule (meaning we have to search for it)
	for r, ruleset in pairs(_ruleset_defs) do
		if self.target_update_map[id] then break end

		for phase, rules in pairs(ruleset) do
			if self.target_update_map[id] then break end

			for i, rule in ipairs(rules) do
				if rule.id == id then
					orig_rule = rule
					self.target_update_map[id] = util.table_copy(rule.vars)
					break
				end
			end
		end
	end

	for _, sieve in ipairs(sieves) do
		local found
		local arg = ""

		if translate.valid_vars[sieve.type] then
			arg = translate.valid_vars[sieve.type].type
		end

		-- search for the rule here
		for i = 1, #self.target_update_map[id] do
			-- found it, append the sieves (ignore for now)
			if arg == self.target_update_map[id][i].type then
				local elts = type(sieve.elts) == "table" and sieve.elts
					or { sieve.elts }

				if not self.target_update_map[id][i].ignore then
					self.target_update_map[id][i].ignore = tab_new(#elts, 0)
				end

				for j = 1, #elts do
					self.target_update_map[id][i].ignore[j] = { sieve.action, elts[j] }
				end

				-- set/update the var's collection key
				self.target_update_map[id][i].collection_key =
					calc.build_collection_key(
						self.target_update_map[id][i],
						orig_rule.opts.transform)

				found = true
				break
			end

			if not found then
				ngx.log(ngx.WARN, arg .. " undefined in rule " .. id)
			end
		end
	end
end

-- push log data regarding matching rule(s) to the configured target
-- in the case of socket or file logging, this data will be buffered
function _M.write_log_events(self, has_ctx, ctx)
	-- there is a small bit of code duplication here to get our context
	-- because this lives outside exec()
	if not has_ctx then
		ctx = ngx.ctx.lua_resty_waf or {}
		if ctx.opts then
			self = ctx.opts
		end
	end

	if not ctx.lrw_initted then
		-- we never ran. this could happen due to something like #157
		ngx.log(ngx.DEBUG, "Not attempting to write log as lua-resty-waf was never exec'd")
		return
	end

	if ctx.altered ~= true and self._event_log_altered_only then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Not logging a request that wasn't altered") end
		return
	end

	if ctx.log_entries_n == 0 then
		if self._debug == true then ngx.log(self._debug_log_level, '[', self.transaction_id, '] ', "Not logging a request that had no rule alerts") end
		return
	end

	local entry = {
		timestamp = ngx.time(),
		client    = ctx.collections["REMOTE_ADDR"],
		method    = ctx.collections["METHOD"],
		uri       = ctx.collections["URI"],
		alerts    = ctx.log_entries,
		id        = self.transaction_id,
	}

	if self._event_log_request_arguments then
		entry.uri_args = ctx.collections["URI_ARGS"]
	end

	if self._event_log_request_headers then
		entry.request_headers = ctx.collections["REQUEST_HEADERS"]
	end

	if self._event_log_request_body then
		entry.request_body = ctx.collections["REQUEST_BODY"]
	end

	if table.getn(util.table_keys(self._event_log_ngx_vars)) ~= 0 then
		entry.ngx = {}
		for k, v in pairs(self._event_log_ngx_vars) do
			entry.ngx[k] = ngx.var[k]
		end
	end

	logger.write_log_events[self._event_log_target](self, entry)
end

return _M
