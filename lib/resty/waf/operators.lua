local _M = {}

local ac        = require "resty.waf.load_ac"
local base      = require "resty.waf.base"
local bit       = require "bit"
local dns       = require "resty.dns.resolver"
local iputils   = require "resty.iputils"
local libinject = require "resty.libinjection"
local logger    = require "resty.waf.log"
local util      = require "resty.waf.util"
local string_find = string.find
local string_gsub = string.gsub
local string_sub  = string.sub

local band, bor, bxor = bit.band, bit.bor, bit.bxor

-- module-level cache of aho-corasick dictionary objects
local _ac_dicts = {}

-- module-level cache of cidr objects
local _cidr_cache = {}

_M.version = base.version

function _M.equals(a, b)
	local equals, value, reason = a
	if type(a) == "table" then
		for _, v in ipairs(a) do
			equals, value = _M.equals(v, b)
			if equals then
				reason = v
				break
			end
		end
	else
		equals = a == b

		if equals then
			value = a
		end
	end

	return equals, value, reason
end

function _M.greater(a, b)
	local greater, value, reason = a

	if type(a) == "table" then
		for _, v in ipairs(a) do
			greater, value = _M.greater(v, b)
			if greater then
				reason = v
				break
			end
		end
	else
		greater = a > b

		if greater then
			value = a
		end
	end

	return greater, value, reason
end

function _M.less(a, b)
	local less, value, reason = a

	if type(a) == "table" then
		for _, v in ipairs(a) do
			less, value = _M.less(v, b)
			if less then
				reason = v
				break
			end
		end
	else
		less = a < b

		if less then
			value = a
		end
	end

	return less, value, reason
end

function _M.greater_equals(a, b)
	local greater_equals, value, reason = a

	if type(a) == "table" then
		for _, v in ipairs(a) do
			greater_equals, value = _M.greater_equals(v, b)
			if greater_equals then
				reason = v
				break
			end
		end
	else
		greater_equals = a >= b

		if greater_equals then
			value = a
		end
	end

	return greater_equals, value, reason
end

function _M.less_equals(a, b)
	local less_equals, value, reason = a

	if type(a) == "table" then
		for _, v in ipairs(a) do
			less_equals, value = _M.less_equals(v, b)
			if less_equals then
				reason = v
				break
			end
		end
	else
		less_equals = a <= b

		if less_equals then
			value = a
		end
	end

	return less_equals, value, reason
end

function _M.exists(needle, haystack)
	local exists, value, reason = needle

	if type(needle) == "table" then
		for _, v in ipairs(needle) do
			exists, value = _M.exists(v, haystack)

			if exists then
				reason = v
				break
			end
		end
	else
		exists = util.table_has_value(needle, haystack)

		if exists then
			value = needle
		end
	end

	return exists, value, reason
end

function _M.contains(haystack, needle)
	local contains, value, reason = needle

	if type(needle) == "table" then
		for _, v in ipairs(needle) do
			contains, value = _M.contains(haystack, v)

			if contains then
				reason = v
				break
			end
		end
	else
		contains = util.table_has_value(needle, haystack)

		if contains then
			value = needle
		end
	end

	return contains, value, reason
end

function _M.str_find(waf, subject, pattern)
	local from, to, match, value, reason = subject

	if type(subject) == "table" then
		for _, v in ipairs(subject) do
			match, value = _M.str_find(waf, v, pattern)

			if match then
				reason = v
				break
			end
		end
	else
		from, to = string_find(subject, pattern, 1, true)

		if from then
			match = true
			value = string_sub(subject, from, to)
		end
	end

	return match, value, reason
end

function _M.regex(waf, subject, pattern)
	local opts = waf._pcre_flags
	local captures, err, match, reason = subject

	if type(subject) == "table" then
		for _, v in ipairs(subject) do
			match, captures = _M.regex(waf, v, pattern)

			if match then
				reason = v
				break
			end
		end
	else
		captures, err = ngx.re.match(subject, pattern, opts)

		if err then
			logger.warn(waf, "error in ngx.re.match: " .. err)
		end

		if captures then
			match = true
		end
	end

	return match, captures, reason
end

function _M.refind(waf, subject, pattern)
	local opts = waf._pcre_flags
	local from, to, err, match, reason = subject

	if type(subject) == "table" then
		for _, v in ipairs(subject) do
			match, from = _M.refind(waf, v, pattern)

			if match then
				reason = v
				break
			end
		end
	else
		from, to, err = ngx.re.find(subject, pattern, opts)

		if err then
			logger.warn(waf, "error in ngx.re.find: " .. err)
		end

		if from then
			match = true
		end
	end

	return match, from, reason
end

function _M.ac_lookup(needle, haystack, ctx)
	local id = ctx.id
	local match, _ac, value, reason = needle

	-- dictionary creation is expensive, so we use the id of
	-- the rule as the key to cache the created dictionary
	if not _ac_dicts[id] then
		_ac = ac.create_ac(haystack)
		_ac_dicts[id] = _ac
	else
		_ac = _ac_dicts[id]
	end

	if type(needle) == "table" then
		for _, v in ipairs(needle) do
			match, value = _M.ac_lookup(v, haystack, ctx)

			if match then
				reason = v
				break
			end
		end
	else
		match = ac.match(_ac, needle)

		if match then
			match = true
			value = needle
		end
	end

	return match, value, reason
end

function _M.cidr_match(ip, cidr_pattern)
	local t = {}
	local n = 1
	local reason = ip

	if type(cidr_pattern) ~= "table" then
		cidr_pattern = { cidr_pattern }
	end

	for _, v in ipairs(cidr_pattern) do
		-- try to grab the parsed cidr from out module cache
		local cidr = _cidr_cache[v]

		-- if it wasn't there, compute and cache the value
		if not cidr then
			local lower, upper = iputils.parse_cidr(v)
			cidr = { lower, upper }
			_cidr_cache[v] = cidr
		end

		t[n] = cidr
		n = n + 1
	end

	return iputils.ip_in_cidrs(ip, t), ip, reason
end

function _M.rbl_lookup(waf, ip, rbl_srv, ctx)
	local nameservers = ctx.nameservers
	local reason = ip
	if type(nameservers) ~= 'table' then
		-- user probably didnt configure nameservers via set_option
		return false, nil, reason
	end

	local resolver, err = dns:new({
		nameservers = nameservers
	})

	if not resolver then
		logger.warn(waf, err)
		return false, nil, reason
	end

	-- id for unit test
	resolver._id = ctx._r_id or nil

	local rbl_query = util.build_rbl_query(ip, rbl_srv)

	if not rbl_query then
		-- we were handed something that didn't look like an IPv4
		return false, nil, reason
	end

	local answers, err = resolver:query(rbl_query)

	if not answers then
		logger.warn(waf, err)
		return false, nil, reason
	end

	if answers.errcode == 3 then
		-- errcode 3 means no lookup, so return false
		return false, nil, reason
	elseif answers.errcode then
		-- we had some other type of err that we should know about
		logger.warn(waf, "rbl lookup failure: " .. answers.errstr ..
			" (" .. answers.errcode .. ")")
		return false, nil, reason
	else
		-- we got a dns response, for now we're only going to return the first entry
		local i, answer = next(answers)
		if answer and type(answer) == 'table' then
			return true, answer.address or answer.cname, reason
		else
			-- we didnt have any valid answers
			return false, nil, reason
		end
	end
end

function _M.detect_sqli(input)
	local reason = input
	if type(input) == 'table' then
		for _, v in ipairs(input) do
			local match, value = _M.detect_sqli(v)

			if match then
				reason = v
				return match, value, reason
			end
		end
	else
		-- yes this is really just one line
		-- libinjection.sqli has the same return values that lookup.operators expects
		return libinject.sqli(input), reason
	end

	return false, nil, reason
end

function _M.detect_xss(input)
	local reason = input
	if type(input) == 'table' then
		for _, v in ipairs(input) do
			local match, value = _M.detect_xss(v)

			if match then
				reason = v
				return match, value, reason
			end
		end
	else
		-- this function only returns a boolean value
		-- so we'll wrap the return values ourselves
		if libinject.xss(input) then
			return true, input, reason
		else
			return false, nil, reason
		end
	end

	return false, nil, reason
end

function _M.str_match(input, pattern)
	local reason = input
	if type(input) == 'table' then
		for _, v in ipairs(input) do
			local match, value = _M.str_match(v, pattern)

			if match then
				reason = v
				return match, value, reason
			end
		end
	else
		local n, m = #input, #pattern

		if m > n then
			return
		end

		local char = {}

		for k = 0, 255 do char[k] = m end
		for k = 1, m-1 do char[pattern:sub(k, k):byte()] = m - k end

		local k = m
		while k <= n do
			local i, j = k, m

			while j >= 1 and input:sub(i, i) == pattern:sub(j, j) do
				i, j = i - 1, j - 1
			end

			if j == 0 then
				return true, input
			end

			k = k + char[input:sub(k, k):byte()]
		end

		return false, nil, reason
	end

	return false, nil, reason
end

function _M.verify_cc(waf, input, pattern)
	local match, value, reason = input
	match = false

	if type(input) == 'table' then
		for _, v in pairs(input) do
			match, value = _M.verify_cc(waf, v, pattern)

			if match then
				reason = v
				break
			end
		end
	else
		-- first match based on the given pattern
		-- if we matched, proceed to Luhn checksum
		do
			local m = _M.refind(waf, input, pattern)

			if not m then return false, nil, reason end
		end

		-- remove all non digits
		input = string_gsub(input, "[^%d]", '')

		-- Luhn checksum
		-- https://www.alienvault.com/blogs/labs-research/luhn-checksum-algorithm-lua-implementation
		local num = 0
		local len = input:len()
		local odd = band(len, 1)

		for count = 0, len - 1 do
			local digit = tonumber(string_sub(input, count + 1, count + 1))
			if bxor(band(count, 1), odd) == 0 then
				digit = digit * 2
			end

			if digit > 9 then
				digit = digit - 9
			end

			num = num + digit
		end

		if (num % 10) == 0 then
			match = true
			value = input
		end
	end

	return match, value, reason
end

_M.lookup = {
	REGEX        = function(waf, collection, pattern) return _M.regex(waf, collection, pattern) end,
	REFIND       = function(waf, collection, pattern) return _M.refind(waf, collection, pattern) end,
	EQUALS       = function(waf, collection, pattern) return _M.equals(collection, pattern) end,
	GREATER      = function(waf, collection, pattern) return _M.greater(collection, pattern) end,
	LESS         = function(waf, collection, pattern) return _M.less(collection, pattern) end,
	GREATER_EQ   = function(waf, collection, pattern) return _M.greater_equals(collection, pattern) end,
	LESS_EQ      = function(waf, collection, pattern) return _M.less_equals(collection, pattern) end,
	EXISTS       = function(waf, collection, pattern) return _M.exists(collection, pattern) end,
	CONTAINS     = function(waf, collection, pattern) return _M.contains(collection, pattern) end,
	STR_EXISTS   = function(waf, collection, pattern) return _M.str_find(waf, pattern, collection) end,
	STR_CONTAINS = function(waf, collection, pattern) return _M.str_find(waf, collection, pattern) end,
	PM           = function(waf, collection, pattern, ctx) return _M.ac_lookup(collection, pattern, ctx) end,
	CIDR_MATCH   = function(waf, collection, pattern) return _M.cidr_match(collection, pattern) end,
	RBL_LOOKUP   = function(waf, collection, pattern, ctx) return _M.rbl_lookup(waf, collection, pattern, ctx) end,
	DETECT_SQLI  = function(waf, collection, pattern) return _M.detect_sqli(collection) end,
	DETECT_XSS   = function(waf, collection, pattern) return _M.detect_xss(collection) end,
	STR_MATCH    = function(waf, collection, pattern) return _M.str_match(collection, pattern) end,
	VERIFY_CC    = function(waf, collection, pattern) return _M.verify_cc(waf, collection, pattern) end,
}

return _M
