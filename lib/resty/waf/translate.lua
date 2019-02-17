local _M = {}

local base = require "resty.waf.base"

local rex = require "rex_pcre"

local re_find   = rex.find
local re_match  = rex.match
local re_gmatch = rex.gmatch
local re_gsub   = rex.gsub

local str_fmt  = string.format
local str_find = string.find
local str_gsub = string.gsub

local pats = {}

local log = ngx.log
local WARN = ngx.WARN

_M.version = base.version

-- table.new(narr, nrec)
local succ, new_tab = pcall(require, "table.new")
if not succ then
	new_tab = function() return {} end
end

local function warn(msg)
	log(WARN, msg)
end

local valid_directives = {
	'SecRule',
	'SecAction',
	'SecMarker',
	'SecDefaultAction'
}

local valid_vars = {
	ARGS                    = { type = 'REQUEST_ARGS', parse = { "values", true } },
	ARGS_COMBINED_SIZE      = { type = 'ARGS_COMBINED_SIZE' },
	ARGS_GET                = { type = 'URI_ARGS', parse = { "values", true } },
	ARGS_GET_NAMES          = { type = 'URI_ARGS', parse = { "keys", true } },
	ARGS_NAMES              = { type = 'REQUEST_ARGS', parse = { "keys", true } },
	ARGS_POST               = { type = 'REQUEST_BODY', parse = { "values", true } },
	ARGS_POST_NAMES         = { type = 'REQUEST_BODY', parse = { "keys", true } },
	FILES                   = { type = 'FILES' },
	FILES_COMBINED_SIZE     = { type = 'FILES_COMBINED_SIZE' },
	FILES_NAMES             = { type = 'FILES_NAMES' },
	FILES_SIZES             = { type = 'FILES_SIZES' },
	FILES_TMP_CONTENT       = { type = 'FILES_TMP_CONTENT', parse = { "values", true } },
	MATCHED_VAR             = { type = 'MATCHED_VAR' },
	MATCHED_VARS            = { type = 'MATCHED_VARS' },
	MATCHED_VAR_NAME        = { type = 'MATCHED_VAR_NAME' },
	MATCHED_VAR_NAMES       = { type = 'MATCHED_VAR_NAMES' },
	QUERY_STRING            = { type = 'QUERY_STRING' },
	REMOTE_ADDR             = { type = 'REMOTE_ADDR' },
	REQUEST_BASENAME        = { type = 'REQUEST_BASENAME' },
	REQUEST_BODY            = { type = 'REQUEST_BODY' },
	REQUEST_COOKIES         = { type = 'COOKIES', parse = { "values", true } },
	REQUEST_COOKIES_NAMES   = { type = 'COOKIES', parse = { "keys", true } },
	REQUEST_FILENAME        = { type = 'URI' },
	REQUEST_HEADERS         = { type = 'REQUEST_HEADERS', parse = { "values", true } },
	REQUEST_HEADERS_NAMES   = { type = 'REQUEST_HEADERS', parse = { "keys", true } },
	REQUEST_LINE            = { type = 'REQUEST_LINE' },
	REQUEST_METHOD          = { type = 'METHOD' },
	REQUEST_PROTOCOL        = { type = 'PROTOCOL' },
	REQUEST_URI             = { type = 'REQUEST_URI' },
	REQUEST_URI_RAW         = { type = 'REQUEST_URI_RAW' },
	RESPONSE_BODY           = { type = 'RESPONSE_BODY' },
	RESPONSE_CONTENT_LENGTH = { type = 'RESPONSE_HEADERS', parse = { "specific", 'Content-Length' } },
	RESPONSE_CONTENT_TYPE   = { type = 'RESPONSE_HEADERS', parse = { "specific", 'Content-Type' } },
	RESPONSE_HEADERS        = { type = 'RESPONSE_HEADERS', parse = { "values", true } },
	RESPONSE_HEADERS_NAMES  = { type = 'RESPONSE_HEADERS', parse = { "keys", true } },
	RESPONSE_PROTOCOL       = { type = 'PROTOCOL' },
	RESPONSE_STATUS         = { type = 'STATUS' },
	SERVER_NAME             = { type = 'REQUEST_HEADERS', parse = { "specific", 'Host' } },
	TIME                    = { type = 'TIME' },
	TIME_DAY                = { type = 'TIME_DAY' },
	TIME_EPOCH              = { type = 'TIME_EPOCH' },
	TIME_HOUR               = { type = 'TIME_HOUR' },
	TIME_MIN                = { type = 'TIME_MIN' },
	TIME_MON                = { type = 'TIME_MON' },
	TIME_SEC                = { type = 'TIME_SEC' },
	TIME_YEAR               = { type = 'TIME_YEAR' },
	TX                      = { type = 'TX', storage = true },
	IP                      = { type = 'IP', storage = true },
	GLOBAL                  = { type = 'GLOBAL', storage = true },
}
_M.valid_vars = valid_vars

local valid_operators = {
	beginsWith       = function(pattern) return 'REFIND', '^' .. pattern end,
	contains         = 'STR_CONTAINS',
	containsWord     = function(pattern) return 'REFIND',
		'\\b' .. pattern .. '\\b' end,
	detectSQLi       = 'DETECT_SQLI',
	detectXSS        = 'DETECT_XSS',
	endsWith         = function(pattern) return 'REFIND', pattern .. '$' end,
	eq               = 'EQUALS',
	ge               = 'GREATER_EQ',
	gt               = 'GREATER',
	ipMatch          = 'CIDR_MATCH',
	ipMatchF         = 'CIDR_MATCH',
	ipMatchFromFile  = 'CIDR_MATCH',
	le               = 'LESS_EQ',
	lt               = 'LESS',
	pm               = 'PM',
	pmf              = 'PM',
	pmFromFile       = 'PM',
	rbl              = 'RBL_LOOKUP',
	rx               = 'REFIND',
	streq            = 'EQUALS',
	strmatch         = 'STR_MATCH',
	verifyCC         = 'VERIFY_CC',
	within           = 'STR_EXISTS',
};

local valid_transforms = {
	base64decode       = 'base64_decode',
	base64decodeext    = 'base64_decode',
	base64encode       = 'base64_encode',
	cssdecode          = 'css_decode',
	cmdline            = 'cmd_line',
	compresswhitespace = 'compress_whitespace',
	hexdecode          = 'hex_decode',
	hexencode          = 'hex_encode',
	htmlentitydecode   = 'html_decode',
	jsdecode           = 'js_decode',
	length             = 'length',
	lowercase          = 'lowercase',
	md5                = 'md5',
	normalisepath      = 'normalise_path',
	normalizepath      = 'normalise_path',
	normalisepathwin   = 'normalise_path_win',
	normalizepathwin   = 'normalise_path_win',
	removewhitespace   = 'remove_whitespace',
	removecomments     = 'remove_comments',
	removecommentschar = 'remove_comments_char',
	removenulls        = 'remove_nulls',
	replacecomments    = 'replace_comments',
	replacenulls       = 'replace_nulls',
	sha1               = 'sha1',
	sqlhexdecode       = 'sql_hex_decode',
	trim               = 'trim',
	trimleft           = 'trim_left',
	trimright          = 'trim_right',
	urldecode          = 'uri_decode',
	urldecodeuni       = 'uri_decode',
};

local action_lookup = {
	allow = 'ACCEPT',
	block = 'DENY',
	deny  = 'DENY',
	drop  = 'DROP',
	pass  = 'IGNORE'
};
_M.action_lookup = action_lookup

local direct_translation_actions = {
	accuracy = true,
	id       = true,
	maturity = true,
	phase    = true,
	rev      = true,
	severity = true,
	skip     = true,
	ver      = true,
}
_M.direct_translation_actions = direct_translation_actions

local expand_operators = {
	beginsWith = true,
	contains = true,
	containsWord = true,
	endsWith = true,
	eq = true,
	ge = true,
	gt = true,
	le = true,
	lt = true,
	streq = true,
	within = true,
}
_M.expand_operators = expand_operators

local action_defaults = {
	action = "DENY",
	phase  = "access",
}

local phase_lookup = {
	[1]          = 'access',
	[2]          = 'access',
	[3]          = 'header_filter',
	[4]          = 'body_filter',
	[5]          = 'log',
	["request"]  = 'access',
	["response"] = 'body_filter',
	["logging"]  = 'log',
}
_M.phase_lookup = phase_lookup

local function table_copy(orig)
	local orig_type = type(orig)
	local copy

	if orig_type == 'table' then
		copy = {}

		for orig_key, orig_value in next, orig, nil do
			copy[table_copy(orig_key)] = table_copy(orig_value)
		end

		setmetatable(copy, table_copy(getmetatable(orig)))
	else
		copy = orig
	end
	return copy
end

local function split(source, delimiter)
	local elements = {}
	local pattern = '([^'..delimiter..']+)'
	string.gsub(source, pattern, function(value)
		elements[#elements + 1] = value
	end)
	return elements
end

local function meta_exception(translation)
	local do_add = true

	if translation.actions.nondisrupt then
		for i = 1, #translation.actions.nondisrupt do
			local action = translation.actions.nondisrupt[i]

			if action.action == 'rule_remove_by_meta' then
				do_add = false
				break
			end
		end
	end

	if do_add then
		local action = {
			action = 'rule_remove_by_meta',
			data   = true
		}

		table.insert(translation.actions.nondisrupt, action)
	end
end

local ctl_lookup = {
	ruleEngine = function(value, translation)
		local mode
		if value == 'On' then
			mode = 'ACTIVE'
		elseif value == 'Off' then
			mode = 'INACTIVE'
		elseif value == 'DetectionOnly' then
			mode = 'SIMULATE'
		else
			error("Invalid ctl:ruleEngine mode")
		end

		local action = {
			action = 'mode_update',
			data   = mode,
		}

		table.insert(translation.actions.nondisrupt, action)
	end,
	ruleRemoveById = function(value, translation)
		local action = {
			action = 'rule_remove_id',
			data   = value,
		}

		table.insert(translation.actions.nondisrupt, action)
	end,
	ruleRemoveByMsg = function(value, translation)
		if not translation.exceptions then translation.exceptions = {} end
		table.insert(translation.exceptions, value)
		meta_exception(translation)
	end,
	ruleRemoveByTag = function(value, translation)
		if not translation.exceptions then translation.exceptions = {} end
		table.insert(translation.exceptions, value)
		meta_exception(translation)
	end,
}

pats.encap_quotes = rex.new([=[^(['"])(.*)\1$]=])
function _M.strip_encap_quotes(str)
	if re_find(str, pats.encap_quotes) then
		local _, s = re_match(str, pats.encap_quotes)
		return s
	end

	return str
end

pats.macro = rex.new("%{([^}]+)}")
function _M.translate_macro(string)
	local iterator = re_gmatch(string, pats.macro)

	while true do
		local macro = iterator()

		if not macro then break end

		local t = split(macro, "%.")
		local key = t[1]
		local specific = t[2]
		local replacement

		local lookup = table_copy(valid_vars[string.upper(key)])

		if lookup then
			replacement = lookup.type

			if lookup.storage then
				replacement = replacement .. '.' .. string.upper(specific)
			else
				if lookup.parse and lookup.parse[1] == 'specific' then
					replacement = replacement .. '.' .. lookup.parse[2]
				end

				if specific then
					replacement = replacement .. '.' .. specific
				end
			end
		else
			replacement = macro
		end

		replacement = str_fmt("%%%s", replacement)

		string = re_gsub(string, macro, replacement)
	end

	return string
end

function _M.valid_line(line)
	local valid = false

	for i = 1, #valid_directives do
		local directive = valid_directives[i]

		if str_find(line, '^' .. directive .. ' ') then return true end
	end

	return false
end

pats.trim_whitespace = rex.new([[^\s*|\s*$]])
pats.line_escape = rex.new([[\s*\\\s*$]])
function _M.clean_input(input)
	local lines    = {}
	local line_buf = {}

	for i = 1, #input do
		local line = input[i]

		-- ignore comments and blank lines
		local skip
		if #line == 0 then skip = true end
		if str_find(line, [[^%s*$]]) then skip = true end
		if str_find(line, [[^%s*#]]) then skip = true end

		if not skip then
			-- trim whitespace
			line = re_gsub(line, pats.trim_whitespace, '')

			if re_match(line, pats.line_escape) then
				-- strip the multi-line escape and surrounding whitespace
				line = re_gsub(line, pats.line_escape, '')
				table.insert(line_buf, line)
			else
				-- either the end of a mutli line directive, or standalone line
				-- push the buffer to the return array and clear the buffer
				table.insert(line_buf, line)

				local final_line = table.concat(line_buf, ' ')

				if _M.valid_line(final_line) then
					table.insert(lines, final_line)
				end

				line_buf = {}
			end
		end
	end

	return lines
end

pats.token_quoted = rex.new([[^"((?:[^"\\]+|\\.)*)"]])
pats.token_unquoted = rex.new([[([^\s]+)]])
function _M.tokenize(line)
	local tokens = {}
	local x = 0

	repeat
		local m = re_match(line, pats.token_quoted)

		if not m then
			m = re_match(line, pats.token_unquoted)
		end

		if not m then
			error('token did not match quoted or unquoted patterns')
		end

		-- got our token!
		local token = m

		local toremove = [[^"?\Q]] .. token .. [[\E"?]]

		line = re_gsub(line, toremove, '')
		line = re_gsub(line, [[^\s*]], '')

		-- remove any escaping backslashes from escaped quotes
		token = str_gsub(token, [[\"]], [["]])

		table.insert(tokens, token)
	until #line == 0

	return tokens
end

pats.elt_wrap = rex.new([[(?:\/'?|'?\/)]])
function _M.parse_vars(raw_vars)
	local tokens = {}
	local parsed_vars = {}
	local var_buf = {}
	local sentinal

	local split_vars = split(raw_vars, '|')

	repeat
		local chunk = table.remove(split_vars, 1)
		table.insert(var_buf, chunk)

		if (not re_find(chunk, pats.elt_wrap)
			or not str_find(chunk, ':', 1, true)) then

			local inbuf = (#var_buf > 1
				and re_find(var_buf[1], pats.elt_wrap))

			if not inbuf then sentinal = true end
		end

		if str_find(chunk, [[/'?$]]) then
			sentinal = true
		end

		if sentinal then
			local token = table.concat(var_buf, '|')
			table.insert(tokens, token)
			var_buf = {}
			sentinal = false
		end
	until #split_vars == 0

	for i = 1, #tokens do
		local token = tokens[i]

		local token_parts = split(token, ':')
		local var = table.remove(token_parts, 1)
		local specific = table.concat(token_parts, ':')

		local parsed = {}
		local modifier

		local dopush = true

		if string.find(var, '&', 1, true) then
			var = string.sub(var, 2, #var)
			parsed.modifier = '&'
		end

		if string.find(var, '!', 1, true) then
			var = string.sub(var, 2, #var)
			parsed.modifier = '!'

			local prev_parsed_var = table.remove(parsed_vars)

			if not prev_parsed_var then error("no prev var") end

			if prev_parsed_var.variable ~= var then
				error("seen var " .. var .. " doesnt match previous var " ..
					prev_parsed_var.variable)
			end

			if not prev_parsed_var.ignore then prev_parsed_var.ignore = {} end
			table.insert(prev_parsed_var.ignore, specific)

			parsed = prev_parsed_var
			parsed.modifier = '!'

			dopush = false
			table.insert(parsed_vars, parsed)
		end

		if dopush then
			parsed.variable = var
			if #specific > 0 then parsed.specific = specific end

			table.insert(parsed_vars, parsed)
		end
	end

	return parsed_vars
end

pats.operator = rex.new([[\s*(?:(\!)?(?:\@([a-zA-Z]+)\s*)?)?(.*)$]])
function _M.parse_operator(raw_operator)
	local op_regex = pats.operator

	local negated, operator, pattern = re_match(raw_operator, op_regex)
	if not operator and not pattern then
		error("Could not match again op_regex: " .. raw_operator)
	end

	if not operator then operator = 'rx' end

	local parsed = {}

	if negated then parsed.negated = negated end
	parsed.operator = operator
	parsed.pattern = pattern

	return parsed
end

function _M.parse_actions(raw_actions)
	local tokens = {}
	local parsed_actions = {}
	local action_buf = {}
	local sentinal = false

	local split_actions = split(raw_actions, ',')

	if not split_actions then return {} end

	repeat
		local chunk = table.remove(split_actions, 1)

		if not chunk then break end

		table.insert(action_buf, chunk)

		if (not string.find(chunk, "'", 1, true)
			or not string.find(chunk, ':', 1, true)) then

			local inbuf = (#action_buf > 1
				and string.find(action_buf[1], "'", 1, true))

			if not inbuf then sentinal = true end
		end

		if str_find(chunk, [['$]]) then
			sentinal = true
		end

		if sentinal then
			local token = table.concat(action_buf, ',')
			table.insert(tokens, token)
			action_buf = {}
			sentinal = false
		end
	until #split_actions == 0

	for i = 1, #tokens do
		local token = tokens[i]

		local token_parts = split(token, ':')
		local action = table.remove(token_parts, 1)
		local value = table.concat(token_parts, ':')

		action = re_gsub(action, pats.trim_whitespace, '')

		local parsed = {
			action = action
		}

		if #value > 0 then
			parsed.value = _M.strip_encap_quotes(value)
		end

		table.insert(parsed_actions, parsed)
	end

	return parsed_actions
end

function _M.parse_tokens(tokens)
	local entry, directive, vars, operator, actions
	entry = {}

	entry["original"] = table.concat(tokens, ' ')

	directive = table.remove(tokens, 1)
	if directive == 'SecRule' then
		vars = table.remove(tokens, 1)
		operator = table.remove(tokens, 1)
	end
	actions = table.remove(tokens)

	if #tokens ~= 0 then error(#tokens .. " tokens when we should have 0") end

	entry.directive = directive
	if vars then entry.vars = _M.parse_vars(vars) end
	if operator then entry.operator = _M.parse_operator(operator) end
	if actions and actions ~= '' then
		entry.actions = _M.parse_actions(actions)
	end

	return entry
end

function _M.build_chains(rules)
	local chain = {}
	local chains = {}

	for i = 1, #rules do
		local rule = rules[i]

		table.insert(chain, rule)

		local is_chain
		if type(rule.actions) == 'table' then
			for j = 1, #rule.actions do
				local action = rule.actions[j]
				if action.action == 'chain' then is_chain = true; break end
			end
		end

		if not is_chain then
			table.insert(chains, chain)
			chain = {}
		end
	end

	return chains
end

pats.specific_elt = rex.new([=[^'?\/(.*)\/'?]=])
function _M.translate_vars(rule, translation, opts)
	translation.vars = {}
	local n = 0

	opts = opts or {}
	local force = opts.force
	local quiet = opts.quiet

	for i = 1, #rule.vars do
		local ok, err = pcall(function()
			local var = rule.vars[i]
			local original_var = var.variable
			local lookup_var   = table_copy(valid_vars[original_var])

			if not lookup_var or not lookup_var.type then
				error("no valid var " .. original_var)
			end

			if var.specific
				and lookup_var.parse and lookup_var.parse[1] == 'specific' then
				error("invalid spec attribute")
			end

			local translated_var = lookup_var
			local modifier = var.modifier
			local specific = var.specific or ''

			local specific_regex
			if str_find(specific, [=[^'?/]=]) then
				specific = re_gsub(specific, pats.specific_elt, '%1')
				specific_regex = true
			end

			if modifier and modifier == '!' then
				for j = 1, #var.ignore do
					local elt = var.ignore[j]

					local elt_regex
					if str_find(elt, [=[^'?/]=]) then
						elt = re_gsub(elt, pats.specific_elt, "%1")
						elt_regex = true
					end

					local key = elt_regex and 'regex' or 'ignore'
					if lookup_var.storage then elt = string.upper(elt) end

					if type(translated_var.ignore) ~= 'table' then
						translated_var.ignore = {}
					end
					table.insert(translated_var.ignore, { key, elt })
				end
			elseif #specific > 0 then
				local key = specific_regex and 'regex' or 'specific'

				if lookup_var.storage then specific = string.upper(specific) end

				translated_var.parse = { key, specific }
			end

			if modifier and modifier == '&' then
				translated_var.length = true
			end

			if type(translation.vars) ~= 'table' then translation.vars = {} end
			table.insert(translation.vars, translated_var)
		end)

		if err then
			if not quiet then warn(err) end
			if not force then error(err) end
		else
			n = n + 1
		end
	end

	if n == 0 then error("rule had no valid vars") end
end

function _M.translate_operator(rule, translation, path)
	local original_operator = rule.operator.operator
	local translated_operator = valid_operators[original_operator]

	if not translated_operator then
		error("Cannot translate operator " .. original_operator)
	end

	if type(translated_operator) == 'function' then
		local operator, pattern = translated_operator(rule.operator.pattern)
		translation.operator = operator
		translation.pattern = pattern
	else
		translation.operator = translated_operator
		translation.pattern  = rule.operator.pattern
	end

	if rule.operator.negated then translation.op_negated = true end

	local isnum = tonumber(translation.pattern)
	translation.pattern = isnum and isnum or translation.pattern

	if str_find(rule.operator.operator, "[fF]$") or
		str_find(rule.operator.operator, "FromFile$") then
		local buffer = {}
		local pattern_file = rule.operator.pattern

		path = path or '.'

		local f = assert(io.open(path .. '/' ..  pattern_file, 'r'))

		while true do
			local line = f:read("*line")

			if line == nil then break end

			local skip
			if #line == 0 then skip = true end
			if str_find(line, [[^%s*$]]) then skip = true end
			if str_find(line, [[^%s*#]]) then skip = true end

			if not skip then
				table.insert(buffer, line)
			end
		end

		f:close()

		translation.pattern = buffer
		return
	end

	if translated_operator == 'PM' then
		local pattern = split(rule.operator.pattern, "%s+")
		translation.pattern = pattern
	end

	if translated_operator == 'CIDR_MATCH' then
		local pattern = split(rule.operator.pattern, ",")
		translation.pattern = pattern
	end

	local doexpand = expand_operators[original_operator] or
		(type(translation.pattern) == 'string' and
		re_find(translation.pattern, pats.macro))

	if doexpand then
		if not translation.opts then translation.opts = {} end
		translation.opts.parsepattern = true
		translation.pattern = _M.translate_macro(translation.pattern)
	end
end

function _M.translate_actions(rule, translation, opts)
	if not rule.actions then return end

	opts = opts or {}

	local loose = opts.loose
	local quiet = opts.quiet

	local silent_actions = {
		chain = true
	}

	local disruptive_actions = {
		allow = true,
		block = true,
		deny  = true,
		drop  = true,
		pass  = true,
	}

	if not translation.actions then
		translation.actions = { nondisrupt = {} }
	end

	if not translation.actions.nondisrupt then
		translation.actions.nondisrupt = {}
	end

	for i = 1, #rule.actions do
		local ok, err = pcall(function()
			local action = rule.actions[i]
			local key = action.action
			local value = action.value

			if silent_actions[key] then return end

			if disruptive_actions[key] then
				translation.action = string.upper(action_lookup[key])
				return
			end
			if direct_translation_actions[key] then
				translation[key] = value
				return
			end
			if key == 'capture' then
				if translation.operator == 'REFIND' then
					translation.operator = 'REGEX'
				end
				return
			end
			if key == 'ctl' then
				local t = split(value, '=')
				local opt = t[1]
				local data = tonumber(t[2]) and tonumber(t[2]) or t[2]

				if ctl_lookup[opt] then
					ctl_lookup[opt](data, translation)
				else
					error("Cannot translate ctl option " .. opt)
				end
				return
			end
			if key == 'expirevar' then
				local t = split(value, '=')
				local var = t[1]
				local time = t[2]
				local tt = split(var, "%.")
				local collection = tt[1]
				local element = tt[2]
				time = tonumber(time) and tonumber(time) or _M.translate_macro(time)
				local e = {
					action = 'expirevar',
					data = {
						col = string.upper(collection),
						key = string.upper(element),
						time = time
					}
				}
				table.insert(translation.actions.nondisrupt, e)
				return
			end
			if key == 'initcol' then
				local t = split(value, '=')
				local col = t[1]
				local val = t[2]
				local e = {
					action = 'initcol',
					data = {
						col = string.upper(col),
						value = _M.translate_macro(val)
					}
				}
				table.insert(translation.actions.nondisrupt, e)
				return
			end
			if key == 'logdata' then
				translation.logdata = _M.translate_macro(value)
				return
			end
			if key == 'msg' then
				translation.msg = _M.translate_macro(value)
				return
			end
			if key == 'nolog' or key == 'noauditlog' then
				translation.opts.log = false
				return
			end
			if key == 'log' or key == 'auditlog' then
				translation.opts.log = true
				return
			end
			if key == 'skipAfter' then
				translation.skip_after = value
				return
			end
			if key == 'setvar' then
				local t = split(value, '=')
				local var = t[1]
				local val = t[2]
				local tt = split(var, "%.")
				local collection = table.remove(tt, 1)
				local element = table.concat(tt, '.')
				-- delete
				if not val then
					if str_find(var, [=[^!]=]) then
						collection = string.sub(collection, 2, #collection)
						local e = {
							action = 'deletevar',
							data = {
								col = string.upper(collection),
								key = string.upper(element)
							}
						}
						table.insert(translation.actions.nondisrupt, e)
						return
					else
						val = 1
					end
				end
				local setvar = {
					col = string.upper(collection),
					key = string.upper(element)
				}
				if str_find(val, [=[^%+]=]) then
					setvar.inc = true
					val = string.sub(val, 2, #val)
				end
				setvar.value = tonumber(val) and tonumber(val)
					or _M.translate_macro(val)
				local e = {
					action = 'setvar',
					data = setvar
				}
				table.insert(translation.actions.nondisrupt, e)
				return
			end
			if key == 'status' then
				local e = {
					action = 'status',
					data = tonumber(value)
				}
				table.insert(translation.actions.nondisrupt, e)
				return
			end
			if key == 'pause' then
				local e = {
					action = 'sleep',
					data = tonumber(value) / 1000
				}
				table.insert(translation.actions.nondisrupt, e)
				return
			end
			if key == 't' then
				if value == 'none' then return end
				local transform = valid_transforms[string.lower(value)]
				if not transform then
					error("Cannot perform transform " .. value)
				end
				table.insert(translation.opts.transform, transform)
				return
			end
			if key == 'tag' then
				if not translation.tag then translation.tag = {} end
				table.insert(translation.tag, _M.translate_macro(value))
				return
			end

			error("Cannot translate action " .. key)
		end)

		if not ok then
			if not loose then error(err) end
			if not quiet then warn(err) end
		end
	end

	if translation.actions.nondisrupt and
		#translation.actions.nondisrupt == 0 then
		translation.actions = nil
	end
end

function _M.translate_chain(chain, opts)
	local chain_id
	local chain_action
	local lua_resty_waf_chain = {}

	opts = opts or {}

	chain_action = {}
	local end_actions = {"action", "msg", "logdata", "skip", "skip_after"}

	for i = 1, #chain do
		local rule = chain[i]

		local translation = { actions = {}, opts = { transform = {} } }

		local directive = rule.directive

		if rule.directive == 'SecRule' then
			_M.translate_vars(rule, translation, opts)
			_M.translate_operator(rule, translation, opts.path)
		elseif directive == 'SecAction' or directive == 'SecMarker' then
			translation.vars = {{ unconditional = true }}

			-- SecMarker is a rule that never matches
			-- with its only action representing its ID
			if directive == 'SecMarker' then
				translation.op_negated = true

				local marker = table.remove(rule.actions, 1)
				translation.id = marker.action
			end
		end

		_M.translate_actions(rule, translation, opts)

		-- assign the same ID to each rule in the chain
		if translation.id then
			chain_id = translation.id
		else
			translation.id = chain_id
		end

		-- these actions exist in the chain starter in ModSecurity
		-- but they belong in the final rule in lua-resty-waf
		for j = 1, #end_actions do
			local action = end_actions[j]

			if translation[action] then
				local t_action = translation[action]

				chain_action[action] = t_action
				translation[action] = nil
			end
		end

		-- if we've reached the end of the chain, assign our values that
		-- had to be pushed from the chain starter, or assign the default
		if i == #chain then
			for j = 1, #end_actions do
				local end_action = end_actions[j]

				if chain_action[end_action] then
					translation[end_action] = chain_action[end_action]
				elseif action_defaults[end_action] then
					translation[end_action] = action_defaults[end_action]
				end
			end
		else
			translation.action = 'CHAIN'
		end

		if not translation.actions then translation.actions = {} end
		translation.actions.disrupt = translation.action
		translation.action = nil

		if #translation.opts.transform == 0 then
			translation.opts.transform = nil
		end

		if #translation.opts == 0 and not next(translation.opts) then
			translation.opts = nil
		end

		table.insert(lua_resty_waf_chain, translation)
	end

	return lua_resty_waf_chain
end

function _M.figure_phase(translation)
	local phase = tonumber(translation[1].phase) or translation[1].phase

	translation[1].phase = nil

	local p = phase and phase_lookup[phase]
	return p and p or 'access'
end

function _M.translate_chains(chains, opts)
	local lua_resty_waf_chains = {
		access        = {},
		body_filter   = {},
		header_filter = {},
		log           = {},
	}

	local errs = {}

	for i = 1, #chains do
		local chain = chains[i]

		local ok, err = pcall(function()
			local translation = _M.translate_chain(chain, opts)

			local phase = _M.figure_phase(translation)

			for j = 1, #translation do
				table.insert(lua_resty_waf_chains[phase], translation[j])
			end
		end)

		if err then
			local origs = {}
			for j = 1, #chain do
				table.insert(origs, chain[j].original)
			end

			table.insert(errs, { err = err, orig = origs })
		end
	end

	return lua_resty_waf_chains, #errs > 0 and errs or nil
end

-- take an array of inputs and return an array of waf chains, and errs
function _M.translate(raw, opts)
	local input = _M.clean_input(raw)

	local parsed_lines = new_tab(#input, 0)
	for i = 1, #input do
		local tokens = _M.tokenize(input[i])
		local parsed_line = _M.parse_tokens(tokens)
		parsed_lines[i] = parsed_line
	end
	local modsec_chains = _M.build_chains(parsed_lines)
	return _M.translate_chains(modsec_chains, opts)
end

return _M
