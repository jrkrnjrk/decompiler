-- Server CLI for Leo decompiler
-- Usage: luau leo_cli.luau <base64-bytecode>
--    or: echo <base64> | luau leo_cli.luau

local Leo = (function()
-- Leo Luau Decompiler 1.0
-- MADE BY LEO
-- Static decompiler for official Luau bytecode v3-v9 (target v9). Input is never executed.

local VERSION_NAME = "Leo Luau Decompiler 1.0"
local CREDIT_LINE = "MADE BY LEO"

local OPCODES = {
	"NOP", "BREAK", "LOADNIL", "LOADB", "LOADN", "LOADK", "MOVE",
	"GETGLOBAL", "SETGLOBAL", "GETUPVAL", "SETUPVAL", "CLOSEUPVALS",
	"GETIMPORT", "GETTABLE", "SETTABLE", "GETTABLEKS", "SETTABLEKS",
	"GETTABLEN", "SETTABLEN", "NEWCLOSURE", "NAMECALL", "CALL", "RETURN",
	"JUMP", "JUMPBACK", "JUMPIF", "JUMPIFNOT", "JUMPIFEQ", "JUMPIFLE",
	"JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
	"ADD", "SUB", "MUL", "DIV", "MOD", "POW",
	"ADDK", "SUBK", "MULK", "DIVK", "MODK", "POWK",
	"AND", "OR", "ANDK", "ORK", "CONCAT", "NOT", "MINUS", "LENGTH",
	"NEWTABLE", "DUPTABLE", "SETLIST", "FORNPREP", "FORNLOOP", "FORGLOOP",
	"FORGPREP_INEXT", "FASTCALL3", "FORGPREP_NEXT", "NATIVECALL", "GETVARARGS",
	"DUPCLOSURE", "PREPVARARGS", "LOADKX", "JUMPX", "FASTCALL", "COVERAGE",
	"CAPTURE", "SUBRK", "DIVRK", "FASTCALL1", "FASTCALL2", "FASTCALL2K",
	"FORGPREP", "JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS",
	"IDIV", "IDIVK", "GETUDATAKS", "SETUDATAKS", "NAMECALLUDATA",
	"NEWCLASSMEMBER", "CALLFB", "CMPPROTO", "FASTPCALL", "NEWCLASS",
}

local OP = {}
for i, name in OPCODES do
	OP[name] = i - 1
end

local AUX_OPS = {}
for _, name in {
	"GETGLOBAL", "SETGLOBAL", "GETIMPORT", "GETTABLEKS", "SETTABLEKS", "NAMECALL",
	"JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
	"NEWTABLE", "SETLIST", "FORGLOOP", "FASTCALL3", "LOADKX", "FASTCALL2", "FASTCALL2K",
	"JUMPXEQKNIL", "JUMPXEQKB", "JUMPXEQKN", "JUMPXEQKS",
	"GETUDATAKS", "SETUDATAKS", "NAMECALLUDATA", "NEWCLASSMEMBER", "CALLFB", "CMPPROTO", "NEWCLASS",
} do
	AUX_OPS[OP[name]] = true
end

local LCT_VAL, LCT_REF, LCT_UPVAL = 0, 1, 2

local function DecodeError(msg)
	return setmetatable({ message = msg }, {
		__tostring = function(self)
			return self.message
		end,
	})
end

local function Reader(data)
	local buf
	if typeof(data) == "buffer" then
		buf = data
	else
		buf = buffer.fromstring(data)
	end
	local self = { buf = buf, pos = 0, len = buffer.len(buf) }

	function self:check(n)
		if self.pos + n > self.len then
			error(DecodeError("unexpected end of bytecode at offset " .. self.pos), 0)
		end
	end

	function self:u8()
		self:check(1)
		local v = buffer.readu8(self.buf, self.pos)
		self.pos += 1
		return v
	end

	function self:u32()
		self:check(4)
		local v = buffer.readu32(self.buf, self.pos)
		self.pos += 4
		return v
	end

	function self:i32()
		self:check(4)
		local v = buffer.readi32(self.buf, self.pos)
		self.pos += 4
		return v
	end

	function self:f32()
		self:check(4)
		local v = buffer.readf32(self.buf, self.pos)
		self.pos += 4
		return v
	end

	function self:f64()
		self:check(8)
		local v = buffer.readf64(self.buf, self.pos)
		self.pos += 8
		return v
	end

	function self:bytes(n)
		self:check(n)
		local s = buffer.readstring(self.buf, self.pos, n)
		self.pos += n
		return s
	end

	function self:varint()
		local result, shift = 0, 0
		while true do
			local b = self:u8()
			result += bit32.lshift(bit32.band(b, 127), shift)
			if bit32.band(b, 128) == 0 then
				return result
			end
			shift += 7
			if shift > 35 then
				error(DecodeError("varint too long"), 0)
			end
		end
	end

	function self:varint64()
		local result, shift = 0, 0
		while true do
			local b = self:u8()
			result += bit32.lshift(bit32.band(b, 127), shift)
			if bit32.band(b, 128) == 0 then
				return result
			end
			shift += 7
			if shift > 70 then
				error(DecodeError("varint64 too long"), 0)
			end
		end
	end

	return self
end

-- Roblox client bytecode encrypts the opcode byte: real_op = (enc * 203) % 256
local ROBLOX_OP_KEY = 203
local function insn_op(insn)
	local enc = bit32.band(insn, 255)
	return (enc * ROBLOX_OP_KEY) % 256
end
local function insn_a(insn)
	return bit32.band(bit32.rshift(insn, 8), 255)
end
local function insn_b(insn)
	return bit32.band(bit32.rshift(insn, 16), 255)
end
local function insn_c(insn)
	return bit32.band(bit32.rshift(insn, 24), 255)
end
local function insn_d(insn)
	local u = bit32.band(bit32.rshift(insn, 16), 65535)
	if u >= 32768 then
		return u - 65536
	end
	return u
end
local function insn_e(insn)
	local v = bit32.rshift(insn, 8)
	if bit32.band(v, 0x800000) ~= 0 then
		v -= 0x1000000
	end
	return v
end

local RESERVED = {
	["and"] = true, ["break"] = true, ["do"] = true, ["else"] = true, ["elseif"] = true, ["end"] = true,
	["false"] = true, ["for"] = true, ["function"] = true, ["if"] = true, ["in"] = true,
	["local"] = true, ["nil"] = true, ["not"] = true, ["or"] = true, ["repeat"] = true,
	["return"] = true, ["then"] = true, ["true"] = true, ["until"] = true, ["while"] = true, ["continue"] = true,
}

local function is_ident(s)
	if type(s) ~= "string" or s == "" then
		return false
	end
	if RESERVED[s] then
		return false
	end
	if string.match(s, "^%d") then
		return false
	end
	return string.match(s, "^[%a_][%w_]*$") ~= nil
end

local function sanitize_name(name)
	if type(name) ~= "string" or name == "" then
		return "v"
	end
	local out = string.gsub(name, "[^%w_]", "_")
	if string.match(out, "^%d") then
		out = "_" .. out
	end
	return out
end

local function format_number(n)
	if type(n) == "number" and n == math.floor(n) and math.abs(n) < 2 ^ 53 then
		return tostring(math.floor(n))
	end
	return tostring(n)
end

local function format_string(s)
	s = tostring(s)
	s = string.gsub(s, "\\", "\\\\")
	s = string.gsub(s, '"', '\\"')
	s = string.gsub(s, "\n", "\\n")
	s = string.gsub(s, "\r", "\\r")
	s = string.gsub(s, "\t", "\\t")
	s = string.gsub(s, "\0", "\\0")
	return '"' .. s .. '"'
end

local function const_render(c)
	local k, v = c.kind, c.value
	if k == "nil" then
		return "nil"
	elseif k == "bool" then
		return v and "true" or "false"
	elseif k == "number" then
		return format_number(v)
	elseif k == "integer" then
		return tostring(v)
	elseif k == "string" then
		return format_string(v)
	elseif k == "vector" then
		local x, y, z, w = v[1], v[2], v[3], v[4]
		if math.abs(w or 0) < 1e-12 then
			return string.format("vector.create(%s, %s, %s)", format_number(x), format_number(y), format_number(z))
		end
		return string.format("vector.create(%s, %s, %s, %s)", format_number(x), format_number(y), format_number(z), format_number(w))
	elseif k == "import" then
		return type(v) == "string" and v or ("IMPORT(" .. tostring(v) .. ")")
	elseif k == "table" then
		if v.values then
			local inner = {}
			for i, pair in v.values do
				inner[i] = "[" .. pair[1] .. "] = " .. pair[2]
			end
			return "{" .. table.concat(inner, ", ") .. "}"
		end
		local inner = {}
		for i, kk in v.keys do
			inner[i] = "[" .. kk .. "] = 0"
		end
		return "{" .. table.concat(inner, ", ") .. "}"
	elseif k == "closure" then
		return "<proto " .. tostring(v) .. ">"
	elseif k == "class_shape" then
		return "<class " .. tostring(v) .. ">"
	end
	return tostring(v)
end

local function index_expr(obj, key)
	if string.sub(key, 1, 1) == '"' and string.sub(key, -1) == '"' then
		local inner = string.sub(key, 2, -2)
		if is_ident(inner) and not string.find(inner, "\\", 1, true) then
			return obj .. "." .. inner
		end
	end
	return obj .. "[" .. key .. "]"
end

local function k_text(proto, idx)
	if idx >= 0 and idx < #proto.constants then
		return const_render(proto.constants[idx + 1])
	end
	return "K[" .. tostring(idx) .. "]"
end

local function decode_instructions(code)
	local out = {}
	local pc, n = 0, #code
	while pc < n do
		local insn = code[pc + 1]
		local op = insn_op(insn)
		local name = OPCODES[op + 1] or ("OP_" .. op)
		local aux, size = nil, 1
		if AUX_OPS[op] and pc + 1 < n then
			aux = code[pc + 2]
			size = 2
		end
		out[#out + 1] = {
			pc = pc,
			op = op,
			name = name,
			a = insn_a(insn),
			b = insn_b(insn),
			c = insn_c(insn),
			d = insn_d(insn),
			e = insn_e(insn),
			aux = aux,
			size = size,
		}
		pc += size
	end
	return out
end

local function decode_chunk(data)
	if data == nil or data == "" then
		error(DecodeError("empty input"), 0)
	end
	local r = Reader(data)
	local version = r:u8()
	if version == 0 then
		error(DecodeError("compiler error bytecode: " .. (r:bytes(r.len - 1) or "")), 0)
	end

	local types_version = 0
	if version >= 4 then
		types_version = r:u8()
	end

	local string_count = r:varint()
	local strings = {}
	for _ = 1, string_count do
		local length = r:varint()
		strings[#strings + 1] = r:bytes(length)
	end

	local function string_at(idx)
		if idx == 0 then
			return nil
		end
		return strings[idx] or ("<bad-string-" .. idx .. ">")
	end

	local userdata_types = {}
	if types_version == 3 then
		local index = r:u8()
		while index ~= 0 do
			local sid = r:varint()
			userdata_types[#userdata_types + 1] = { index, string_at(sid) or "" }
			index = r:u8()
		end
	end

	local proto_count = r:varint()
	local protos = {}

	for pi = 0, proto_count - 1 do
		if version >= 12 then
			r:varint()
		end
		local p = {
			index = pi,
			maxstacksize = r:u8(),
			numparams = r:u8(),
			nups = r:u8(),
			is_vararg = r:u8(),
			flags = 0,
			typeinfo = "",
			code = {},
			constants = {},
			child_ids = {},
			linedefined = 0,
			debugname = nil,
			lineinfo = {},
			locvars = {},
			upvalue_names = {},
			instructions = {},
		}
		if version >= 4 then
			p.flags = r:u8()
			local typesize = r:varint()
			if typesize > 0 then
				p.typeinfo = r:bytes(typesize)
			end
		end
		local sizecode = r:varint()
		for _ = 1, sizecode do
			p.code[#p.code + 1] = r:u32()
		end
		local sizek = r:varint()
		for _ = 1, sizek do
			local tag = r:u8()
			if tag == 0 then
				p.constants[#p.constants + 1] = { kind = "nil", value = nil }
			elseif tag == 1 then
				p.constants[#p.constants + 1] = { kind = "bool", value = r:u8() ~= 0 }
			elseif tag == 2 then
				p.constants[#p.constants + 1] = { kind = "number", value = r:f64() }
			elseif tag == 3 then
				p.constants[#p.constants + 1] = { kind = "string", value = string_at(r:varint()) or "" }
			elseif tag == 4 then
				local iid = r:u32()
				local count = bit32.rshift(iid, 30)
				local ids = { bit32.band(bit32.rshift(iid, 20), 1023), bit32.band(bit32.rshift(iid, 10), 1023), bit32.band(iid, 1023) }
				local parts = {}
				for i = 1, count do
					local kid = ids[i]
					local c = p.constants[kid + 1]
					parts[#parts + 1] = (c and c.kind == "string" and c.value) or ("k" .. kid)
				end
				p.constants[#p.constants + 1] = { kind = "import", value = #parts > 0 and table.concat(parts, ".") or string.format("import(0x%08x)", iid) }
			elseif tag == 5 then
				local nkeys = r:varint()
				local keys = {}
				for _k = 1, nkeys do
					local kid = r:varint()
					local c = p.constants[kid + 1]
					keys[#keys + 1] = c and const_render(c) or ("k" .. kid)
				end
				p.constants[#p.constants + 1] = { kind = "table", value = { keys = keys } }
			elseif tag == 8 then
				local nkeys = r:varint()
				local pairs_ = {}
				for _k = 1, nkeys do
					local kid = r:varint()
					local vid = r:i32()
					local kc = p.constants[kid + 1]
					local ktxt = kc and const_render(kc) or ("k" .. kid)
					local vtxt = "0"
					if vid >= 0 and p.constants[vid + 1] then
						vtxt = const_render(p.constants[vid + 1])
					end
					pairs_[#pairs_ + 1] = { ktxt, vtxt }
				end
				local keys = {}
				for i, pair in pairs_ do
					keys[i] = pair[1]
				end
				p.constants[#p.constants + 1] = { kind = "table", value = { keys = keys, values = pairs_ } }
			elseif tag == 6 then
				p.constants[#p.constants + 1] = { kind = "closure", value = r:varint() }
			elseif tag == 7 then
				p.constants[#p.constants + 1] = { kind = "vector", value = { r:f32(), r:f32(), r:f32(), r:f32() } }
			elseif tag == 11 then
				p.constants[#p.constants + 1] = { kind = "vector", value = { r:f64(), r:f64(), r:f64(), r:f64() } }
			elseif tag == 9 then
				local neg = r:u8()
				local mag = r:varint64()
				p.constants[#p.constants + 1] = { kind = "integer", value = neg ~= 0 and -mag or mag }
			elseif tag == 10 then
				local cnid = r:varint()
				local nprop = r:varint()
				local nmeth = r:varint()
				local members = {}
				for _m = 1, nprop + nmeth do
					members[#members + 1] = r:varint()
				end
				local c = p.constants[cnid + 1]
				p.constants[#p.constants + 1] = { kind = "class_shape", value = { name = c and const_render(c) or ("k" .. cnid), members = members } }
			else
				error(DecodeError("unknown constant tag " .. tag .. " in proto " .. pi), 0)
			end
		end

		local sizep = r:varint()
		for _ = 1, sizep do
			p.child_ids[#p.child_ids + 1] = r:varint()
		end
		p.linedefined = r:varint()
		p.debugname = string_at(r:varint())

		if r:u8() ~= 0 then
			local linegaplog2 = r:u8()
			local intervals = sizecode > 0 and (bit32.rshift(sizecode - 1, linegaplog2) + 1) or 0
			local rel, acc = {}, 0
			for _ = 1, sizecode do
				acc = bit32.band(acc + r:u8(), 255)
				rel[#rel + 1] = acc
			end
			local abs_lines, lastline = {}, 0
			for _ = 1, intervals do
				lastline += r:i32()
				abs_lines[#abs_lines + 1] = lastline
			end
			for pc = 0, sizecode - 1 do
				local base = abs_lines[bit32.rshift(pc, linegaplog2) + 1] or 0
				p.lineinfo[pc + 1] = base + rel[pc + 1]
			end
		end

		if r:u8() ~= 0 then
			local nloc = r:varint()
			for _ = 1, nloc do
				p.locvars[#p.locvars + 1] = {
					name = string_at(r:varint()) or "v",
					startpc = r:varint(),
					endpc = r:varint(),
					reg = r:u8(),
				}
			end
			local nup = r:varint()
			for _ = 1, nup do
				p.upvalue_names[#p.upvalue_names + 1] = string_at(r:varint()) or "_up"
			end
		end

		if version >= 11 then
			r:varint()
		end

		p.instructions = decode_instructions(p.code)
		protos[#protos + 1] = p
	end

	local main = r:varint()
	if main >= #protos then
		error(DecodeError("main proto index out of range"), 0)
	end

	return {
		version = version,
		types_version = types_version,
		strings = strings,
		userdata_types = userdata_types,
		protos = protos,
		main = main,
	}
end

local function default_reg_name(proto, reg)
	for _, lv in proto.locvars do
		if lv.reg == reg then
			return sanitize_name(lv.name)
		end
	end
	if reg < proto.numparams then
		return "arg" .. (reg + 1)
	end
	return "v" .. reg
end

local function local_name_at(proto, reg, pc)
	for _, lv in proto.locvars do
		if lv.reg == reg and lv.startpc <= pc and pc < lv.endpc then
			return sanitize_name(lv.name)
		end
	end
	return nil
end

local function lift_proto(chunk, proto, is_main, indent)
	indent = indent or 0
	local pad = string.rep("    ", indent)
	local inner_pad = is_main and pad or (pad .. "    ")
	local nregs = math.max(proto.maxstacksize, proto.numparams) + 8
	local regs = table.create(nregs)
	for i = 0, nregs - 1 do
		regs[i] = default_reg_name(proto, i)
	end
	local declared = {}
	local statements = {}

	for _, lv in proto.locvars do
		if lv.startpc == 0 and regs[lv.reg] ~= nil then
			regs[lv.reg] = sanitize_name(lv.name)
		end
	end

	local params = {}
	for i = 0, proto.numparams - 1 do
		params[#params + 1] = regs[i]
		declared[i] = true
	end
	if proto.is_vararg ~= 0 then
		params[#params + 1] = "..."
	end

	if not is_main then
		local fname = proto.debugname and sanitize_name(proto.debugname) or ("anon_" .. proto.index)
		statements[#statements + 1] = pad .. "function " .. fname .. "(" .. table.concat(params, ", ") .. ")"
	end

	local function expr_of(reg)
		return regs[reg] or ("r" .. reg)
	end

	local function slot_name(reg, pc)
		return local_name_at(proto, reg, pc) or (reg < proto.numparams and ("arg" .. (reg + 1)) or ("v" .. reg))
	end

	local function assign(reg, expr, pc)
		local name = slot_name(reg, pc)
		regs[reg] = name
		if reg < proto.numparams then
			statements[#statements + 1] = inner_pad .. name .. " = " .. expr
			declared[reg] = true
			return
		end
		if not declared[reg] then
			statements[#statements + 1] = inner_pad .. "local " .. name .. " = " .. expr
			declared[reg] = true
		else
			statements[#statements + 1] = inner_pad .. name .. " = " .. expr
		end
	end

	local function set_temp(reg, expr)
		regs[reg] = expr
	end

	local pending_namecall = nil
	local i = 1
	local insns = proto.instructions
	while i <= #insns do
		local ins = insns[i]
		local op, A, B, C, D, aux = ins.op, ins.a, ins.b, ins.c, ins.d, ins.aux

		if op == OP.FASTCALL or op == OP.FASTCALL1 or op == OP.FASTCALL2 or op == OP.FASTCALL2K or op == OP.FASTCALL3 or op == OP.FASTPCALL
			or op == OP.NOP or op == OP.BREAK or op == OP.COVERAGE or op == OP.PREPVARARGS or op == OP.CLOSEUPVALS or op == OP.NATIVECALL then
			i += 1
			continue
		end

		if op == OP.LOADNIL then
			set_temp(A, "nil")
			assign(A, "nil", ins.pc)
		elseif op == OP.LOADB then
			local val = B ~= 0 and "true" or "false"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.LOADN then
			set_temp(A, tostring(D))
			assign(A, tostring(D), ins.pc)
		elseif op == OP.LOADK then
			local val = k_text(proto, D)
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.LOADKX then
			local val = k_text(proto, aux or 0)
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.MOVE then
			local src = expr_of(B)
			set_temp(A, src)
			assign(A, src, ins.pc)
		elseif op == OP.GETGLOBAL then
			local key = k_text(proto, aux or 0)
			local val = (string.sub(key, 1, 1) == '"' and is_ident(string.sub(key, 2, -2))) and string.sub(key, 2, -2) or ("_G[" .. key .. "]")
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SETGLOBAL then
			local key = k_text(proto, aux or 0)
			local name = (string.sub(key, 1, 1) == '"' and is_ident(string.sub(key, 2, -2))) and string.sub(key, 2, -2) or ("_G[" .. key .. "]")
			statements[#statements + 1] = inner_pad .. name .. " = " .. expr_of(A)
		elseif op == OP.GETUPVAL then
			local uname = sanitize_name(proto.upvalue_names[B + 1] or ("up" .. B))
			set_temp(A, uname)
			assign(A, uname, ins.pc)
		elseif op == OP.SETUPVAL then
			local uname = sanitize_name(proto.upvalue_names[B + 1] or ("up" .. B))
			statements[#statements + 1] = inner_pad .. uname .. " = " .. expr_of(A)
		elseif op == OP.GETIMPORT then
			local val = k_text(proto, D)
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.GETTABLE then
			local val = expr_of(B) .. "[" .. expr_of(C) .. "]"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SETTABLE then
			statements[#statements + 1] = inner_pad .. expr_of(B) .. "[" .. expr_of(C) .. "] = " .. expr_of(A)
		elseif op == OP.GETTABLEKS or op == OP.GETUDATAKS then
			local kid = (op == OP.GETUDATAKS and aux) and bit32.band(aux, 65535) or (aux or 0)
			local val = index_expr(expr_of(B), k_text(proto, kid))
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SETTABLEKS or op == OP.SETUDATAKS then
			local kid = (op == OP.SETUDATAKS and aux) and bit32.band(aux, 65535) or (aux or 0)
			statements[#statements + 1] = inner_pad .. index_expr(expr_of(B), k_text(proto, kid)) .. " = " .. expr_of(A)
		elseif op == OP.GETTABLEN then
			local val = expr_of(B) .. "[" .. (C + 1) .. "]"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SETTABLEN then
			statements[#statements + 1] = inner_pad .. expr_of(B) .. "[" .. (C + 1) .. "] = " .. expr_of(A)
		elseif op == OP.NAMECALL or op == OP.NAMECALLUDATA then
			local kid = (op == OP.NAMECALLUDATA and aux) and bit32.band(aux, 65535) or (aux or 0)
			local method = k_text(proto, kid)
			local mname = string.sub(method, 1, 1) == '"' and string.sub(method, 2, -2) or method
			pending_namecall = { A, expr_of(B), mname }
			set_temp(A, expr_of(B) .. ":" .. mname)
			set_temp(A + 1, expr_of(B))
		elseif op == OP.CALL or op == OP.CALLFB then
			local nrets = C - 1
			local call
			if pending_namecall and pending_namecall[1] == A then
				local obj, method = pending_namecall[2], pending_namecall[3]
				pending_namecall = nil
				local args
				if B == 0 then
					args = "..."
				else
					local parts = {}
					for j = 0, math.max(B - 2, 0) - 1 do
						parts[#parts + 1] = expr_of(A + 2 + j)
					end
					args = table.concat(parts, ", ")
				end
				call = obj .. ":" .. method .. "(" .. args .. ")"
			else
				local args
				if B == 0 then
					args = "..."
				else
					local parts = {}
					for j = 0, math.max(B - 1, 0) - 1 do
						parts[#parts + 1] = expr_of(A + 1 + j)
					end
					args = table.concat(parts, ", ")
				end
				call = expr_of(A) .. "(" .. args .. ")"
			end
			if nrets == 0 then
				statements[#statements + 1] = inner_pad .. call
			elseif nrets == 1 or nrets < 0 then
				assign(A, call, ins.pc)
			else
				local names = {}
				for j = 0, nrets - 1 do
					local nm = local_name_at(proto, A + j, ins.pc) or ("v" .. (A + j))
					names[#names + 1] = nm
					regs[A + j] = nm
					declared[A + j] = true
				end
				statements[#statements + 1] = inner_pad .. "local " .. table.concat(names, ", ") .. " = " .. call
			end
		elseif op == OP.RETURN then
			if B == 1 then
				if not is_main then
					statements[#statements + 1] = inner_pad .. "return"
				end
			elseif B == 0 then
				statements[#statements + 1] = inner_pad .. "return ..."
			else
				local vals = {}
				for j = 0, B - 2 do
					vals[#vals + 1] = expr_of(A + j)
				end
				statements[#statements + 1] = inner_pad .. "return " .. table.concat(vals, ", ")
			end
		elseif op == OP.JUMP or op == OP.JUMPBACK or op == OP.JUMPX then
			local off = op == OP.JUMPX and ins.e or D
			statements[#statements + 1] = inner_pad .. "goto label_" .. (ins.pc + 1 + off) .. " -- " .. ins.name
		elseif op == OP.JUMPIF then
			statements[#statements + 1] = inner_pad .. "if " .. expr_of(A) .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.JUMPIFNOT then
			statements[#statements + 1] = inner_pad .. "if not " .. expr_of(A) .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.JUMPIFEQ or op == OP.JUMPIFLE or op == OP.JUMPIFLT or op == OP.JUMPIFNOTEQ or op == OP.JUMPIFNOTLE or op == OP.JUMPIFNOTLT then
			local opsym = ({
				[OP.JUMPIFEQ] = "==",
				[OP.JUMPIFLE] = "<=",
				[OP.JUMPIFLT] = "<",
				[OP.JUMPIFNOTEQ] = "~=",
				[OP.JUMPIFNOTLE] = ">",
				[OP.JUMPIFNOTLT] = ">=",
			})[op]
			statements[#statements + 1] = inner_pad .. "if " .. expr_of(A) .. " " .. opsym .. " " .. expr_of(aux or 0) .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.JUMPXEQKNIL then
			local inv = bit32.rshift(aux or 0, 31)
			statements[#statements + 1] = inner_pad .. "if " .. expr_of(A) .. (inv == 0 and " == nil" or " ~= nil") .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.JUMPXEQKB then
			local inv = bit32.rshift(aux or 0, 31)
			local lit = bit32.band(aux or 0, 1) ~= 0 and "true" or "false"
			statements[#statements + 1] = inner_pad .. "if " .. expr_of(A) .. (inv == 0 and " == " or " ~= ") .. lit .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.JUMPXEQKN or op == OP.JUMPXEQKS then
			local inv = bit32.rshift(aux or 0, 31)
			local kid = bit32.band(aux or 0, 0xFFFFFF)
			statements[#statements + 1] = inner_pad .. "if " .. expr_of(A) .. (inv == 0 and " == " or " ~= ") .. k_text(proto, kid) .. " then goto label_" .. (ins.pc + 1 + D) .. " end"
		elseif op == OP.ADD or op == OP.SUB or op == OP.MUL or op == OP.DIV or op == OP.MOD or op == OP.POW or op == OP.IDIV then
			local opsym = ({ [OP.ADD] = "+", [OP.SUB] = "-", [OP.MUL] = "*", [OP.DIV] = "/", [OP.MOD] = "%", [OP.POW] = "^", [OP.IDIV] = "//" })[op]
			local val = "(" .. expr_of(B) .. " " .. opsym .. " " .. expr_of(C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.ADDK or op == OP.SUBK or op == OP.MULK or op == OP.DIVK or op == OP.MODK or op == OP.POWK or op == OP.IDIVK then
			local opsym = ({ [OP.ADDK] = "+", [OP.SUBK] = "-", [OP.MULK] = "*", [OP.DIVK] = "/", [OP.MODK] = "%", [OP.POWK] = "^", [OP.IDIVK] = "//" })[op]
			local val = "(" .. expr_of(B) .. " " .. opsym .. " " .. k_text(proto, C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SUBRK then
			local val = "(" .. k_text(proto, B) .. " - " .. expr_of(C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.DIVRK then
			local val = "(" .. k_text(proto, B) .. " / " .. expr_of(C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.AND then
			local val = "(" .. expr_of(B) .. " and " .. expr_of(C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.OR then
			local val = "(" .. expr_of(B) .. " or " .. expr_of(C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.ANDK then
			local val = "(" .. expr_of(B) .. " and " .. k_text(proto, C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.ORK then
			local val = "(" .. expr_of(B) .. " or " .. k_text(proto, C) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.CONCAT then
			local parts = {}
			for j = B, C do
				parts[#parts + 1] = expr_of(j)
			end
			local val = table.concat(parts, " .. ")
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.NOT then
			local val = "(not " .. expr_of(B) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.MINUS then
			local val = "(-" .. expr_of(B) .. ")"
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.LENGTH then
			local val = "#" .. expr_of(B)
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.NEWTABLE then
			set_temp(A, "{}")
			assign(A, "{}", ins.pc)
		elseif op == OP.DUPTABLE then
			local val = k_text(proto, D)
			set_temp(A, val)
			assign(A, val, ins.pc)
		elseif op == OP.SETLIST then
			local count = B - 1
			local start = aux or 1
			if count >= 0 then
				for j = 0, count - 1 do
					statements[#statements + 1] = inner_pad .. expr_of(A) .. "[" .. (start + j) .. "] = " .. expr_of(A + 1 + j)
				end
			end
		elseif op == OP.FORNPREP then
			statements[#statements + 1] = inner_pad .. "for " .. expr_of(A + 3) .. " = " .. expr_of(A + 2) .. ", " .. expr_of(A) .. ", " .. expr_of(A + 1) .. " do"
		elseif op == OP.FORNLOOP then
			statements[#statements + 1] = inner_pad .. "end -- numeric for"
		elseif op == OP.FORGPREP or op == OP.FORGPREP_INEXT or op == OP.FORGPREP_NEXT then
			statements[#statements + 1] = inner_pad .. "-- generic for prep " .. ins.name
		elseif op == OP.FORGLOOP then
			local nvars = bit32.band(aux or 2, 255)
			local vars = {}
			for j = 0, math.max(nvars, 1) - 1 do
				vars[#vars + 1] = expr_of(A + 3 + j)
			end
			statements[#statements + 1] = inner_pad .. "for " .. table.concat(vars, ", ") .. " in " .. expr_of(A) .. " do end -- generic for"
		elseif op == OP.GETVARARGS then
			if B == 0 then
				assign(A, "...", ins.pc)
			elseif B > 1 then
				local names = {}
				for j = 0, B - 2 do
					local nm = local_name_at(proto, A + j, ins.pc) or ("v" .. (A + j))
					names[#names + 1] = nm
					declared[A + j] = true
					regs[A + j] = nm
				end
				statements[#statements + 1] = inner_pad .. "local " .. table.concat(names, ", ") .. " = ..."
			end
		elseif op == OP.NEWCLOSURE or op == OP.DUPCLOSURE then
			local cid
			if op == OP.NEWCLOSURE then
				cid = proto.child_ids[D + 1] or D
			else
				local ck = proto.constants[D + 1]
				cid = (ck and ck.kind == "closure" and ck.value) or D
			end
			local j = i + 1
			while j <= #insns and insns[j].op == OP.CAPTURE do
				j += 1
			end
			local child = chunk.protos[cid + 1]
			if child then
				local fname = child.debugname and sanitize_name(child.debugname) or ("anon_" .. child.index)
				statements[#statements + 1] = lift_proto(chunk, child, false, indent + (is_main and 0 or 1))
				set_temp(A, fname)
				if not declared[A] and A >= proto.numparams then
					declared[A] = true
					regs[A] = fname
				else
					assign(A, fname, ins.pc)
				end
			else
				assign(A, "function(...) end -- missing proto " .. tostring(cid), ins.pc)
			end
			i = j
			continue
		elseif op ~= OP.CAPTURE then
			statements[#statements + 1] = inner_pad .. "-- " .. ins.name .. " A=" .. A .. " B=" .. B .. " C=" .. C .. " D=" .. D
		end

		i += 1
	end

	if not is_main then
		statements[#statements + 1] = pad .. "end"
	end
	return table.concat(statements, "\n")
end

local function decompile_bytecode(data)
	local chunk = decode_chunk(data)
	local header = {
		"-- " .. VERSION_NAME,
		"-- " .. CREDIT_LINE,
		"-- bytecode v" .. chunk.version .. " (Luau v3-v9 family)",
		"-- static reconstruction; names come from debug info when present",
		"",
	}
	return table.concat(header, "\n") .. lift_proto(chunk, chunk.protos[chunk.main + 1], true, 0) .. "\n"
end

local function decompile(source)
	local data
	if typeof(source) == "Instance" then
		if not getscriptbytecode then
			return "-- Leo: getscriptbytecode missing"
		end
		local ok, bc = pcall(getscriptbytecode, source)
		if not ok or type(bc) ~= "string" or bc == "" then
			return "-- Leo: no bytecode\n--[[\n" .. tostring(bc) .. "\n]]"
		end
		data = bc
	elseif type(source) == "string" or typeof(source) == "buffer" then
		data = source
	else
		return "-- Leo: expected script or bytecode"
	end
	local ok, result = pcall(decompile_bytecode, data)
	if not ok then
		return "--[[ Leo decode/lift error:\n" .. tostring(result) .. "\n]]"
	end
	return result
end

local Leo = {
	VERSION = VERSION_NAME,
	decompile = decompile,
	decompile_bytecode = decompile_bytecode,
	decode_chunk = decode_chunk,
}

pcall(function()
	local env = (getgenv and getgenv()) or _G
	env.decompile = decompile
	env.LeoDecompile = decompile
end)

return Leo

end)()
