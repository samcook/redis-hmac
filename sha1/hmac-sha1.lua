local function hmac_sha1()

	local self = {}
	
	local BLOCK_SIZE = 64 -- 512 bits

	local function hex_to_binary(hex)
		return hex:gsub('..', function(hexval)
			return string.char(tonumber(hexval, 16))
		end)
	end

	local function xor_with_0x5c(c)
		return string.char(bit.bxor(string.byte(c),0x5c))
	end

	local function xor_with_0x36(c)
		return string.char(bit.bxor(string.byte(c),0x36))
	end

	local function sha1_binary(msg)
		return hex_to_binary(redis.sha1hex(msg))
	end

	function self.compute(key, text)
		assert(type(key)  == 'string', "key passed to sha1_hmac should be a string")
		assert(type(text) == 'string', "text passed to sha1_hmac should be a string")

		if #key > BLOCK_SIZE then
			key = sha1_binary(key)
		end

		local key_xord_with_0x36 = key:gsub('.', xor_with_0x36) .. string.rep(string.char(0x36), BLOCK_SIZE - #key)
		local key_xord_with_0x5c = key:gsub('.', xor_with_0x5c) .. string.rep(string.char(0x5c), BLOCK_SIZE - #key)

		return redis.sha1hex(key_xord_with_0x5c .. sha1_binary(key_xord_with_0x36 .. text))
	end
	
	return self

end