# redis-hmac

A redis compatible Lua script for computing HMAC-SHA1 signatures

## Usage

Copy the script into your redis Lua script that requires calculating an HMAC-SHA1 signature.

```lua
-- insert hmac-sha1.lua here

local key = 'mysecretkey'
local text = 'content to sign'

local signature = hmac_sha1().compute(key, text)
```

## Credits

HMAC Lua code adapted from https://github.com/kikito/sha1.lua to use redis builtin SHA1 and bit operations