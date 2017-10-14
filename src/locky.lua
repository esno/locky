local os = require('os')
local opensslDigest = require('openssl.digest')
local opensslPkey = require('openssl.pkey')
local socket = require('socket')

local locky = {
  method = {
    AUTH = 1,
    UNLOCK = 2
  },
  udp = socket.udp()
}

function locky.init(self, hostname, port)
  locky.udp:setsockname('*', 0)
  locky.udp:setpeername(hostname, port)
  locky.udp:settimeout(10)
end

function locky.auth(self, privateKeyFile)
  local msg = 'ACK:' .. os.time()
  local msgLengthH = (#msg >> 8) & 0xff;
  local msgLengthL = #msg & 0xff;
  local digest = opensslDigest.new('sha256')
  digest = digest:update(msg)
  local key = opensslPkey.new()

  local fd = io.open(privateKeyFile, 'r')
  local privateKey = fd:read('*a')
  fd:close()

  key:setPrivateKey(privateKey)
  locky.udp:send(
    locky.method.AUTH ..
    string.char(msgLengthH) ..
    string.char(msgLengthL) ..
    msg ..
    key:sign(digest)
  )
end

function locky.waitForSecret(self, privateKeyFile)
  local fd = io.open(privateKeyFile, 'r')
  local privateKey = fd:read('*a')
  fd:close()
  local key = opensslPkey.new()
  key:setPrivateKey(privateKey)

  local data = locky.udp:receive()
  if data then
    local plain = key:decrypt(data)
    return plain
  end
end

return locky
