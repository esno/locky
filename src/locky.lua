local os = require('os')
local io = require('io')
local opensslCipher = require('openssl.cipher')
local opensslDigest = require('openssl.digest')
local opensslPkey = require('openssl.pkey')
local opensslRand = require('openssl.rand')
local socket = require('socket')

local locky = {
  method = {
    AUTH = 1,
    UNLOCK = 2
  },
  udp = socket.udp()
}

local _getPassword = function(prompt)
  os.execute('stty -echo raw')
  if prompt then io.write(prompt) end
  repeat
    local c = io.read(1)
    -- \127 is backspace
    if c == '\127' and #(password or '') > 0 then
      password = password:sub(1, -2)
    elseif c ~= '\r' then
      password = (password or '') .. c
    end
  until c == '\r'
  os.execute('stty sane')
  io.write('\n')
  io.flush()
  return password
end

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

function locky.unlock(self, secret)
  local luksKey = _getPassword('LUKS Key: ')
  local iv = opensslRand.bytes(16)
  local cipher = opensslCipher.new('aes-256-cbc')
  cipher = cipher:encrypt(secret, iv)
  cipher:update(luksKey)

  locky.udp:send(
    locky.method.UNLOCK ..
    iv ..
    cipher:final()
  )
end

function locky.waitForMsg(self, privateKeyFile)
  local fd = io.open(privateKeyFile, 'r')
  local privateKey = fd:read('*a')
  fd:close()
  local key = opensslPkey.new()
  key:setPrivateKey(privateKey)

  local data = locky.udp:receive()
  if data then
    return key:decrypt(data)
  end
  return nil
end

return locky
