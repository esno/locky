#!/usr/bin/env lua

socket = require('socket')
udp = socket.udp()
udp:setpeername('localhost', 23420)
udp:settimeout(1)
udp:send('14ping')
udp:close()
