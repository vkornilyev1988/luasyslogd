syslog = {}
local posix = require'posix'
local bdb = require'libluabdb'
local system = require'libluasystem_os'
local fcntl = posix.fcntl
local unistd = posix.unistd
local sys_sock = posix.sys.socket

local log_path = '/var/run/log'
local log_link_path = '/dev/log'
local klog_path = '/dev/klog'
local klog_f = nil

syslog.cfg = {}
syslog.dir = {}

syslog.dir.db = '/data/db'

syslog.cfg.db = {}
syslog.cfg.db.security = 'log_security'
syslog.cfg.db.auth = 'log_auth'
syslog.cfg.db.system = 'log_system'
syslog.cfg.db.dhcp = 'log_dhcp'

-- num, action, proto, src, dest, dir, eth
-- name, msg

-- local function syslog_klog()
-- 	klog_f = io.open(klog_path, 'r')
-- 	if not klog_f then
-- 		print('failed to start syslog')
-- 		return nil
-- 	end
-- 	local prev_ipfw = nil
-- 	local c_ipfw = 0
-- 	local db_conn_ipfw = bdb.open(syslog.cfg.db.security, syslog.dir.db)
-- 	while true do
-- 		local line = klog_f:lines()()
-- 		if not line then
			
-- 		else
-- 			if line:find('ipfw:') then
-- 				if not prev_ipfw then
-- 					prev_ipfw = line
-- 					local n, act, proto, src, dest, dir, iface = line:match('<%d+>%[%d+%] ipfw: (%d+) (%w+) ([A-Z0-9.:]+) (.*) (.*) (%w+) via ([a-z0-9_]+)')
-- 					bdb.put(db_conn_ipfw, math.floor(socket.gettime() * 1000),
-- 						{num = tonumber(n), action = act, proto = proto, src = src, dest = dest, dir = dir, eth = iface})
-- 				else
-- 					local i, j
-- 					i = prev_ipfw:find(']')
-- 					j = line:find(']')
-- 					if prev_ipfw:sub(i + 1) == line:sub(j + 1) then
-- 						c_ipfw = c_ipfw + 1
-- 					else
-- 						if c_ipfw ~= 0 then
-- 							bdb.put(db_conn_ipfw, math.floor(socket.gettime() * 1000),
-- 								{num = c_ipfw, action = "Repeat", proto="", src="", dest = "", dir="", eth=""})
-- 						end
-- 						local n, act, proto, src, dest, dir, iface = line:match('<%d+>%[%d+%] ipfw: (%d+) (%w+) ([A-Z0-9.:]+) (.*) (.*) (%w+) via ([a-z0-9_]+)')
-- 						bdb.put(db_conn_ipfw, math.floor(socket.gettime() * 1000),
-- 							{num = tonumber(n), action = act, proto = proto, src = src, dest = dest, dir = dir, eth = iface})
-- 						prev_ipfw = line
-- 						c_ipfw = 0
-- 					end
-- 				end
-- 			else

-- 			end
-- 		end
-- 	end
-- end

local function syslog_log()
	unistd.unlink(log_path)
	unistd.unlink(log_link_path)
	local s, errmsg = sys_sock.socket(sys_sock.AF_UNIX, sys_sock.SOCK_DGRAM, 0)
	assert(s ~= nil, errmsg)
	local rc, errmsg = sys_sock.bind(s, {family=sys_sock.AF_UNIX, path=log_path})
	assert(rc == 0, errmsg)
	unistd.link(log_path, log_link_path, true)
	return s
end

local function syslog_klog()

	klog_f = fcntl.open(klog_path, fcntl.O_RDONLY | fcntl.O_NONBLOCK)
	kkk = syslog_log()
	local fds = {
	   [klog_f] = {events={IN=true}},
	   [kkk] = {events={IN=true}}
	}
	local prev_ipfw = nil
	local c_ipfw = 0
	local db_conn_ipfw = bdb.open(syslog.cfg.db.security, syslog.dir.db)
	local db_conn_auth = bdb.open(syslog.cfg.db.auth, syslog.dir.db)
	local db_conn_sys = bdb.open(syslog.cfg.db.system, syslog.dir.db)
	local db_conn_dhcp = bdb.open(syslog.cfg.db.dhcp, syslog.dir.db)
	while true do
		require 'posix'.poll.poll(fds, -1)
		for fd in pairs(fds) do
			if fds[fd].revents.IN then
				local line = ""
				if fd == klog_f then
					local c = unistd.read(fd, 1)
					while c ~= '\n' do
						line = line .. c
						c = unistd.read(fd, 1)
					end
				elseif fd == kkk then
					line = sys_sock.recv(fd, 1024)
				end
				if line:find('ipfw:') then
					if not prev_ipfw then
						prev_ipfw = line
						local n, act, proto, src, dest, dir, iface = line:match('ipfw: (%d+) (%w+) ([A-z0-9.:]+) (.*) (.*) (%w+) via ([A-z0-9_]+)')
						if n and act and proto and src and dest and dir and iface then
							local t = posix.time.clock_gettime(posix.time.CLOCK_REALTIME)
	            			bdb.put(db_conn_ipfw, math.floor(t.tv_sec * 1000 + t.tv_nsec /1000000),
								{num = tonumber(n), action = act:lower(), proto = proto:lower(), src = src, dest = dest, dir = dir, eth = iface})
	            		end
					else
						local i, j
						i = prev_ipfw:find('ipfw:')
						j = line:find('ipfw:')
						if prev_ipfw:sub(i + 1) == line:sub(j + 1) then
							c_ipfw = c_ipfw + 1
						else
							if c_ipfw ~= 0 then
                				local t = posix.time.clock_gettime(posix.time.CLOCK_REALTIME)
								bdb.put(db_conn_ipfw, math.floor(t.tv_sec * 1000 + t.tv_nsec /1000000),
									{num = c_ipfw, action = "repeat", proto="", src="", dest = "", dir="", eth=""})
							end
							local n, act, proto, src, dest, dir, iface = line:match('ipfw: (%d+) (%w+) ([A-z0-9.:]+) (.*) (.*) (%w+) via ([A-z0-9_]+)')
							if n and act and proto and src and dest and dir and iface then
								local t = posix.time.clock_gettime(posix.time.CLOCK_REALTIME)
	              				bdb.put(db_conn_ipfw, math.floor(t.tv_sec * 1000 + t.tv_nsec /1000000),
									{num = tonumber(n), action = act:lower(), proto = proto:lower(), src = src, dest = dest, dir = dir, eth = iface})
								prev_ipfw = line
								c_ipfw = 0
							end
						end
					end
				elseif line:find('auth:') or line:find('login:') then
					local name,user,msg = line:match('([a-zA-Z%[%]0-9]+)%: ([^%s]*) (.*)')
					if name and user and msg then
						bdb.put(db_conn_auth, math.floor(t.tv_sec * 1000 + t.tv_nsec /1000000),{type = 'shell', user=user, msg = msg})
					end
				else
					local name,msg = line:match('([a-zA-Z%[%]0-9]+)%: (.*)')
					if name and msg then
						local conn = nil;
						if name:find('dhcp') then
							conn = db_conn_dhcp
						else
							conn = db_conn_sys
						end
	          			local t = posix.time.clock_gettime(posix.time.CLOCK_REALTIME)
						bdb.put(conn, math.floor(t.tv_sec * 1000 + t.tv_nsec /1000000),{name = name, msg = msg})
					end
				end
			end
			if fds[fd].revents.HUP then
				unistd.close(fd)
				fds[fd] = nil
				if not next(fds) then
					return
				end
			end
		end
	end
end

function syslog.start()
	if not system.ls(syslog.dir.db .. '/' .. syslog.cfg.db.security .. '.db', true) then
		bdb.create(syslog.cfg.db.security, syslog.dir.db, "num:l", 'action:s', 'proto:s', 'src:s', 'dest:s', 'dir:s', 'eth:s')
	end
	if not system.ls(syslog.dir.db .. '/' .. syslog.cfg.db.auth .. '.db', true) then
		bdb.create(syslog.cfg.db.auth, syslog.dir.db, "type:s", 'user:s', 'msg:s')
	end
	if not system.ls(syslog.dir.db .. '/' .. syslog.cfg.db.system .. '.db', true) then
		bdb.create(syslog.cfg.db.system, syslog.dir.db, "name:s", 'msg:s')
	end
	if not system.ls(syslog.dir.db .. '/' .. syslog.cfg.db.dhcp .. '.db', true) then
		bdb.create(syslog.cfg.db.dhcp, syslog.dir.db, "name:s", 'msg:s')
	end
	syslog_klog()
end

-- syslog.start()

return syslog