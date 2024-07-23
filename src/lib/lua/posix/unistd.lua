-- posix.unistd

local sys = require("syscalls")
local pwd = require("posix.pwd")
local grp = require("posix.grp")
local stat = require("posix.sys.stat")
local errno = require("posix.errno")
local checkArg = require("checkArg")
local permissions = require("permissions")

local lib = {}

lib._exit = sys.exit

-- i *think* this is compliant
function lib.access(path, mode)
  checkArg(1, path, "string")
  checkArg(2, mode, "string", "nil")

  local statx, err = sys.stat(path)
  if not statx then
    return nil, errno.errno(err), err
  end

  local uid, gid = sys.getuid(), sys.getgid()
  local rperm, wperm, xperm =
    permissions.strtobmp(("%s--%s--r--"):format(
      statx.uid == uid and "r" or "-", statx.gid == gid and "r" or "-")),
    permissions.strtobmp(("-%s--%s--w-"):format(
      statx.uid == uid and "w" or "-", statx.gid == gid and "w" or "-")),
    permissions.strtobmp(("--%s--%s--x"):format(
      statx.uid == uid and "x" or "-", statx.gid == gid and "x" or "-"))

  local status = true
  for c in mode:gmatch(".") do
    if c == "r" then
      if (statx.mode & rperm) == 0 then status = false end
    elseif c == "w" then
      if (statx.mode & wperm) == 0 then status = false end
    elseif c == "x" then
      if (statx.mode & xperm) == 0 then status = false end
    elseif c ~= "f" then
      return nil, errno.errno(errno.EINVAL), errno.EINVAL
    end
  end

  if status then return 0 else
    return nil, errno.errno(errno.EACCES), errno.EACCES
  end
end

-- no unistd.alarm

function lib.chdir(path)
  checkArg(1, path, "string")

  local ok, err = sys.chdir(path)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

function lib.chown(path, uid, gid)
  checkArg(1, path, "string")
  checkArg(2, uid, "number", "string")
  checkArg(3, gid, "number", "string")

  if type(uid) == "string" then
    uid = assert(pwd.getpwnam(uid)).pw_uid
  end

  if type(gid) == "string" then
    gid = assert(grp.getgrnam(gid)).gr_gid
  end

  local ok, err = sys.chown(path, uid, gid)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

function lib.close(fd)
  checkArg(1, fd, "number")

  local ok, err = sys.close(fd)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

function lib.crypt(text)
  checkArg(1, text, "string")
  return require("sha3").sha256(text):gsub(".", function(c)
    return ("%02x"):format(c:byte())
  end)
end

function lib.dup(fd)
  checkArg(1, fd, "number")

  local new, err = sys.dup(fd)
  if not new then return nil, errno.errno(err), err end
  return new
end

function lib.dup2(fd, newfd)
  checkArg(1, fd, "number")
  checkArg(2, newfd, "number")

  local new, err = sys.dup2(fd, newfd)
  if not new then return nil, errno.errno(err), err end
  return new
end

function lib.exec(path, argt)
  checkArg(1, path, "string")
  checkArg(2, argt, "table")

  local _, err = sys.execve(path, argt)
  return nil, errno.errno(err), err
end

local function searchpath(path, argt)
  if path:find("/") then
    local statx = sys.stat(path)
    if statx then argt[0] = path return path, argt end
  end

  local _path = os.getenv("PATH") or "/bin:/usr/bin"
  for entry in _path:gmatch("[^:]+") do
    local search = entry .. "/" .. path
    local searchwe = search .. ".lua"

    local statx, _ = sys.stat(search)
    if statx then
      argt[0] = argt[0] or path
      return search, argt
    end

    local statxwe, _ = sys.stat(searchwe)
    if statxwe then
      argt[0] = argt[0] or path
      return searchwe, argt
    end
  end

  return nil, errno.errno(errno.ENOENT), errno.ENOENT
end

function lib.execp(path, argt)
  checkArg(1, path, "string")
  checkArg(2, argt, "table")

  local _path, _argt, enoe = searchpath(path, argt)
  if not _path then return _path, _argt, enoe end
  return lib.exec(_path, _argt)
end

-- extension: execpe
function lib.execpe(path, argt, env)
  checkArg(1, path, "string")
  checkArg(2, argt, "table")
  checkArg(3, env, "table")

  local _path, _argt, enoe = searchpath(path, argt)
  if not _path then return _path, _argt, enoe end

  local ok, err = sys.execve(_path, _argt, env)
  if not ok then return nil, errno.errno(err), err end
end

-- no unistd.fdatasync
-- no real unistd.fork because Cynosure's implementation is noncompliant
function lib.fork()
  return nil, errno.errno(errno.ENOSYS), errno.ENOSYS
end

function lib.fsync(fd)
  checkArg(1, fd, "number")
  local ok, err = sys.flush(fd)
  if not ok then return nil, errno.errno(err), err end
  return 0
end
-- no unistd.ftruncate

lib.getcwd = sys.getcwd
lib.getegid = sys.getegid
lib.geteuid = sys.geteuid
lib.getgid = sys.getgid

-- no unistd.getgroups
-- no unistd.gethostid
-- no unistd.getopt

lib.getpgrp = sys.getpgrp
lib.getpid = sys.getpid
lib.getppid = sys.getppid
lib.getuid = sys.getuid

function lib.getlogin()
  return sys.ioctl(sys.isatty(0) and 0 or
    sys.isatty(1) and 1 or sys.isatty(2) and 2, "getlogin")
end

function lib.isatty(fd)
  checkArg(1, fd, "number")

  local ok, err = sys.isatty(fd)
  if ok == nil then return nil, errno.errno(err), err end
  if not ok then return nil, "not a TTY", -1 end

  return 1
end

-- no unistd.lchown
-- no unistd.link
-- no unistd.linkat

lib.SEEK_SET = 0x1
lib.SEEK_CUR = 0x2
lib.SEEK_END = 0x3
function lib.lseek(fd, offset, whence)
  checkArg(1, fd, "number")
  checkArg(2, offset, "number")
  checkArg(3, whence, "number")

  whence = whence == 1 and "set"
        or whence == 2 and "cur"
        or whence == 3 and "end"
  if type(whence) == "number" then
    return nil, errno.errno(errno.EINVAL), errno.EINVAL
  end

  local ok, err = sys.seek(fd, whence, offset)
  if not ok then return nil, errno.errno(err), err end
  return ok
end

-- no unistd.nice
-- no unistd.pathconf

lib.pipe = sys.pipe

function lib.read(fd, count)
  checkArg(1, fd, "number")
  checkArg(2, count, "number")

  local data, err = sys.read(fd, count)
  if not data and err then return nil, errno.errno(err), err end
  return data or ""
end

-- no unistd.readlink

function lib.rmdir(path)
  checkArg(1, path, "string")

  local statx, err = sys.stat(path)
  if not statx then return nil, errno.errno(err), err end

  if stat.S_ISDIR(statx.mode) == 0 then return nil,
    errno.errno(errno.ENOTDIR), errno.ENOTDIR end

  local fd, _err = sys.opendir(path)
  if not fd then return nil, errno.errno(_err), _err end

  local ent = sys.readdir(fd)
  sys.close(fd)

  if ent then return nil, errno.errno(errno.EEXIST), errno.EEXIST end

  local ok, __err = sys.unlink(path)
  if not ok then return nil, errno.errno(__err), __err end
  return 0
end

function lib.setpid(what, id, gid)
  checkArg(1, what, "string")
  checkArg(2, id, "number")
  checkArg(3, gid, "number", what ~= "p" and "nil")

  if #what ~= 1 or not what:match("[uUgGsp]") then
    return nil, errno.errno(errno.EINVAL), errno.EINVAL
  end

  local fname = "set" .. (
    what == "U" and "eu" or
    what == "G" and "eg" or
    what == "p" and "pg" or
    what) .. (what == "p" and "rp" or "id")

  local ok, err = sys[fname](id, gid)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

function lib.sleep(n)
  local uptime = sys.uptime()
  local max = uptime + n
  repeat
    coroutine.yield(max - uptime)
    uptime = sys.uptime()
  until uptime >= max
end

-- no unistd.sync
-- no unistd.sysconf

function lib.tcgetpgrp(fd)
  checkArg(1, fd, "number")

  local id, err = sys.ioctl(fd, "getpg")
  if not id then return nil, errno.errno(err), err end
  return id
end

function lib.tcsetpgrp(fd, pgid)
  checkArg(1, fd, "number")
  checkArg(2, pgid, "number")

  local ok, err = sys.ioctl(fd, "setpg", pgid)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

-- no unistd.truncate

function lib.ttyname(fd)
  checkArg(1, fd, "number")

  local name, err = sys.ioctl(fd, "ttyname")
  if not name and err then return nil, errno.errno(err), err end
  return name
end

function lib.unlink(path)
  checkArg(1, path, "string")

  local statx, err = sys.stat(path)
  if not statx then return nil, errno.errno(err), err end

  if stat.S_ISDIR(statx.mode) ~= 0 then
    return nil, errno.errno(errno.EISDIR), errno.EISDIR
  end

  local ok, _err = sys.unlink(path)
  if not ok then return nil, errno.errno(_err), _err end

  return 0
end

function lib.write(fd, buf)
  checkArg(1, fd, "number")
  checkArg(2, buf, "string")

  local ok, err = sys.write(fd, buf)
  if not ok then return nil, errno.errno(err), err end
  return 0
end

return lib
