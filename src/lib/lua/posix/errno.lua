-- convert an error message to a name --

local lang = require("i18n")
local checkArg = require("checkArg")

local lib = {}

local map = {
  [1]   = "EPERM",
  [2]   = "ENOENT",
  [8]   = "ENOEXEC",
  [9]   = "EBADF",
  [10]  = "ECHILD",
  [13]  = "EACCES",
  [15]  = "ENOTBLK",
  [16]  = "EBUSY",
  [17]  = "EEXIST",
  [18]  = "EXDEV",
  [19]  = "ENODEV",
  [20]  = "ENOTDIR",
  [21]  = "EISDIR",
  [22]  = "EINVAL",
  [25]  = "ENOTTY",
  [38]  = "ENOSYS",
  [39]  = "ENOTEMPTY",
  [40]  = "ELOOP",
  [49]  = "EUNATCH",
  [83]  = "ELIBEXEC",
  [92]  = "ENOPROTOOPT",
  [95]  = "ENOTSUP",
}

for k, v in pairs(map) do lib[v] = k end

function lib.errno(id)
  checkArg(1, id, "number", "string")
  if type(id) == "string" then return id end
  return lang.fetch(map[id] or "EUNKNOWN")
end

return lib
