-- Cynosure 2 terminal handler --

local sys = require("syscalls")

local handler = { keyBackspace = 8 }

function handler.setRaw(raw)
  if raw then
    sys.ioctl(0, "stty", {echo=false, raw=true})
    sys.ioctl(0, "setvbuf", "none")

  else
    sys.ioctl(0, "stty", {echo=true, raw=false})
    sys.ioctl(0, "setvbuf", "line")
  end
end

function handler.cursorVisible(yesno)
  io.write(yesno and "\27[?25h" or "\27[?25l")
  io.flush()
end

function handler.ttyIn()
  return not not sys.isatty(0)
end

function handler.ttyOut()
  return not not sys.isatty(1)
end

return handler
