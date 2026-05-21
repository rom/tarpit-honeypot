-- Fake POP3 (handler: lua). The +OK banner advertises a live, unique APOP
-- timestamp challenge (RFC 1939) each connection; USER / PASS / APOP are
-- captured and rejected. Nothing is executed.
--
-- Demonstrates: time.ms (live per-connection challenge), rng:hex (unique
-- token), personality (stable hostname), sleep, meta/flag.

local p = personality()
local stamp = "<" .. tostring(time.ms()) .. "." .. rng:hex(6) .. "@" .. p.hostname .. ">"
conn:write("+OK POP3 server ready " .. stamp .. "\r\n")

for _ = 1, 12 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local verb = string.upper(c:sub(1, 4))
  if verb == "USER" then
    meta("user", c)
    conn:write("+OK\r\n")
  elseif verb == "PASS" then
    meta("pass", c)
    flag("pop3-login-attempt")
    sleep(200 + rng:int(300))
    conn:write("-ERR [AUTH] Authentication failed\r\n")
  elseif verb == "APOP" then
    meta("apop", c)
    flag("pop3-login-attempt")
    conn:write("-ERR authentication failed\r\n")
  elseif verb == "CAPA" then
    conn:write("+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\n.\r\n")
  elseif verb == "STAT" then
    conn:write("+OK 0 0\r\n")
  elseif verb == "QUIT" then
    conn:write("+OK Bye\r\n")
    break
  elseif #c > 0 then
    conn:write("-ERR unknown command\r\n")
  end
end
