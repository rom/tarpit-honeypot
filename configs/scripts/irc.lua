-- Fake IRC server (handler: lua). IRC is a classic botnet C2 channel, so a
-- listener on 6667/6697 that captures NICK / USER / PASS / JOIN is high
-- signal. Answers PING with PONG and sends the usual numeric welcome so a
-- bot proceeds and reveals its channel + key. Nothing executes.
--
-- Demonstrates: personality (stable server name), host:get/set (per-source
-- connection counter), meta/flag (C2 capture), engagement.

local p = personality()
local server = "irc." .. p.hostname .. ".net"
local nick = "*"

conn:write(":" .. server .. " NOTICE * :*** Looking up your hostname...\r\n")

for _ = 1, 30 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local upper = string.upper(c)
  if upper:find("^PING") then
    local token = c:sub(6)
    conn:write("PONG " .. server .. " :" .. token .. "\r\n")
  elseif upper:find("^NICK ") then
    nick = c:sub(6)
    meta("irc_nick", nick)
  elseif upper:find("^USER ") then
    meta("irc_user", c)
    flag("irc-registration")
    -- Standard welcome burst so the bot believes it is connected.
    conn:write(":" .. server .. " 001 " .. nick .. " :Welcome to the Internet Relay Network " .. nick .. "\r\n")
    conn:write(":" .. server .. " 002 " .. nick .. " :Your host is " .. server .. "\r\n")
    conn:write(":" .. server .. " 376 " .. nick .. " :End of /MOTD command.\r\n")
  elseif upper:find("^PASS ") then
    meta("irc_pass", c:sub(6))
    flag("irc-registration")
  elseif upper:find("^JOIN ") then
    meta("irc_channel", c:sub(6))
    flag("irc-channel-join") -- the C2 channel (+ key) a botnet joins
    conn:write(":" .. nick .. " JOIN " .. c:sub(6) .. "\r\n")
  elseif upper:find("^QUIT") then
    conn:write("ERROR :Closing Link\r\n")
    break
  end
end
