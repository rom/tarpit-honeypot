-- Fake Tor ControlPort (handler: lua, port 9051). An exposed control port lets
-- an attacker drive the Tor daemon (new circuits, hidden-service hijack). We
-- answer PROTOCOLINFO and capture any AUTHENTICATE secret, then deny. Read-only.
--
-- Demonstrates: line protocol, credential capture (auth_pass surfaces in
-- /captures), abuse flagging.

local p = personality()
for _ = 1, 20 do
  local line = conn:readline()
  if not line then break end
  local c = line:gsub("[\r\n]", "")
  local up = string.upper(c)
  if up:find("^PROTOCOLINFO") then
    conn:write("250-PROTOCOLINFO 1\r\n")
    conn:write("250-AUTH METHODS=HASHEDPASSWORD COOKIE\r\n")
    conn:write("250-VERSION Tor=\"0.4.8.10\"\r\n")
    conn:write("250 OK\r\n")
  elseif up:find("^AUTHENTICATE") then
    meta("tor_control_auth", c)
    local secret = c:match("^[Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ee]%s+(.+)")
    if secret then meta("auth_pass", secret) end
    flag("tor-control-auth")
    conn:write("515 Authentication failed: Password did not match HashedControlPassword value from configuration\r\n")
  elseif up:find("^GETINFO") then
    flag("tor-control-getinfo")
    conn:write("514 Authentication required.\r\n")
  elseif up:find("^QUIT") then
    conn:write("250 closing connection\r\n")
    break
  elseif c ~= "" then
    conn:write("510 Unrecognized command\r\n")
  end
end
local _ = p
