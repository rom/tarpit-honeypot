-- Fake STOMP message broker (handler: lua, port 61613 — ActiveMQ / RabbitMQ
-- STOMP). Captures the CONNECT frame's login/passcode (surfaced as a credential)
-- and the destinations a client SUBSCRIBEs / SENDs to. Nothing is queued.
--
-- STOMP frames are: COMMAND\n header:value\n ... \n\n body NUL. We parse the
-- command + headers line-wise (the API reads lines), which covers CONNECT.

local function frame()
  local cmd = conn:readline()
  if not cmd then return nil, nil end
  cmd = cmd:gsub("[\r\n%z]", "")
  local headers = {}
  for _ = 1, 30 do
    local h = conn:readline()
    if not h or h == "\r\n" or h == "\n" then break end
    local k, v = h:gsub("[\r\n]", ""):match("^([^:]+):(.*)$")
    if k then headers[string.lower(k)] = v end
  end
  return cmd, headers
end

for _ = 1, 6 do
  local cmd, h = frame()
  if not cmd or cmd == "" then break end
  meta("stomp_command", cmd)
  if cmd == "CONNECT" or cmd == "STOMP" then
    if h.login then meta("auth_user", h.login) end
    if h.passcode then meta("auth_pass", h.passcode) end
    flag("stomp-connect")
    conn:write("CONNECTED\nversion:1.2\nheart-beat:0,0\nserver:ActiveMQ/5.18.3\nsession:ID:broker-" ..
      rng:hex(8) .. "\n\n\0")
  elseif cmd == "SUBSCRIBE" or cmd == "SEND" then
    if h.destination then meta("stomp_destination", h.destination) end
    flag("stomp-" .. string.lower(cmd))
  elseif cmd == "DISCONNECT" then
    break
  end
end
