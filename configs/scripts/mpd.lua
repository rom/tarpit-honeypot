-- Fake Music Player Daemon (handler: lua, TCP 6600). MPD ships with no
-- password by default; an exposed one is a soft target and an odd thing to
-- find on a server (often a pivoted desktop). Greets with the version line,
-- answers status/stats, and captures password / command_list attempts.

conn:write("OK MPD 0.23.5\n")

for _ = 1, 20 do
  local line = conn:readline()
  if not line then break end
  local c = (line:gsub("[\r\n]", ""))
  local verb = string.lower(c:match("^(%S+)") or "")
  if verb == "status" then
    conn:write("volume: 100\nstate: stop\nplaylistlength: 0\nrepeat: 0\nrandom: 0\nOK\n")
  elseif verb == "stats" then
    conn:write("artists: 0\nalbums: 0\nsongs: 0\nuptime: " .. tostring(time.uptime()) ..
      "\ndb_playtime: 0\nOK\n")
  elseif verb == "currentsong" then
    conn:write("OK\n")
  elseif verb == "password" then
    meta("mpd_password", c)
    flag("mpd-auth-attempt")
    conn:write("ACK [3@0] {password} incorrect password\n")
  elseif verb == "commands" then
    conn:write("command: status\ncommand: stats\ncommand: play\ncommand: password\nOK\n")
  elseif verb == "command_list_begin" or verb == "command_list_ok_begin" then
    meta("mpd_command_list", "begin")
  elseif verb == "close" then
    break
  elseif #verb > 0 then
    conn:write("OK\n")
  end
end
